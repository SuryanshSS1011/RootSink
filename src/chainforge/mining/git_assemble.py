"""Assemble SILVER ChainRecords from clone-based OSV GIT mining evidence (git_case.sh).

Unlike ARVO cases (container + PoC -> GOLD), a GIT candidate is mined by cloning the repo at
``fixed^`` and running Joern dataflow. There is no execution oracle, so the ceiling is SILVER
(dataflow-witnessed). Evidence shape (from git_case.sh):

    {"osv_id", "source": "osv-git", "repo", "fixed_commit", "vuln_commit",
     "labeled_cwes": [...], "repro": null,
     "dataflows": [{"src_cwe", "sink_cwe", "path_count", "has_dataflow"}, ...]}

One clone can produce several source->sink dataflow hits for the SAME crash-free vuln. As with
ARVO, we pick the MOST-SPECIFIC source per sink (416>476>190>20) so we emit one chain per
(sink) rather than double-counting one bug, and label it by its true root.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field

from ..cwe import is_admissible_edge
from ..schema import (
    ChainLink,
    ChainRecord,
    CommitRange,
    ConfidenceTier,
    LinkEvidence,
    LinkRole,
)

# Same specificity ranking as pilot.py: a lifecycle/overflow root beats the broad CWE-20 catch-all.
_SOURCE_SPECIFICITY = {416: 4, 476: 3, 190: 2, 20: 1}


@dataclass
class GitDataflow:
    src_cwe: int
    sink_cwe: int
    path_count: int
    has_dataflow: bool


@dataclass
class GitEvidence:
    """Parsed git_case.sh evidence.json."""

    osv_id: str
    repo: str
    fixed_commit: str
    vuln_commit: str | None
    labeled_cwes: list[int]
    dataflows: list[GitDataflow] = field(default_factory=list)

    @classmethod
    def from_json(cls, d: dict) -> GitEvidence:
        return cls(
            osv_id=str(d.get("osv_id", "")),
            repo=str(d.get("repo", "")),
            fixed_commit=str(d.get("fixed_commit", "")),
            vuln_commit=d.get("vuln_commit"),
            labeled_cwes=[int(c) for c in d.get("labeled_cwes", [])],
            dataflows=[
                GitDataflow(
                    src_cwe=int(x["src_cwe"]),
                    sink_cwe=int(x["sink_cwe"]),
                    path_count=int(x.get("path_count", 0)),
                    has_dataflow=bool(x.get("has_dataflow")),
                )
                for x in d.get("dataflows", [])
                if "src_cwe" in x and "sink_cwe" in x
            ],
        )


def _project_from_repo(repo: str) -> str:
    """github.com/owner/name -> 'owner/name' (stable project label)."""
    m = re.search(r"github\.com[:/]+([^/]+/[^/.]+)", repo)
    return m.group(1) if m else (repo or "unknown")


def _stable_id(osv_id: str) -> str:
    """Deterministic CHAINFORGE id from the OSV id (git records have no ARVO localId).

    Uses a 7-hex-digit hash in the 0x9GIT band (prefix '91') so it never collides with ARVO
    (localId-based, 10-digit) or syzbot (0800xxx) id ranges.
    """
    h = int(hashlib.sha1(osv_id.encode()).hexdigest()[:8], 16) % 10_000_000
    return f"CHAINFORGE-91{h:07d}"


def assemble_git_record(ev: GitEvidence) -> ChainRecord | None:
    """Build ONE SILVER ChainRecord from git evidence, or None if no admissible dataflow.

    Picks the sink with the strongest most-specific source dataflow. Emits a single length-2
    chain source->sink at SILVER (dataflow-witnessed; no execution oracle for clone-based cases).
    """
    positive = [
        d for d in ev.dataflows if d.has_dataflow and is_admissible_edge(d.src_cwe, d.sink_cwe)
    ]
    if not positive:
        return None

    # For each sink, the most-specific source; then across sinks, prefer the one whose chosen
    # source is most specific (ties -> higher path_count). One chain per case, labeled by root.
    best_per_sink: dict[int, GitDataflow] = {}
    for d in positive:
        cur = best_per_sink.get(d.sink_cwe)
        key = (_SOURCE_SPECIFICITY.get(d.src_cwe, 0), d.path_count)
        if cur is None or key > (_SOURCE_SPECIFICITY.get(cur.src_cwe, 0), cur.path_count):
            best_per_sink[d.sink_cwe] = d
    chosen = max(
        best_per_sink.values(),
        key=lambda d: (_SOURCE_SPECIFICITY.get(d.src_cwe, 0), d.path_count),
    )

    dataflow_ref = (
        f"joern:reachableBy paths={chosen.path_count} (clone {ev.vuln_commit or 'fixed^'})"
    )
    source_link = ChainLink(
        cwe_id=chosen.src_cwe,
        role=LinkRole.SOURCE,
        evidence=LinkEvidence(dataflow_path=dataflow_ref),
    )
    sink_link = ChainLink(cwe_id=chosen.sink_cwe, role=LinkRole.SINK)

    return ChainRecord(
        id=_stable_id(ev.osv_id),
        aliases=[ev.osv_id],
        project=_project_from_repo(ev.repo),
        language="C",  # c2cpg frontend; clone-based mining is C/C++ only
        ecosystem="osv-git",
        commit_range=CommitRange(introduced=ev.vuln_commit, fixed=ev.fixed_commit),
        chain=[source_link, sink_link],
        chain_string=f"CWE-{chosen.src_cwe}->CWE-{chosen.sink_cwe}",
        sanitizer_reports=[],  # no execution oracle -> SILVER, never GOLD
        patch_diff=None,
        label_confidence_tier=ConfidenceTier.SILVER,
        dataflow_evidence=dataflow_ref,
        provenance="osv-git",
    )


def assemble_git_batch(evidences: list[GitEvidence]) -> list[ChainRecord]:
    """Assemble all git evidences into SILVER records (dropping those with no admissible flow)."""
    out = []
    for ev in evidences:
        rec = assemble_git_record(ev)
        if rec is not None:
            out.append(rec)
    return out
