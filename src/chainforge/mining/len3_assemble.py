"""Assemble patch-witnessed length-3 chains (Strategy C) into 3-link ChainRecords.

Input: the strat_c output (list of {osv_id, repo, fixed_commit, chain, sink_cwe, input_patterns,
overflow_patterns}). Each becomes a CWE-20 -> CWE-190 -> sink record. Tier is SILVER: the fix
diff introducing BOTH an input-validation guard AND an overflow guard is a strong PATCH witness
that the author recognized the chain, but it is not an execution witness -> not GOLD. The two
patch hunks are recorded per-link as the evidence for that hop.
"""

from __future__ import annotations

import hashlib
import re

from ..schema import (
    ChainLink,
    ChainRecord,
    CommitRange,
    ConfidenceTier,
    LinkEvidence,
    LinkRole,
)


def _project(repo: str) -> str:
    m = re.search(r"github\.com[:/]+([^/]+/[^/.]+)", repo)
    return m.group(1) if m else (repo or "unknown")


def _stable_id(osv_id: str) -> str:
    """Length-3 records get the 0x93 id band (distinct from arvo/kernel/git-len2 bands)."""
    h = int(hashlib.sha1(osv_id.encode()).hexdigest()[:8], 16) % 10_000_000
    return f"CHAINFORGE-93{h:07d}"


def assemble_len3_record(cand: dict) -> ChainRecord | None:
    """Build one 3-link CWE-20->CWE-190->sink SILVER record from a Strategy C candidate."""
    sink = cand.get("sink_cwe")
    if sink not in (787, 125, 119):
        return None
    # Normalize across the two candidate shapes: GIT (osv_id/repo) and ARVO (local_id/project).
    is_arvo = "local_id" in cand
    alias = f"OSS-Fuzz-{cand['local_id']}" if is_arvo else cand["osv_id"]
    id_seed = str(cand["local_id"]) if is_arvo else cand["osv_id"]
    project = cand["project"] if is_arvo else _project(cand.get("repo", ""))
    ecosystem = "arvo-len3" if is_arvo else "osv-git-len3"
    lang = "C++" if is_arvo and (cand.get("language", "").lower() in ("c++", "cpp")) else "C"
    inp = ", ".join(cand.get("input_patterns", [])[:2]) or "input-validation guard added"
    ovf = ", ".join(cand.get("overflow_patterns", [])[:2]) or "overflow guard added"
    chain = [
        ChainLink(
            cwe_id=20,
            role=LinkRole.SOURCE,
            evidence=LinkEvidence(patch_hunk_ref=f"fix adds input guard: {inp[:80]}"),
        ),
        ChainLink(
            cwe_id=190,
            role=LinkRole.INTERMEDIATE,
            evidence=LinkEvidence(patch_hunk_ref=f"fix adds overflow guard: {ovf[:80]}"),
        ),
        ChainLink(cwe_id=sink, role=LinkRole.SINK),
    ]
    return ChainRecord(
        id=_stable_id(id_seed),
        aliases=[alias],
        project=project,
        language=lang,
        ecosystem=ecosystem,
        commit_range=CommitRange(fixed=cand.get("fixed_commit")),
        chain=chain,
        chain_string=f"CWE-20->CWE-190->CWE-{sink}",
        sanitizer_reports=[],  # patch-witnessed, not execution-witnessed -> SILVER
        patch_diff=None,
        label_confidence_tier=ConfidenceTier.SILVER,
        dataflow_evidence=(
            "patch co-signal: fix commit introduces BOTH an input-validation guard and an "
            "integer-overflow guard (author-witnessed 20->190->sink chain; Strategy C)"
        ),
        provenance=ecosystem,
    )


def assemble_len3_batch(cands: list[dict]) -> list[ChainRecord]:
    out = []
    seen = set()
    for c in cands:
        rec = assemble_len3_record(c)
        if rec is not None and rec.id not in seen:
            seen.add(rec.id)
            out.append(rec)
    return out
