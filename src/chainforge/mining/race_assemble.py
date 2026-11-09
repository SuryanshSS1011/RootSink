"""Assemble the CWE-362 race arm (362->416 / 362->476) into ChainRecords.

The race arm is sourced from NVD multi-CWE co-occurrence (a CVE tagged both CWE-362 and a
UAF/null-deref sink) — the MITRE-endorsed CanPrecede edges 362->416 and 362->476. OSV has
zero CWE-362 records; NVD is the only public source with this population.

Tiering:
  - SILVER : the fix commit INTRODUCES a synchronization primitive (lock/atomic/refcount/
             workqueue-teardown) -> author-witnessed race remedy (patch co-signal,
             triage.patch_signals_race). This is the race-arm analogue of Strategy C.
  - BRONZE : NVD multi-CWE co-occurrence only (no fetchable fix, or fix adds no primitive) —
             a co-occurrence seed with MITRE-endorsed ordering, per schema BRONZE definition.

A data race cannot be witnessed by static single-threaded dataflow (Joern), so there is no
SILVER-by-dataflow path here and no GOLD (no execution oracle); the ceiling is patch-witness.
"""

from __future__ import annotations

import hashlib

from ..schema import (
    ChainLink,
    ChainRecord,
    CommitRange,
    ConfidenceTier,
    LinkEvidence,
    LinkRole,
)


def _stable_id(cve: str, sink: int) -> str:
    """Race-arm records get the 0x94 id band (distinct from arvo/kernel/git/len3 bands)."""
    h = int(hashlib.sha1(f"{cve}:{sink}".encode()).hexdigest()[:8], 16) % 10_000_000
    return f"CHAINFORGE-94{h:07d}"


def assemble_race_record(seed: dict) -> ChainRecord | None:
    """Build one CWE-362->{416,476} record from a tiered race-arm seed.

    Seed shape (from the NVD race harvester + patch tiering):
        {"cve", "cwe_sequence": [362, sink], "chain_string", "all_catalog_cwes",
         "fix_refs": [...], "tier": "SILVER"|"BRONZE", "race_signal": bool|None,
         "matched_patterns": [...]}
    """
    seq = seed.get("cwe_sequence") or []
    if len(seq) != 2 or seq[0] != 362 or seq[1] not in (416, 476):
        return None
    sink = seq[1]
    tier = ConfidenceTier.SILVER if seed.get("tier") == "SILVER" else ConfidenceTier.BRONZE
    fix = (seed.get("fix_refs") or [None])[0]

    if tier == ConfidenceTier.SILVER:
        pats = ", ".join(seed.get("matched_patterns", [])[:2]) or "synchronization added"
        source_ev = LinkEvidence(patch_hunk_ref=f"fix introduces sync guard: {pats[:80]}")
        evidence = (
            "patch co-signal: fix commit introduces a synchronization primitive closing a "
            "data race (author-witnessed CWE-362 root); NVD multi-CWE co-occurrence with the "
            f"CWE-{sink} sink (MITRE-direct CanPrecede 362->{sink})"
        )
    else:
        source_ev = LinkEvidence()
        evidence = (
            f"NVD multi-CWE co-occurrence: CVE tagged both CWE-362 and CWE-{sink}; "
            f"MITRE-direct CanPrecede edge 362->{sink} imposes the ordering"
        )

    chain = [
        ChainLink(cwe_id=362, role=LinkRole.SOURCE, evidence=source_ev),
        ChainLink(cwe_id=sink, role=LinkRole.SINK),
    ]
    return ChainRecord(
        id=_stable_id(seed["cve"], sink),
        aliases=[seed["cve"]],
        project="linux",  # race-arm population is overwhelmingly the kernel; refined at merge
        language="C",
        ecosystem="nvd-race",
        commit_range=CommitRange(fixed=fix),
        chain=chain,
        chain_string=f"CWE-362->CWE-{sink}",
        sanitizer_reports=[],  # race not execution-witnessed here -> never GOLD
        patch_diff=None,
        label_confidence_tier=tier,
        dataflow_evidence=evidence,
        provenance="nvd-race",
    )


def assemble_race_batch(seeds: list[dict]) -> list[ChainRecord]:
    """Assemble race-arm seeds into records, deduped by id (one chain per CVE+sink)."""
    out: list[ChainRecord] = []
    seen: set[str] = set()
    for s in seeds:
        rec = assemble_race_record(s)
        if rec is not None and rec.id not in seen:
            seen.add(rec.id)
            out.append(rec)
    return out
