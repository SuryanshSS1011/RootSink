"""Synthetic length-3 chain generation (adviser's tier-flagged flagship stratum).

CWE-190-mediated and length-3 chains are rare/unminable in the reproducible corpus (three
independent lines of evidence; see FINDINGS.md), so the length-3 stratum is SYNTHETIC:
templated spines that compose two admissible length-2 edges through a CWE-190 intermediate,
e.g. CWE-20 -> CWE-190 -> CWE-787. Every synthetic record is tier-flagged (synthetic=True,
never GOLD) so a reviewer can subset it out.

"Validated link-by-link" (the adviser's methodological story): each constituent edge is
checked against the REAL length-2 corpus. Two of the three CWEs in a 20->190->787 spine —
the source (20) and the sink (787) — appear in real GOLD chains; the 190 intermediate is the
templated insertion. So the spine's endpoints are corpus-anchored even though the overflow
middle is composed. link_validation records the real records that anchor each contracted
endpoint edge (and flags the synthetic 190 hops).

This module composes spines from a real dataset; it is pure Python (no ROAR) and testable.
"""

from __future__ import annotations

from collections import defaultdict

from .cwe import is_admissible_edge
from .schema import (
    ChainLink,
    ChainRecord,
    ConfidenceTier,
    LinkEvidence,
    LinkRole,
)

# Admissible length-3 spines through the CWE-190 intermediate (plan section 3a).
# Each is (source, intermediate=190, sink) with both edges admissible.
LENGTH3_SPINES: tuple[tuple[int, int, int], ...] = tuple(
    (src, 190, sink)
    for src in (20,)
    for sink in (787, 125, 119)
    if is_admissible_edge(src, 190) and is_admissible_edge(190, sink)
)


def _index_by_pair(real_records: list[ChainRecord]) -> dict[tuple[int, int], list[ChainRecord]]:
    """Index real length-2 records by their (source_cwe, sink_cwe) pair."""
    idx: dict[tuple[int, int], list[ChainRecord]] = defaultdict(list)
    for r in real_records:
        if len(r.chain) == 2:
            idx[(r.chain[0].cwe_id, r.chain[1].cwe_id)].append(r)
    return idx


def _anchor_refs(
    pair: tuple[int, int], by_pair: dict[tuple[int, int], list[ChainRecord]]
) -> list[str]:
    """Ids of real records anchoring a contracted endpoint edge, best (GOLD) first."""
    recs = sorted(
        by_pair.get(pair, []),
        key=lambda r: 0 if r.label_confidence_tier == ConfidenceTier.GOLD else 1,
    )
    return [r.id for r in recs[:3]]


def compose_spine(
    spine: tuple[int, int, int],
    by_pair: dict[tuple[int, int], list[ChainRecord]],
    record_id: str,
    project: str = "synthetic",
) -> ChainRecord | None:
    """Compose one synthetic length-3 record for a spine, anchored to the real corpus.

    The endpoint (contracted) edge source->sink must have at least one real record to anchor
    the spine — otherwise the spine is entirely unsupported and we return None. Tier is SILVER
    if the contracted edge is anchored by a real GOLD chain, else BRONZE.
    """
    src, mid, sink = spine
    contracted = (src, sink)
    anchors = _anchor_refs(contracted, by_pair)
    if not anchors:
        return None  # no real endpoint anchor -> do not fabricate

    has_gold_anchor = any(
        r.label_confidence_tier == ConfidenceTier.GOLD for r in by_pair.get(contracted, [])
    )
    tier = ConfidenceTier.SILVER if has_gold_anchor else ConfidenceTier.BRONZE

    # link_validation: one entry per hop. Endpoint CWEs are corpus-anchored via the
    # contracted-edge real records; the 190 hops are flagged as templated.
    link_validation = [
        f"src-hop CWE-{src}->CWE-{mid}: templated (190 unminable; see FINDINGS)",
        f"sink-hop CWE-{mid}->CWE-{sink}: templated (190 unminable); "
        f"endpoints anchored by real CWE-{src}->CWE-{sink}: {','.join(anchors)}",
    ]

    chain = [
        ChainLink(
            cwe_id=src,
            role=LinkRole.SOURCE,
            evidence=LinkEvidence(dataflow_path=f"anchored:{anchors[0]}"),
        ),
        ChainLink(cwe_id=mid, role=LinkRole.INTERMEDIATE),
        ChainLink(cwe_id=sink, role=LinkRole.SINK),
    ]
    return ChainRecord(
        id=record_id,
        project=project,
        chain=chain,
        chain_string=f"CWE-{src}->CWE-{mid}->CWE-{sink}",
        label_confidence_tier=tier,
        synthetic=True,
        link_validation=link_validation,
        provenance="synthetic-composed",
    )


def generate_length3(real_records: list[ChainRecord], id_start: int = 900000) -> list[ChainRecord]:
    """Generate the synthetic length-3 stratum from the real length-2 corpus.

    One record per admissible spine that has a real endpoint anchor. Ids are numbered from
    id_start (a high range to keep them visibly distinct from real localId-based ids).
    """
    by_pair = _index_by_pair(real_records)
    out: list[ChainRecord] = []
    n = id_start
    for spine in LENGTH3_SPINES:
        rec = compose_spine(spine, by_pair, record_id=f"CHAINFORGE-{n:07d}")
        if rec is not None:
            out.append(rec)
            n += 1
    return out
