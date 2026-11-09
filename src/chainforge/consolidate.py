"""Dataset consolidation: merge per-batch evidence into one canonical dataset.

Pilot batches accumulate as separate evidence directories, and the SAME ARVO case can
appear in more than one batch — sometimes with different labels (e.g. a use-after-free case
labeled CWE-20->787 by an early batch before the lifecycle detector existed, and correctly
CWE-416->787 by a later one). Naively assembling all of them double-counts and keeps stale
mislabels.

This module deduplicates by ARVO localId and assigns a STABLE record id keyed to the
localId (so re-running a case updates rather than duplicates), keeping the BEST record per
localId. "Best" = higher confidence tier, then more-specific source CWE (the lifecycle/
overflow root over the broad CWE-20 fallback) — i.e. the later, corrected labeling wins. It
also emits a manifest (counts by tier and CWE pair) so the dataset's true composition is
explicit.
"""

from __future__ import annotations

import hashlib
from collections import Counter
from dataclasses import dataclass, field

from .pilot import _SOURCE_SPECIFICITY
from .schema import ChainRecord, ConfidenceTier

# Tier ordering for "best record" comparison.
_TIER_RANK = {ConfidenceTier.GOLD: 3, ConfidenceTier.SILVER: 2, ConfidenceTier.BRONZE: 1}

# Stable id format: CHAINFORGE-<zero-padded localId>. Keyed to the ARVO localId so the same
# case always gets the same record id across re-runs and batches.
_ID_PREFIX = "CHAINFORGE"


def stable_id(local_id: int) -> str:
    """Deterministic record id for an ARVO localId (stable across runs/batches)."""
    return f"{_ID_PREFIX}-{local_id:010d}"


def _source_cwe(rec: ChainRecord) -> int:
    return rec.chain[0].cwe_id


def record_score(rec: ChainRecord) -> tuple[int, int]:
    """Rank a record for dedup: (tier rank, source specificity). Higher is better.

    A GOLD 416->787 beats a BRONZE 20->787; among same-tier records, the more-specific root
    (416 > 476 > 190 > 20) wins — so a corrected lifecycle/overflow label supersedes an
    earlier broad CWE-20 mislabel for the same case.
    """
    return (
        _TIER_RANK.get(rec.label_confidence_tier, 0),
        _SOURCE_SPECIFICITY.get(_source_cwe(rec), 0),
    )


def _local_id_of(rec: ChainRecord) -> int | None:
    """Extract the ARVO localId from a record's aliases (OSS-Fuzz-<id>)."""
    for a in rec.aliases:
        if a.startswith("OSS-Fuzz-"):
            tail = a.removeprefix("OSS-Fuzz-")
            if tail.isdigit():
                return int(tail)
    return None


def _dedup_key(rec: ChainRecord) -> str | None:
    """Stable dedup key from a record's provenance id, or None if it has no known one.

    ARVO -> 'ossfuzz:<localId>' (numeric); syzbot -> 'syzbot:<extid>'. Records keyed this way
    dedup across batches AND get a stable, provenance-derived id (so a re-harvest updates rather
    than duplicating). The SAME kernel bug across kernel versions shares its syzbot extid.
    """
    lid = _local_id_of(rec)
    if lid is not None:
        return f"ossfuzz:{lid}"
    for a in rec.aliases:
        if a.startswith("syzbot-"):
            return f"syzbot:{a.removeprefix('syzbot-')}"
    return None


def _stable_id_for_key(key: str) -> str:
    """Stable CHAINFORGE id from a dedup key (schema requires digits: ^CHAINFORGE-\\d{4,}$).

    ARVO keeps its localId-based id. syzbot: a deterministic numeric id in a distinct '9'
    range from a hash of the extid, so it never collides with ARVO's localId-based ids.
    """
    kind, _, val = key.partition(":")
    if kind == "ossfuzz" and val.isdigit():
        return stable_id(int(val))
    # Deterministic 12-digit numeric hash of the extid, prefixed '9' to isolate the range.
    digest = int(hashlib.sha1(val.encode()).hexdigest(), 16) % (10**11)
    return f"{_ID_PREFIX}-9{digest:011d}"


@dataclass
class Manifest:
    """Summary of a consolidated dataset."""

    total: int
    by_tier: dict[str, int] = field(default_factory=dict)
    by_chain: dict[str, int] = field(default_factory=dict)
    by_pair_tier: dict[str, dict[str, int]] = field(default_factory=dict)
    distinct_projects: int = 0
    superseded: int = 0  # duplicate localIds dropped in favor of a better record

    def to_dict(self) -> dict:
        return {
            "total": self.total,
            "by_tier": self.by_tier,
            "by_chain": self.by_chain,
            "by_pair_tier": self.by_pair_tier,
            "distinct_projects": self.distinct_projects,
            "superseded_duplicates": self.superseded,
        }


def consolidate(records: list[ChainRecord]) -> tuple[list[ChainRecord], Manifest]:
    """Deduplicate by provenance key (ARVO localId or syzbot extid), keep the best, assign
    stable ids, build manifest.

    Records without a recognizable provenance key are kept as-is (by their existing id). The
    returned records are sorted by stable id for deterministic output.
    """
    best: dict[str, ChainRecord] = {}
    no_id: list[ChainRecord] = []
    superseded = 0

    for rec in records:
        key = _dedup_key(rec)
        if key is None:
            no_id.append(rec)
            continue
        if key not in best:
            best[key] = rec
        else:
            # keep whichever scores higher; the other is superseded
            if record_score(rec) > record_score(best[key]):
                best[key] = rec
            superseded += 1

    # Re-id the deduped records with their stable provenance-derived id.
    out: list[ChainRecord] = []
    for key, rec in best.items():
        out.append(rec.model_copy(update={"id": _stable_id_for_key(key)}))
    out.extend(no_id)
    out.sort(key=lambda r: r.id)

    manifest = _build_manifest(out, superseded)
    return out, manifest


def _build_manifest(records: list[ChainRecord], superseded: int) -> Manifest:
    by_tier: Counter[str] = Counter()
    by_chain: Counter[str] = Counter()
    by_pair_tier: dict[str, Counter[str]] = {}
    projects: set[str] = set()

    for rec in records:
        tier = rec.label_confidence_tier.value
        by_tier[tier] += 1
        by_chain[rec.chain_string] += 1
        by_pair_tier.setdefault(rec.chain_string, Counter())[tier] += 1
        projects.add(rec.project)

    return Manifest(
        total=len(records),
        by_tier=dict(by_tier),
        by_chain=dict(by_chain),
        by_pair_tier={k: dict(v) for k, v in by_pair_tier.items()},
        distinct_projects=len(projects),
        superseded=superseded,
    )
