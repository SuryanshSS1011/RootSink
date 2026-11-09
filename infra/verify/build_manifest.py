#!/usr/bin/env python3
"""Regenerate data/release/dataset.manifest.json from the release files.

The manifest is the only place a reader learns the dataset's true composition, so it must be
derived from the shipped files rather than maintained by hand - an out-of-date manifest is
worse than none. Every figure here is recomputed from dataset.jsonl and its sidecars.

Usage: build_manifest.py [--release data/release] [--out <path>]
"""

from __future__ import annotations

import argparse
import collections
import json
import os
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))
from chainforge.evidence import guard_evidence_defect, patch_is_content  # noqa: E402
from chainforge.field_policy import measure_leakage  # noqa: E402

# ARVO-derived provenances, kept explicit: the ARVO share of GOLD is a headline honesty
# number (an over-reliance on one upstream corpus is the main external criticism of the
# dataset), so it must not silently change when a new provenance tag is introduced.
ARVO_PROVENANCE = {"arvo", "arvo-len3", "arvo-len3-exec", "arvo-newarm", "arvo-msan"}


def _carries_guard(rec: dict) -> bool:
    """True if this record's patch can actually back its guard claim (see guard_evidence_defect)."""
    sha = re.search(r"[0-9a-f]{40}", (rec.get("commit_range") or {}).get("fixed") or "")
    return guard_evidence_defect(rec.get("patch_diff"), sha.group(0) if sha else "") is None


GUARD_SOURCE = {20, 129, 190, 252, 456}


def _attestation(rows):
    """Split guard-absence records into attested / explicitly unattested / unknown."""
    out = collections.Counter()
    for r in rows:
        chain = links(r)
        if not chain or chain[0].get("cwe_id") not in GUARD_SOURCE:
            continue
        ref = (chain[0].get("evidence") or {}).get("patch_hunk_ref") or ""
        if "NOT attested" in ref:
            out["unattested"] += 1
        elif re.search(r"attested|origin block|adds a guard|adds an integer-overflow", ref, re.I):
            out["attested"] += 1
        else:
            out["unknown"] += 1
    return dict(out)


def links(rec):
    return [c for c in (rec.get("chain") or []) if isinstance(c, dict)]


def link_locations(rec):
    out = []
    for c in links(rec):
        loc = (c.get("evidence") or {}).get("location")
        if loc and loc.get("file"):
            out.append(loc)
    return out


def build(rows, release_dir):
    tier = collections.Counter(r.get("label_confidence_tier") for r in rows)
    chain = collections.Counter(r.get("chain_string") for r in rows)
    eco = collections.Counter(r.get("ecosystem") or "unknown" for r in rows)
    pair_tier: dict[str, collections.Counter] = collections.defaultdict(collections.Counter)
    for r in rows:
        pair_tier[r.get("chain_string")][r.get("label_confidence_tier")] += 1

    gold = [r for r in rows if r.get("label_confidence_tier") == "gold"]
    gold_prov = collections.Counter(r.get("provenance") for r in gold)
    gold_proj = collections.Counter(r.get("project") for r in gold)
    arvo_gold = sum(v for k, v in gold_prov.items() if k in ARVO_PROVENANCE)

    obs = collections.Counter()
    for r in rows:
        for s in r.get("sanitizer_reports") or []:
            obs["upstream" if s.get("observed_by") == "upstream" else "self_or_unset"] += 1

    n_links = sum(len(link_locations(r)) for r in rows)
    n_recs = sum(1 for r in rows if link_locations(r))

    splits: dict[str, dict] = {}
    for s in ("train", "validation", "test"):
        sub = [r for r in rows if r.get("split") == s]
        if sub:
            splits[s] = {
                "n": len(sub),
                "gold": sum(1 for r in sub if r.get("label_confidence_tier") == "gold"),
            }

    sidecars = {}
    for name in (
        "single_weakness.jsonl",
        "dropped.jsonl",
        "corrections_changelog.jsonl",
        "dataset_full_consolidated.jsonl",
    ):
        p = os.path.join(release_dir, name)
        if os.path.exists(p):
            with open(p) as fh:
                sidecars[name] = sum(1 for line in fh if line.strip())

    return {
        "total": len(rows),
        "by_tier": dict(tier.most_common()),
        "by_chain": dict(chain.most_common()),
        "by_ecosystem": dict(eco.most_common()),
        "by_pair_tier": {
            k: dict(v.most_common())
            for k, v in sorted(pair_tier.items(), key=lambda kv: -sum(kv[1].values()))
        },
        "sidecars": sidecars,
        "by_chain_length": dict(sorted(collections.Counter(len(links(r)) for r in rows).items())),
        "gold_by_chain_length": dict(
            sorted(collections.Counter(len(links(r)) for r in gold).items())
        ),
        "differential_complete": dict(
            collections.Counter(str(r.get("differential_complete")) for r in rows).most_common()
        ),
        "links_with_location": n_links,
        "records_with_location": n_recs,
        "gold_by_provenance": dict(gold_prov.most_common()),
        "gold_arvo_share_pct": round(100 * arvo_gold / max(len(gold), 1)),
        "gold_top_project_share_pct": round(
            100 * (gold_proj.most_common(1)[0][1] if gold_proj else 0) / max(len(gold), 1)
        ),
        "witness_observed_by": dict(obs.most_common()),
        "by_language": dict(collections.Counter(r.get("language") for r in rows).most_common()),
        "by_locality": dict(
            collections.Counter(r.get("locality") or "unknown" for r in rows).most_common()
        ),
        "splits": splits,
        "split_policy": "project-disjoint; linux-kernel subdivided by subsystem",
        # Fix-commit dates, for consumers building a temporal contamination control.
        "fix_date_coverage": sum(1 for r in rows if r.get("fix_date")),
        "disclosure_date_coverage": sum(1 for r in rows if r.get("disclosure_date")),
        "any_date_coverage": sum(1 for r in rows if r.get("fix_date") or r.get("disclosure_date")),
        "fix_date_years": dict(
            sorted(
                collections.Counter(r["fix_date"][:4] for r in rows if r.get("fix_date")).items()
            )
        ),
        "eval_strata": {
            k or "unmarked": v
            for k, v in collections.Counter(r.get("eval_stratum") for r in rows).most_common()
        },
        # A "vise pair" is a record carrying BOTH a patched-revision sanitizer run and the
        # patch: the matched vulnerable/patched twin that makes a counterfactual well-defined.
        # Reported because the gap is structural, not incidental - see docs.
        # Guard-absence attestation: the fraction of records whose SOURCE is a missing check
        # AND whose patch demonstrably adds that check. This is the dataset's core claim, so it
        # is reported rather than left to be recomputed - a source CWE assigned because of the
        # sink's crash class attests nothing.
        # Per-record evidence floor: the WEAKEST link's kind. This is the number a consumer
        # selecting training data actually needs, and it is not the tier. GOLD is a
        # reproduction contract about the SINK; it says nothing about whether the source link
        # was ever witnessed. Reporting both, and their cross-tab, keeps that from being read
        # as a stronger claim than it is.
        # Single-field leakage of chain_string, so a consumer can see what must be withheld
        # from a policy rather than discovering it after training. See chainforge.field_policy.
        "label_leakage_by_field_held_out": measure_leakage(rows),
        "difficulty_band": dict(
            collections.Counter(r.get("difficulty_band") for r in rows).most_common()
        ),
        "evidence_floor": dict(
            collections.Counter(r.get("evidence_floor") for r in rows).most_common()
        ),
        "gold_all_links_execution_witnessed": sum(
            1 for r in gold if r.get("evidence_floor") == "execution"
        ),
        "evidence_kind_per_link": dict(
            collections.Counter(
                c.get("evidence_kind") for r in rows for c in links(r)
            ).most_common()
        ),
        "guard_absence_attested": _attestation(rows),
        # Sources demonstrated by guard ablation: applying that hunk alone to the vulnerable
        # revision silences the sanitizer. The only evidence kind here that shows causation.
        # Minimal counterfactuals: the guard hunk alone, rather than the whole developer fix.
        "minimal_guard_patches": sum(
            1
            for r in rows
            if (links(r) and (links(r)[0].get("evidence") or {}).get("minimal_guard_patch"))
        ),
        "guard_absence_causally_proven": sum(
            1
            for r in rows
            if (links(r) and (links(r)[0].get("evidence") or {}).get("causal_proof"))
        ),
        # How much of the GOLD patch evidence is the actual diff rather than a bare link. A URL
        # cannot express the guard that was added, so it cannot support a counterfactual.
        "gold_patch_materialised": sum(1 for r in gold if patch_is_content(r.get("patch_diff"))),
        # Of those, how many can actually CARRY the guard. A materialised diff that touches
        # only a Makefile, a fuzz harness or is cut mid-hunk is well-formed and still cannot
        # support the counterfactual GOLD asserts, so the two numbers must be read together.
        "gold_patch_can_carry_guard": sum(1 for r in gold if _carries_guard(r)),
        "vise_pairs_gold": sum(
            1
            for r in gold
            if r.get("patch_diff")
            and any(s.get("revision") == "patched" for s in r.get("sanitizer_reports") or [])
        ),
    }


def main(argv):
    ap = argparse.ArgumentParser()
    ap.add_argument("--release", default="data/release")
    ap.add_argument("--out", default=None)
    args = ap.parse_args(argv)

    ds = os.path.join(args.release, "dataset.jsonl")
    with open(ds) as fh:
        rows = [json.loads(x) for x in fh if x.strip()]
    man = build(rows, args.release)
    out = args.out or os.path.join(args.release, "dataset.manifest.json")
    with open(out, "w") as fh:
        json.dump(man, fh, indent=2)
    print(f"{out}: {man['total']} chains, {man['by_tier'].get('gold', 0)} GOLD")
    print(
        f"  arms={len(man['by_chain'])}  localized links={man['links_with_location']}"
        f"  ARVO share of GOLD={man['gold_arvo_share_pct']}%"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
