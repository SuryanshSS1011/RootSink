#!/usr/bin/env python3
"""Re-tier every record by chainforge.integrity, in either direction, and log it.

Pipelines re-tier only the records they touch. When the contract's implementation changes (as on
2026-10-20, when I5's "clean twice" was first enforced as written), every record must be judged
again by the same code the release gate uses. Until release 1.0.9 a Candidate was left alone unless
a run of ours reached it (release 1.0.5 corrections, item 1). From release 1.0.10 every record gets
the tier the paper's rules give (`chainforge.integrity.expected_tier`): an Upstream record is
Partial when our own fixed-kernel run crashed with the same bug, and a record no run of ours
reached is a Candidate when its root CWE rests only on an advisory or the catalogue's default
(`chainforge.integrity.unreached_tier`). A change made by either rule is logged with its rule.
Idempotent; run from rebuild_derived.sh.

Usage: retier_all.py [--release data/release] [--dry-run]
"""

from __future__ import annotations

import argparse
import collections
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))
from chainforge.evidence import cwe_basis  # noqa: E402
from chainforge.integrity import expected_tier, reached  # noqa: E402


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--release", default="data/release")
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args(argv)
    rel = Path(args.release)
    with open(rel / "dataset.jsonl") as fh:
        rows = [json.loads(line) for line in fh]
    log, stats = [], collections.Counter()
    for r in rows:
        old = r["label_confidence_tier"]
        # Release 1.0.10: every tier, Candidates included, is the one the paper's rules give
        # (`chainforge.integrity.expected_tier`). Until 1.0.9 a Candidate no run of ours reached
        # kept its source pipeline's tier (release 1.0.5 corrections, item 1).
        new, v = expected_tier(r, Path("."))
        if v:
            r["gold_contract_gaps"] = v
        else:
            r.pop("gold_contract_gaps", None)
        if new != old:
            stats[f"{old} -> {new}"] += 1
            r["label_confidence_tier"] = new
            entry = {"id": r["id"], "op": "contract-retier", "from": old, "to": new, "rules": v}
            if new == "bronze" or (old == "bronze" and not reached(r, Path("."))):
                root = (r.get("chain") or [{}])[0]
                entry["rule"] = "unreached Candidate rule (release 1.0.10)"
                entry["root_basis"] = cwe_basis(root, r.get("provenance") or "")
            elif v.get("I5", "").startswith("our "):
                entry["rule"] = "fixed kernel crashed the same way (release 1.0.10)"
            log.append(entry)
    print(dict(stats))
    if args.dry_run:
        return 0
    with open(rel / "dataset.jsonl", "w") as fh:
        fh.writelines(json.dumps(r) + "\n" for r in rows)
    with open(rel / "corrections_changelog.jsonl", "a") as fh:
        fh.writelines(json.dumps(e) + "\n" for e in log)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
