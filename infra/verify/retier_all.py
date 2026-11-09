#!/usr/bin/env python3
"""Re-tier every GOLD and SILVER record by chainforge.integrity, in either direction, and log it.

Pipelines re-tier only the records they touch. When the contract's implementation changes (as on
2026-10-20, when I5's "clean twice" was first enforced as written), every record must be judged
again by the same code the release gate uses. Gold-upstream is left to the pipelines that set it,
and so is a Candidate unless a run of ours reached it (release 1.0.5 corrections, item 1).
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
from chainforge.integrity import gold_violations, tier_for, vul_log  # noqa: E402


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
        # A Candidate that a run of ours reached is judged like any other run record (release
        # 1.0.5 corrections, item 1); Candidates no run of ours reached keep their tier.
        ran = old == "bronze" and vul_log(r, Path(".")) is not None
        if old not in ("gold", "silver") and not ran:
            continue
        v = gold_violations(r, Path("."))
        new = tier_for(r, v)
        if v:
            r["gold_contract_gaps"] = v
        else:
            r.pop("gold_contract_gaps", None)
        if new != old:
            stats[f"{old} -> {new}"] += 1
            r["label_confidence_tier"] = new
            log.append({"id": r["id"], "op": "contract-retier", "from": old, "to": new, "rules": v})
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
