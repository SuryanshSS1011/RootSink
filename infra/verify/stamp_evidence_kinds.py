#!/usr/bin/env python3
"""Stamp evidence_kind on every link and evidence_floor on every record.

Makes SPECIFICATION R3 queryable. Before this, the only way to know what backed a link was to
regex the prose in patch_hunk_ref, which left 752 links unclassifiable and 620 with nothing to
read - so the query R3 implies ("every link at least execution-witnessed") could not be
written at all.

Usage: stamp_evidence_kinds.py <dataset.jsonl> --out <out.jsonl>
"""

from __future__ import annotations

import argparse
import collections
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))
from chainforge.evidence import classify_link, floor  # noqa: E402


def main(argv):
    ap = argparse.ArgumentParser()
    ap.add_argument("dataset")
    ap.add_argument("--out", required=True)
    args = ap.parse_args(argv)

    with open(args.dataset) as fh:
        rows = [json.loads(x) for x in fh if x.strip()]

    per_link, per_record = collections.Counter(), collections.Counter()
    for rec in rows:
        for c in rec.get("chain") or []:
            if not isinstance(c, dict):
                continue
            k = classify_link(c.get("evidence"))
            c["evidence_kind"] = str(k)
            per_link[str(k)] += 1
        f = floor(rec)
        rec["evidence_floor"] = str(f)
        per_record[str(f)] += 1

    with open(args.out, "w") as fh:
        for rec in rows:
            fh.write(json.dumps(rec) + "\n")

    print("per-link evidence_kind:")
    for k, v in per_link.most_common():
        print(f"  {v:6d}  {k}")
    print("\nper-record evidence_floor (the weakest link):")
    for k, v in per_record.most_common():
        print(f"  {v:6d}  {k}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
