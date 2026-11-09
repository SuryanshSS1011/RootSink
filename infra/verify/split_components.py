#!/usr/bin/env python3
"""Keep each linux-kernel subsystem inside one split without breaking a duplicate group (R9).

linux-kernel is split by subsystem (`fix_p0_metadata.split_unit`). A duplicate group (one bug, one
fix commit) can span subsystems when its fix touches several, and dedup_groups.py pulls its
members into one split, which can leave part of a subsystem in another fold. This pass joins split
units that share a duplicate group into one component and moves every component that spans folds
wholly into the fold holding most of its records (ties: the alphabetically first fold), logging
each move with rule R9. Projects outside the kernel are already whole by canonical name
(dedup_groups.py, `canonical_project`), and `linux`, the nvd-race catch-all, is not one codebase
and is left alone. Idempotent.

Usage: split_components.py [--release data/release]
"""

from __future__ import annotations

import argparse
import collections
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))
from fix_p0_metadata import split_unit  # noqa: E402


def unit(r: dict) -> str:
    u = split_unit(r)
    return f"record:{r['id']}" if u == "linux" else f"unit:{u}"  # the catch-all binds nothing


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--release", default="data/release")
    args = ap.parse_args(argv)
    rel = Path(args.release)
    with open(rel / "dataset.jsonl") as fh:
        rows = [json.loads(line) for line in fh]

    parent: dict[str, str] = {}

    def find(x: str) -> str:
        parent.setdefault(x, x)
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    for r in rows:
        parent[find(f"id:{r['id']}")] = find(unit(r))
        if r.get("duplicate_group"):
            parent[find(f"group:{r['duplicate_group']}")] = find(f"id:{r['id']}")
    comps: dict[str, list[dict]] = collections.defaultdict(list)
    for r in rows:
        comps[find(f"id:{r['id']}")].append(r)

    log, stats = [], collections.Counter()
    for members in comps.values():
        folds = collections.Counter(r.get("split") for r in members)
        if len(folds) < 2:
            continue
        target = min(folds, key=lambda k: (-folds[k], k))
        units = sorted({unit(r).removeprefix("unit:") for r in members})
        stats["components spanning folds"] += 1
        for r in members:
            if r.get("split") != target:
                log.append(
                    {
                        "id": r["id"],
                        "op": "split-component",
                        "rule": "R9",
                        "from": r.get("split"),
                        "to": target,
                        "why": f"split unit {unit(r).removeprefix('unit:')} shares a fold with "
                        f"{len(units)} unit(s) linked by duplicate groups",
                    }
                )
                r["split"] = target
                stats[f"moved ({r['label_confidence_tier']})"] += 1

    if log:
        with open(rel / "dataset.jsonl", "w") as fh:
            fh.writelines(json.dumps(r) + "\n" for r in rows)
        with open(rel / "corrections_changelog.jsonl", "a") as fh:
            fh.writelines(json.dumps(e) + "\n" for e in log)
    print(dict(stats) or "no component spans folds")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
