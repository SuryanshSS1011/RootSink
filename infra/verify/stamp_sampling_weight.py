#!/usr/bin/env python3
"""Stamp `sampling_weight` on every record: an optional per-record weight that evens out projects.

GOLD is uneven across projects (the kernel alone is about a sixth of it) and OSS-Fuzz often
files several inputs for one bug. A trainer that samples records uniformly therefore sees the
largest codebases, and the bugs with the most filed inputs, far more often than the rest. The
weight lets a consumer rebalance without dropping data:

    w = 1 / (inputs in the record's duplicate group  x  sqrt(distinct bugs of its project))

counted within the record's tier, then rescaled so the weights of each (tier, split) average 1.
One bug filed as k inputs carries the weight of one input, and a project's total weight grows
with the square root of its bug count rather than linearly. A project is
`field_policy.canonical_project`, so linux-kernel counts as one codebase. Sampling uniformly
is unchanged for anyone who ignores the field. It is a harness field, never shown to the policy.

Runs from rebuild_derived.sh after dedup_groups.py, so it always matches the current groups.
Idempotent.

Usage: stamp_sampling_weight.py [--release data/release]
"""

from __future__ import annotations

import argparse
import collections
import json
import math
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))
from chainforge.field_policy import canonical_project  # noqa: E402


def weights(rows: list[dict]) -> dict[str, float]:
    bug = {r["id"]: r.get("duplicate_group") or r["id"] for r in rows}
    tier = {r["id"]: r["label_confidence_tier"] for r in rows}
    group_size = collections.Counter((tier[r["id"]], bug[r["id"]]) for r in rows)
    bugs = collections.defaultdict(set)
    for r in rows:
        bugs[(tier[r["id"]], canonical_project(r["project"]))].add(bug[r["id"]])
    raw = {
        r["id"]: 1.0
        / (
            group_size[(tier[r["id"]], bug[r["id"]])]
            * math.sqrt(len(bugs[(tier[r["id"]], canonical_project(r["project"]))]))
        )
        for r in rows
    }
    cell = collections.defaultdict(list)
    for r in rows:
        cell[(tier[r["id"]], r.get("split"))].append(r["id"])
    out = {}
    for ids in cell.values():
        mean = sum(raw[i] for i in ids) / len(ids)
        for i in ids:
            out[i] = round(raw[i] / mean, 4)
    return out


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--release", default="data/release")
    args = ap.parse_args(argv)
    path = Path(args.release) / "dataset.jsonl"
    with open(path) as fh:
        rows = [json.loads(line) for line in fh]
    w = weights(rows)
    changed = 0
    for r in rows:
        if r.get("sampling_weight") != w[r["id"]]:
            r["sampling_weight"] = w[r["id"]]
            changed += 1
    with open(path, "w") as fh:
        fh.writelines(json.dumps(r) + "\n" for r in rows)
    print(f"sampling_weight stamped; {changed} changed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
