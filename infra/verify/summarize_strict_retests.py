#!/usr/bin/env python3
"""Summarise the strict (fuzz 0) re-tests of hunk tests the fuzz check withdrew.

Input: the merged output dirs of the runner's `ablate` and `pairs` re-test runs (each case has
result.json with control, guard_hunk or proving_pair, and fuzz 0). Counts cases whose control
crashed and whose hunk or pair still suffices at fuzz 0. Writes
data/validation/fuzzcheck_retest.json, which the paper's macros read.

Usage: summarize_strict_retests.py --ablate DIR... --pairs DIR...
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path


def tally(dirs: list[str], key: str, skip: set[str]) -> dict:
    n = held = no_control = 0
    for d in dirs:
        for rj in Path(d).glob("*/result.json"):
            if rj.parent.name in skip:
                continue
            r = json.loads(rj.read_text())
            if r.get("control") != "crashed":
                no_control += 1
                continue
            n += 1
            held += bool(r.get(key))
    return {"retested": n, "held_at_fuzz0": held, "control_not_crashed": no_control}


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--ablate", nargs="+", default=[])
    ap.add_argument("--pairs", nargs="+", default=[])
    ap.add_argument(
        "--exclude",
        nargs="*",
        default=[],
        help="ARVO ids re-tested for another reason (PR-13b replication)",
    )
    ap.add_argument("--out", default="data/validation/fuzzcheck_retest.json")
    args = ap.parse_args(argv)
    out = {
        "rule": "PR-4/PR-13 fuzz check, strict re-tests",
        "single_hunk": tally(args.ablate, "guard_hunk", set(args.exclude)),
        "pairs": tally(args.pairs, "proving_pair", set(args.exclude)),
    }
    Path(args.out).write_text(json.dumps(out, indent=1) + "\n")
    print(json.dumps(out))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
