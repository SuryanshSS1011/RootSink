#!/usr/bin/env python3
"""Re-stamp `difficulty_proxy` and `difficulty_band` on every record from its current evidence.

Both are a pure function of the record (`chainforge.difficulty`), but they were written once, by
whichever step created the record, and never again. Records admitted later (PR-7) had none, and
records whose evidence changed (proofs, sink attribution, patches) kept a stale band. Run from
rebuild_derived.sh so the fields cannot drift from the evidence again. Idempotent.

Usage: stamp_difficulty.py [--release data/release]
"""

from __future__ import annotations

import argparse
import collections
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))
from chainforge import difficulty  # noqa: E402


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--release", default="data/release")
    args = ap.parse_args(argv)
    path = Path(args.release) / "dataset.jsonl"
    with open(path) as fh:
        rows = [json.loads(line) for line in fh]
    changed = collections.Counter()
    for r in rows:
        p, b = difficulty.proxy(r), difficulty.band(r)
        if (r.get("difficulty_proxy"), r.get("difficulty_band")) != (p, b):
            changed[f"{r.get('difficulty_band')} -> {b}"] += 1
            r["difficulty_proxy"], r["difficulty_band"] = p, b
    if changed:
        with open(path, "w") as fh:
            fh.writelines(json.dumps(r) + "\n" for r in rows)
    for k, n in sorted(changed.items()):
        print(f"{n:6d}  {k}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
