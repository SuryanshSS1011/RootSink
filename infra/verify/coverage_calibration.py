#!/usr/bin/env python3
"""Calibrate the repair reward's coverage tolerance from developer fixes (PR-12 note).

`chainforge.reward.coverage_kept` compares a candidate's seed-corpus coverage (libFuzzer
features) with the unmodified vulnerable build's. A fix that deletes the vulnerable feature
also loses coverage, so the tolerance should accept nearly every developer fix. This reads the
archived score results (data/evidence/score/<arvo id>/smoke.json), keeps cases where both sides
scored as expected and both ran a non-empty seed corpus, and writes the distribution of
devfix/nopatch feature ratios to data/validation/pr12_coverage.json.

Usage: coverage_calibration.py [--evidence data/evidence/score] [--out ...]
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path


def ratios(evidence: Path) -> tuple[list[float], dict]:
    out, seen = [], {"scored": 0, "with corpus": 0, "as expected with features": 0}
    for f in sorted(evidence.glob("*/smoke.json")):
        d = json.loads(f.read_text())
        seen["scored"] += 1
        a, b = d.get("corpus_nopatch") or {}, d.get("corpus_devfix") or {}
        if a.get("inputs"):
            seen["with corpus"] += 1
        if d.get("as_expected") and a.get("ft") and b.get("ft"):
            seen["as expected with features"] += 1
            out.append(b["ft"] / a["ft"])
    return sorted(out), seen


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--evidence", default="data/evidence/score")
    ap.add_argument("--out", default="data/validation/pr12_coverage.json")
    args = ap.parse_args(argv)
    r, seen = ratios(Path(args.evidence))
    if not r:
        print("no ratios")
        return 1

    def q(p: float) -> float:
        return round(r[int(p * (len(r) - 1))], 4)

    res = {
        "rule": "PREREGISTRATION PR-12, coverage tolerance calibration",
        "counts": seen,
        "quantiles": {"min": round(r[0], 4), "p01": q(0.01), "p05": q(0.05), "median": q(0.5)},
        "accepted_at": {str(t): sum(x >= t for x in r) for t in (0.8, 0.9, 0.95, 0.99)},
        "n": len(r),
    }
    Path(args.out).write_text(json.dumps(res, indent=1) + "\n")
    print(json.dumps(res))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
