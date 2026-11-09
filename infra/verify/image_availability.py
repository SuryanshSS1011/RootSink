#!/usr/bin/env python3
"""How available ARVO's images were when PR-12 scored them on GitHub-hosted runners.

Reads the archived scorer results (data/evidence/score/<arvo id>/smoke.json). An image counts as
pulled when either side produced a scored outcome; a case that stopped before pulling (its fix
diff could not be fetched) is not a pull attempt. Writes data/validation/image_availability.json.

Usage: image_availability.py [--evidence data/evidence/score]
"""

from __future__ import annotations

import argparse
import collections
import json
from pathlib import Path

SCORED = {"crash", "pass", "build_fail", "patch_fail"}


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--evidence", default="data/evidence/score")
    ap.add_argument("--out", default="data/validation/image_availability.json")
    args = ap.parse_args(argv)
    st = collections.Counter()
    for f in sorted(Path(args.evidence).glob("*/smoke.json")):
        s = json.loads(f.read_text())
        if s.get("nopatch") in SCORED or s.get("devfix") in SCORED:
            st["pulled and ran"] += 1
        elif s.get("status") == "diff_unfetchable":
            st["stopped before pulling (fix diff unfetchable)"] += 1
        else:
            st["pull or run failed"] += 1
    out = {"rule": "ARVO image availability during PR-12 scoring", "counts": dict(st)}
    Path(args.out).write_text(json.dumps(out, indent=1) + "\n")
    print(json.dumps(out))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
