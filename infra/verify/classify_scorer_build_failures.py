#!/usr/bin/env python3
"""Why the scorer could not rebuild some unmodified vulnerable images.

GOLD's vulnerable run replays the fuzzer binary ARVO baked into the image (`arvo`, which runs
/out/<target> on the input). The scorer must instead rebuild the project inside the image
(`arvo compile`) so a patch can take effect. Where that rebuild of the UNMODIFIED source fails,
the record's scorer outcome is `build_fail` while its GOLD replay still crashed.

For each GOLD record whose unmodified scorer run is `build_fail`, this archives the last lines of
the runner's build log (data/evidence/score/<arvo id>/nopatch.build_tail.txt) and classifies the
cause from it:
  package unavailable  the build installs a package whose mirror no longer serves it
  dependency changed   the build fetches a dependency whose upstream content or versions changed
  build not re-runnable the image's build script fails when run again over its own output
                        (links or patches that already exist)
  unknown               none of the above matches
Writes data/validation/scorer_build_failures.json, which the paper's macros read.

Usage: classify_scorer_build_failures.py <score out dir>... [--release data/release]
"""

from __future__ import annotations

import argparse
import collections
import json
import re
from pathlib import Path

CAUSES = [
    (
        "package unavailable",
        re.compile(r"E: (Failed to fetch|Unable to fetch some archives)|Connection failed \[IP"),
    ),
    (
        "dependency changed",
        re.compile(r"Incorrect hash for source|failed to select a version for the requirement"),
    ),
    (
        "build not re-runnable",
        re.compile(
            r"failed to create (hard|symbolic) link .*File exists|already exists in working"
        ),
    ),
]


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("dirs", nargs="+")
    ap.add_argument("--release", default="data/release")
    ap.add_argument("--out", default="data/validation/scorer_build_failures.json")
    args = ap.parse_args(argv)
    with open(Path(args.release) / "dataset.jsonl") as fh:
        gold = [r for r in map(json.loads, fh) if r["label_confidence_tier"] == "gold"]
    cases, counts = [], collections.Counter()
    for r in gold:
        s = r.get("rl_scoring") or {}
        if s.get("nopatch") != "build_fail":
            continue
        aid = Path(s["evidence"]).name
        logs = [Path(d) / aid / "nopatch" / "score.log" for d in args.dirs]
        logs = [p for p in logs if p.is_file()]
        text = logs[-1].read_text(errors="replace") if logs else ""
        cause = next((name for name, rx in CAUSES if rx.search(text)), "unknown")
        if text:
            tail = "\n".join(text.splitlines()[-40:]) + "\n"
            (Path(s["evidence"]) / "nopatch.build_tail.txt").write_text(tail)
        counts[cause] += 1
        cases.append({"id": r["id"], "arvo_id": aid, "cause": cause, "log_found": bool(text)})
    out = {
        "rule": "unmodified rebuild failures of scored GOLD records",
        "counts": dict(counts),
        "cases": cases,
    }
    Path(args.out).write_text(json.dumps(out, indent=1) + "\n")
    print(json.dumps(out["counts"]))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
