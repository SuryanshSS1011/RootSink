#!/usr/bin/env python3
"""Recompute every record's MITRE grounding (`mitre_chain`) from its current chain.

The grounding is derived data: when the classifier or the CWE subset changes (PR-17 added the
`mitre-inherited` kind, under which CWE-416 -> CWE-125/787 is endorsed through CWE-825), stored
groundings go stale. Logged as `mitre-regrounded` with the old and new edge kinds. Idempotent.

Usage: reground_mitre.py [--release data/release]
"""

from __future__ import annotations

import argparse
import collections
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent))
from apply_pr4 import mitre  # noqa: E402


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--release", default="data/release")
    args = ap.parse_args(argv)
    rel = Path(args.release)
    with open(rel / "dataset.jsonl") as fh:
        rows = [json.loads(line) for line in fh]
    log, stats = [], collections.Counter()
    for r in rows:
        new = mitre([link["cwe_id"] for link in r.get("chain") or []])
        old = r.get("mitre_chain") or {}
        if new != old:
            kinds = lambda m: [e["kind"] for e in m.get("edges", [])]  # noqa: E731
            stats[f"{kinds(old)} -> {kinds(new)}"] += 1
            log.append(
                {"id": r["id"], "op": "mitre-regrounded", "from": kinds(old), "to": kinds(new)}
            )
            r["mitre_chain"] = new
    with open(rel / "dataset.jsonl", "w") as fh:
        fh.writelines(json.dumps(r) + "\n" for r in rows)
    with open(rel / "corrections_changelog.jsonl", "a") as fh:
        fh.writelines(json.dumps(e) + "\n" for e in log)
    for k, v in stats.most_common():
        print(f"{v:6d}  {k}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
