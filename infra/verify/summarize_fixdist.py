#!/usr/bin/env python3
"""Summarise the fix-distance probe (runner `fixdist` workflow, scripts/fix_distance.sh).

Per sampled image (data/validation/fixdist_sample.json, by scorer outcome group): does the
vulnerable image's project repository sit at the fix's parent, how many commits and files lie
between them, does the fixed image sit at the fix commit, and do other repositories under /src
differ between the two images. GOLD's patched runs use the fixed image, while the scorer applies
the fix commit's diff to the vulnerable image, so the two can disagree whenever any of these
differ. Writes data/validation/fixdist_result.json, which the paper's macros read.

Usage: summarize_fixdist.py <fixdist.jsonl>... [--sample ...] [--out ...]
"""

from __future__ import annotations

import argparse
import collections
import json
import statistics
from pathlib import Path


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("results", nargs="+")
    ap.add_argument("--sample", default="data/validation/fixdist_sample.json")
    ap.add_argument("--out", default="data/validation/fixdist_result.json")
    args = ap.parse_args(argv)
    got = {}
    for f in args.results:
        for line in Path(f).read_text().splitlines():
            if line.strip():
                d = json.loads(line)
                got[d["arvo_id"]] = d
    groups = collections.defaultdict(list)
    for c in json.loads(Path(args.sample).read_text())["cases"]:
        groups[c["group"]].append(got.get(c["arvo_id"], {"status": "no result"}))
    out = {"rule": "fix-distance probe (PREREGISTRATION, 2026-10-23)", "groups": {}}
    for g, rows in groups.items():
        ok = [d for d in rows if d.get("status") == "ok" and d.get("vul_at_fix_parent") is not None]
        dist = [d["commits_vul_to_fix_parent"] for d in ok if d["commits_vul_to_fix_parent"] >= 0]
        moved = [d for d in ok if not d["vul_at_fix_parent"]]
        out["groups"][g] = {
            "sampled": len(rows),
            "measured": len(ok),
            "not_measured": dict(collections.Counter(d.get("status") for d in rows if d not in ok)),
            "vul_at_fix_parent": sum(d["vul_at_fix_parent"] for d in ok),
            "vul_behind_fix_parent": sum(
                (not d["vul_at_fix_parent"]) and d["vul_before_fix_parent"] for d in ok
            ),
            "vul_not_ancestor": sum(not d["vul_before_fix_parent"] for d in moved),
            "median_commits_behind": statistics.median([x for x in dist if x > 0])
            if any(x > 0 for x in dist)
            else 0,
            "fix_image_at_fix": sum(d.get("fix_image_at_fix") is True for d in ok),
            "fix_image_measured": sum(d.get("fix_image_at_fix") is not None for d in ok),
            "other_repos_differ": sum((d.get("other_repos_differing") or 0) > 0 for d in ok),
            "same_tree_as_scorer": sum(
                d["vul_at_fix_parent"]
                and d.get("fix_image_at_fix") is True
                and not d.get("other_repos_differing")
                for d in ok
            ),
        }
    Path(args.out).write_text(json.dumps(out, indent=1) + "\n")
    print(json.dumps(out, indent=1))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
