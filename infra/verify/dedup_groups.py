#!/usr/bin/env python3
"""Mark near-duplicate records and keep each duplicate group, and each project, inside one split.

OSS-Fuzz often closes several crash reports with one fix: different inputs, one bug. They are
kept (each is a distinct reproduction) but share `duplicate_group` = "<project>@<fix sha[:12]>",
so a consumer can count bugs rather than inputs or deduplicate for training. A group that spans
splits leaks one bug into both train and test; every member is moved to the split of the group's
lexicographically first record id (deterministic), and each move is logged. Groups are keyed on
the fix commit alone: the same fix filed under two project names is still one bug.

One codebase also arrives under several project names (`php-src` and `php/php-src`, or a fork),
which the project-disjoint split cannot see. Before grouping, every canonical project
(`field_policy.canonical_project`) is moved whole into the split that already holds most of its
records (ties: the alphabetically first split). linux-kernel is split by subsystem on purpose,
and `linux` is the nvd-race catch-all rather than one codebase; both are left alone.

Usage: dedup_groups.py [--release data/release]
"""

from __future__ import annotations

import argparse
import collections
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))
from chainforge.field_policy import canonical_project  # noqa: E402

NOT_ONE_CODEBASE = {"linux-kernel", "linux"}


def crash(r: dict) -> str:
    return next((a for a in r["aliases"] if a.startswith(("OSS-Fuzz-", "syzbot-"))), r["id"])


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--release", default="data/release")
    args = ap.parse_args(argv)
    rel = Path(args.release)
    with open(rel / "dataset.jsonl") as fh:
        rows = [json.loads(line) for line in fh]

    log, stats = [], collections.Counter()
    by_project = collections.defaultdict(list)
    for r in rows:
        by_project[canonical_project(r["project"])].append(r)
    for proj, members in sorted(by_project.items()):
        if proj in NOT_ONE_CODEBASE:
            continue
        sizes = collections.Counter(r.get("split") for r in members)
        if len(sizes) < 2:
            continue
        target = min(sizes, key=lambda k: (-sizes[k], k))
        stats["projects consolidated"] += 1
        for r in members:
            if r.get("split") != target:
                log.append(
                    {
                        "id": r["id"],
                        "op": "project-alias-split",
                        "from": r.get("split"),
                        "to": target,
                        "project": r["project"],
                        "canonical": proj,
                    }
                )
                r["split"] = target
                stats["moved for project alias"] += 1

    groups = collections.defaultdict(list)
    for r in rows:
        r.pop("duplicate_group", None)
        sha = re.search(r"[0-9a-f]{40}", (r.get("commit_range") or {}).get("fixed") or "")
        if sha:
            groups[sha.group(0)[:12]].append(r)

    for sha, members in groups.items():
        if len({crash(r) for r in members}) < 2:
            continue
        stats["groups"] += 1
        anchor = min(members, key=lambda r: r["id"])
        key = f"{anchor['project']}@{sha}"
        for r in members:
            r["duplicate_group"] = key
            stats["records"] += 1
            if r.get("split") != anchor.get("split"):
                log.append(
                    {
                        "id": r["id"],
                        "op": "dedup-split",
                        "from": r.get("split"),
                        "to": anchor.get("split"),
                        "group": key,
                    }
                )
                r["split"] = anchor.get("split")
                stats["moved across splits"] += 1

    with open(rel / "dataset.jsonl", "w") as fh:
        fh.writelines(json.dumps(r) + "\n" for r in rows)
    with open(rel / "corrections_changelog.jsonl", "a") as fh:
        fh.writelines(json.dumps(e) + "\n" for e in log)
    print(dict(stats))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
