#!/usr/bin/env python3
"""Put the outcome of our kernel differential attempts on each record they were made for (1.0.10).

`infra/cse-kvm/kdiff_kvm.sh` builds and boots a syzbot record's vulnerable and fixed kernels and
runs its reproducer. Until 1.0.10 the outcome of an attempt that did not yield an archived
two-sided run (the bug did not reproduce, another bug fired, a build failed, or the fixed kernel
crashed the same way) was kept only in `corrections_changelog.jsonl` as a
`kernel-differential-attempt` entry, and its logs were not archived. This step copies one such
entry onto the record as `kernel_attempt` (status, detail, both commits, number of attempts): the
latest attempt that ran the reproducer (`chainforge.integrity.attempt_ran`), or, if none did, the
latest attempt.
Only a `differential` attempt has logs, attached as the record's own `sanitizer_reports`. A
consumer can now see why an Upstream record has no run of ours, and the GOLD contract
(`chainforge.integrity`) can read a fixed kernel that still crashed. It changes no label, site or
tier itself. Every stamp is logged. Idempotent.

Usage: stamp_kernel_attempts.py [--release data/release]
"""

from __future__ import annotations

import argparse
import collections
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))
from chainforge.integrity import attempt_ran  # noqa: E402

RULE = "kernel attempt outcomes 2026-11-09 (release 1.0.10)"
KEYS = ("status", "detail", "vulnerable_commit", "fix_commit")


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--release", default="data/release")
    args = ap.parse_args(argv)
    rel = Path(args.release)
    attempts = collections.defaultdict(list)
    with open(rel / "corrections_changelog.jsonl") as fh:
        for line in fh:
            e = json.loads(line)
            if e.get("op") == "kernel-differential-attempt":
                attempts[e["id"]].append(e)
    with open(rel / "dataset.jsonl") as fh:
        rows = [json.loads(line) for line in fh]
    log, stats = [], collections.Counter()
    for r in rows:
        tried = attempts.get(r["id"])
        if not tried:
            continue
        # The latest attempt that ran the reproducer says the most about the bug; a later build
        # failure says nothing (R10). With no such attempt, the latest attempt.
        ran = [e for e in tried if attempt_ran(e)]
        last = (ran or tried)[-1]
        stamp = {k: last.get(k) for k in KEYS} | {"attempts": len(tried)}
        stats[f"{r.get('label_confidence_tier')} {last.get('status')}"] += 1
        if r.get("kernel_attempt") != stamp:
            r["kernel_attempt"] = stamp
            log.append(
                {
                    "id": r["id"],
                    "op": "kernel-attempt-stamped",
                    "rule": RULE,
                    "status": stamp["status"],
                }
            )
    with open(rel / "dataset.jsonl", "w") as fh:
        fh.writelines(json.dumps(r) + "\n" for r in rows)
    with open(rel / "corrections_changelog.jsonl", "a") as fh:
        fh.writelines(json.dumps(e) + "\n" for e in log)
    print(dict(stats))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
