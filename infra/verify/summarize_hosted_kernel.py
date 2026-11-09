#!/usr/bin/env python3
"""Summarize kernel runs on GitHub-hosted machines: did the unmodified kernel (fix^) build, and did
it reproduce syzbot's bug?

Reads `kablate_kvm.sh` result directories (hunk tests and scorer runs), in the order given, and
keeps the latest result per syzbot extid. Writes data/validation/kernel_hosted.json, which
build_macros.py joins with each record's scorer readiness. A control that never built is an
infrastructure outcome and is counted apart from one that booted (R10).

Usage: summarize_hosted_kernel.py <label>=<results dir> ...
       [--out data/validation/kernel_hosted.json]
"""

from __future__ import annotations

import argparse
import collections
import json
from pathlib import Path

BOOTED = {"ok", "no_single_hunk", "hunks_inconclusive", "control_did_not_crash"}


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("batches", nargs="+", help="label=dir, oldest first")
    ap.add_argument("--out", default="data/validation/kernel_hosted.json")
    args = ap.parse_args(argv)
    latest: dict[str, dict] = {}
    for spec in args.batches:
        label, _, d = spec.partition("=")
        for rj in sorted(Path(d).rglob("result.json")):
            res = json.loads(rj.read_text())
            if "extid" not in res:
                continue
            st = res.get("status")
            fired = res.get("control") == "crashed"
            latest[res["extid"]] = {
                "batch": label,
                "status": st,
                "control_built": st in BOOTED,
                # A kernel that built but never booted the reproducer is no verdict either (R10).
                # Results before release 1.0.5 carry no control_match; a fired control ran.
                "control_ran": fired
                or (st in BOOTED and res.get("control_match") not in (None, "no_boot", "not_run")),
                "control_fired": fired,
                "control_boots": res.get("control_boots"),
                "control_match": res.get("control_match"),
                "compiler": res.get("compiler"),
                "mode": res.get("mode", "hunk-test"),
            }
    out = {
        "what": "latest GitHub-hosted kablate_kvm.sh result per syzbot extid",
        "batches": [s.partition("=")[0] for s in args.batches],
        "summary": dict(collections.Counter(v["status"] for v in latest.values())),
        "by_extid": dict(sorted(latest.items())),
    }
    Path(args.out).write_text(json.dumps(out, indent=1) + "\n")
    print(out["summary"], len(latest))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
