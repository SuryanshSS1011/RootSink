#!/usr/bin/env python3
"""Mark kernel hunk tests as applied with exact context.

The kernel single-hunk test (infra/cse-kvm/kablate_kvm.sh) applies each hunk with `git apply`,
which, like GNU patch at fuzz 0, accepts a line offset but requires every context line to match.
The fuzz check of ARVO hunk tests therefore has nothing to check for these, and their tests get
`application: "strict"` with the reason. Logged as `application-stamped`. Idempotent.

Usage: stamp_kernel_application.py [--release data/release]
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

KINDS = ("causal_proof", "guard_site_proof")


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--release", default="data/release")
    args = ap.parse_args(argv)
    rel = Path(args.release)
    with open(rel / "dataset.jsonl") as fh:
        rows = [json.loads(line) for line in fh]
    log = []
    for r in rows:
        if r.get("provenance") != "syzbot":
            continue
        ev = (r.get("chain") or [{}])[0].get("evidence") or {}
        for k in KINDS:
            p = ev.get(k)
            if p and p.get("application") != "strict":
                p["application"] = "strict"
                p["application_basis"] = "git apply (exact context)"
                log.append({"id": r["id"], "op": "application-stamped", "test": k})
    with open(rel / "dataset.jsonl", "w") as fh:
        fh.writelines(json.dumps(r) + "\n" for r in rows)
    with open(rel / "corrections_changelog.jsonl", "a") as fh:
        fh.writelines(json.dumps(e) + "\n" for e in log)
    print(f"{len(log)} kernel tests stamped")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
