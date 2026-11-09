#!/usr/bin/env python3
"""Apply the fuzz check of hunk tests (PREREGISTRATION, PR-4/PR-13 amendment of 2026-10-22).

Input: the runner's `fuzzcheck` artifacts (`fuzzcheck.jsonl`: arvo_id, opaque key, status) and
data/validation/fuzzcheck_supply.json (key -> record id and test kind). Per test:

  strict      the test's hunk(s) apply with every context line matching, so the test patched
              the place it names. The test is kept and marked `application: "strict"`.
  fuzzy       they apply only with fuzz, so the test may have patched another place. The test
              is withdrawn from `causal_proof`, `guard_site_proof` or `tested_pair` into
              `evidence.fuzzed_test` until a strict re-test, and the record is re-tiered by
              `rebuild_derived.sh` from what remains.
  none, unresolved, diff_unfetchable, pull_failed, ...
              undetermined: nothing changes (R10); listed for a retry.

Writes data/validation/fuzzcheck_result.json. Idempotent.

Usage: apply_fuzz_check.py <fuzzcheck.jsonl>... [--release data/release]
"""

from __future__ import annotations

import argparse
import collections
import json
from pathlib import Path


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("results", nargs="+")
    ap.add_argument("--release", default="data/release")
    ap.add_argument("--supply", default="data/validation/fuzzcheck_supply.json")
    ap.add_argument("--out", default="data/validation/fuzzcheck_result.json")
    args = ap.parse_args(argv)
    status = {}
    for f in args.results:
        for line in Path(f).read_text().splitlines():
            if line.strip():
                x = json.loads(line)
                # A determined status (strict/fuzzy) is never overwritten by a later failure.
                if status.get(x["key"]) not in ("strict", "fuzzy"):
                    status[x["key"]] = x["status"]
    supply = json.loads(Path(args.supply).read_text())["cases"]
    tests = collections.defaultdict(list)
    for c in supply:
        tests[c["id"]].append(c)
    rel = Path(args.release)
    with open(rel / "dataset.jsonl") as fh:
        rows = [json.loads(line) for line in fh]
    counts: dict = collections.defaultdict(collections.Counter)
    log, retry = [], []
    for r in rows:
        for c in tests.get(r["id"], []):
            s = status.get(c["key"], "not run")
            counts[c["kind"]][f"{c['tier']} {s}"] += 1
            ev = r["chain"][0].setdefault("evidence", {})
            if s == "strict":
                if ev.get(c["kind"]) and ev[c["kind"]].get("application") != "strict":
                    ev[c["kind"]]["application"] = "strict"
            elif s == "fuzzy":
                if ev.get(c["kind"]):
                    ev.setdefault("fuzzed_test", {})[c["kind"]] = ev.pop(c["kind"])
                    log.append(
                        {
                            "id": r["id"],
                            "op": "hunk-test-withdrawn-fuzzed",
                            "test": c["kind"],
                            "rule": "PR-4/PR-13 fuzz check",
                        }
                    )
            else:
                retry.append({"id": r["id"], "kind": c["kind"], "status": s})
    with open(rel / "dataset.jsonl", "w") as fh:
        fh.writelines(json.dumps(r) + "\n" for r in rows)
    with open(rel / "corrections_changelog.jsonl", "a") as fh:
        fh.writelines(json.dumps(e) + "\n" for e in log)
    res = {
        "rule": "PREREGISTRATION PR-4/PR-13 fuzz check",
        "tests": len(supply),
        "by_kind": {k: dict(v) for k, v in counts.items()},
        "withdrawn_now": len(log),
        "undetermined": len(retry),
        "retry": retry,
    }
    Path(args.out).write_text(json.dumps(res, indent=1) + "\n")
    print(json.dumps({k: v for k, v in res.items() if k != "retry"}, indent=1))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
