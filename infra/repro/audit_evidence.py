#!/usr/bin/env python3
"""Audit that every record's cited execution evidence actually RESOLVES.

Written after 162 syzbot GOLD records were found citing
`kernel_gold/kernel/<extid>/console.log` files that no longer exist - 21% of GOLD
asserting a witness nothing could back. For a dataset whose headline claim is
execution-reproducibility, a reviewer dereferencing a `log_ref` and getting nothing is the
worst possible failure, so this must be a standing check rather than an accident we notice.

A `log_ref` falls into one of three kinds, each verified differently:

  path        e.g. "kernel_gold/kernel/<extid>/console.log" - must exist under --root
  bare-name   e.g. "vul.sanitizer.txt" - a filename with NO path. Unresolvable by
              construction: it does not say WHICH case's log it is. Reported as
              UNRESOLVABLE, because it is a provenance defect even when the file exists
              somewhere on the machine that produced it.
  external    e.g. "syzbot:<extid>:CrashReport" - a reference to an upstream artifact;
              recorded as EXTERNAL (checkable with --check-external, which fetches).

Usage:
  audit_evidence.py data/release/dataset.jsonl --root $CF_HOME
  audit_evidence.py data/release/dataset.jsonl --root . --fail-on-missing
"""

import argparse
import collections
import json
import os
import re
import sys

# http(s) URLs are EXTERNAL artifacts, not local paths - classifying them as
# paths made 485 dereferenceable syzbot report URLs count as "missing".
_EXTERNAL = re.compile(r"^(https?://|syzbot:|osv:|nvd:|cve:)", re.I)


def classify(log_ref: str) -> str:
    if not log_ref:
        return "empty"
    if _EXTERNAL.match(log_ref):
        return "external"
    if "/" in log_ref:
        return "path"
    return "bare-name"


def main(argv):
    ap = argparse.ArgumentParser()
    ap.add_argument("dataset")
    ap.add_argument("--root", default=".", help="root the relative log_ref paths are under")
    ap.add_argument(
        "--fail-on-missing",
        action="store_true",
        help="exit non-zero if any cited path does not resolve",
    )
    ap.add_argument("--by-tier", action="store_true", help="break results down by tier")
    args = ap.parse_args(argv)

    kinds = collections.Counter()
    missing = []
    per_tier = collections.defaultdict(collections.Counter)
    records_with_missing = set()

    with open(args.dataset) as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            rec = json.loads(line)
            tier = (rec.get("label_confidence_tier") or "").lower()
            for rep in rec.get("sanitizer_reports") or []:
                ref = str((rep or {}).get("log_ref") or "")
                kind = classify(ref)
                kinds[kind] += 1
                per_tier[tier][kind] += 1
                if kind == "path":
                    if os.path.exists(os.path.join(args.root, ref)):
                        kinds["path-resolved"] += 1
                        per_tier[tier]["path-resolved"] += 1
                    else:
                        kinds["path-MISSING"] += 1
                        per_tier[tier]["path-MISSING"] += 1
                        missing.append((rec.get("id"), tier, ref))
                        records_with_missing.add(rec.get("id"))

    total = sum(v for k, v in kinds.items() if k in ("path", "bare-name", "external", "empty"))
    print(f"log_ref entries: {total}")
    for k in ("path", "bare-name", "external", "empty"):
        if kinds[k]:
            print(f"  {kinds[k]:6d}  {k}")
    if kinds["path"]:
        print(f"    resolved: {kinds['path-resolved']}   MISSING: {kinds['path-MISSING']}")
    if kinds["bare-name"]:
        print(
            f"  NOTE: {kinds['bare-name']} bare-name refs are UNRESOLVABLE by construction "
            "(no path identifies which case's log they are)"
        )

    if args.by_tier:
        print("\nby tier:")
        for tier, c in sorted(per_tier.items()):
            bits = " ".join(
                f"{k}={c[k]}"
                for k in ("path-resolved", "path-MISSING", "bare-name", "external")
                if c[k]
            )
            print(f"  {tier or '?':8s} {bits}")

    if missing:
        print(f"\nRECORDS CITING MISSING EVIDENCE: {len(records_with_missing)}")
        for rid, tier, ref in missing[:10]:
            print(f"  {rid} [{tier}] -> {ref}")
        if len(missing) > 10:
            print(f"  ... and {len(missing) - 10} more")

    if args.fail_on_missing and (missing or kinds["bare-name"]):
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
