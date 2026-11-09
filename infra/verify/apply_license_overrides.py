#!/usr/bin/env python3
"""Give every record without a license its project's hand-checked one, offline.

Order: license_overrides.json (each entry cites the file it was read from), then a license an
already-licensed record of the same canonical project carries. Never overwrites a resolved
license and never guesses: a project with neither stays NOASSERTION and is listed. Logged as
`license-override` or `license-from-project`. Run by rebuild_derived.sh so records mined after
fetch_licenses.py last ran are covered.

Usage: apply_license_overrides.py [--release data/release]
"""

from __future__ import annotations

import argparse
import collections
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))
from chainforge.field_policy import canonical_project  # noqa: E402

UNSET = (None, "", "NOASSERTION")


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--release", default="data/release")
    args = ap.parse_args(argv)
    rel = Path(args.release)
    with open(rel / "dataset.jsonl") as fh:
        rows = [json.loads(line) for line in fh]
    ov = json.loads(Path(__file__).with_name("license_overrides.json").read_text())
    by_canon = {canonical_project(k): v["spdx"] for k, v in ov.items()}
    known: dict[str, collections.Counter] = collections.defaultdict(collections.Counter)
    for r in rows:
        if r.get("license") not in UNSET:
            known[canonical_project(r["project"])][r["license"]] += 1
    log, left = [], collections.Counter()
    for r in rows:
        if r.get("license") not in UNSET:
            continue
        canon = canonical_project(r["project"])
        lic, op = by_canon.get(canon), "license-override"
        # One unambiguous license for this codebase. Never for the `linux` catch-all of advisory
        # races (OPEN_ISSUES #21): its CVEs span many products, so a shared name is not a codebase.
        if not lic and canon != "linux" and len(known[canon]) == 1:
            lic, op = next(iter(known[canon])), "license-from-project"
        if lic:
            log.append({"id": r["id"], "op": op, "license": lic, "was": r.get("license")})
            r["license"] = lic
        else:
            r["license"] = "NOASSERTION"
            left[r["project"]] += 1
    with open(rel / "dataset.jsonl", "w") as fh:
        fh.writelines(json.dumps(r) + "\n" for r in rows)
    with open(rel / "corrections_changelog.jsonl", "a") as fh:
        fh.writelines(json.dumps(e) + "\n" for e in log)
    print(
        f"{len(log)} licensed; NOASSERTION remain for {sum(left.values())} records", file=sys.stderr
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
