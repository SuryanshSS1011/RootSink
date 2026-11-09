#!/usr/bin/env python3
"""Apply PREREGISTRATION PR-17 to sinks: a CWE-119 sink from a UBSan index-out-of-bounds report
takes CWE-125 (read) or CWE-787 (write) from the access at the reported line and column, read in
the vulnerable image by the runner's `dirprobe` workflow (scripts/access_direction.py).

Input: dirprobe output lines {key, status, access} and data/validation/pr17_dir_supply.json (key
-> record). A decided access remaps the sink, keeping `cwe_class: 119` and `cwe_mapping` `read` or
`write`; an undecided or unreadable one keeps CWE-119 marked `class-level`. The chain string and
MITRE grounding are recomputed; rebuild_derived.sh re-tiers. Writes
data/validation/pr17_dir_result.json. Logged as `pr17-sink-map`. Idempotent.

Usage: apply_pr17_sinks.py <dirprobe.jsonl>... [--release data/release]
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
    ap.add_argument("results", nargs="+")
    ap.add_argument("--release", default="data/release")
    ap.add_argument("--supply", default="data/validation/pr17_dir_supply.json")
    ap.add_argument("--out", default="data/validation/pr17_dir_result.json")
    args = ap.parse_args(argv)
    got = {}
    for f in args.results:
        for line in Path(f).read_text().splitlines():
            if line.strip():
                d = json.loads(line)
                got[d["key"]] = d
    key_of = {c["id"]: c["key"] for c in json.loads(Path(args.supply).read_text())["cases"]}
    rel = Path(args.release)
    with open(rel / "dataset.jsonl") as fh:
        rows = [json.loads(line) for line in fh]
    log, stats = [], collections.Counter()
    for r in rows:
        if r["id"] not in key_of:
            # Other CWE-119 sinks (UBSan vptr reports, no direction to read) stay class-level.
            sink = (r.get("chain") or [{}])[-1]
            if sink.get("cwe_id") == 119 and sink.get("cwe_mapping") != "class-level":
                sink["cwe_class"], sink["cwe_mapping"] = 119, "class-level"
                stats[f"{r['label_confidence_tier']} class-level (no index report)"] += 1
            continue
        d = got.get(key_of[r["id"]], {"status": "no result"})
        acc = d.get("access") if d.get("status") == "ok" else None
        new = {"READ": 125, "WRITE": 787}.get(acc, 119)
        mapping = {125: "read", 787: "write"}.get(new, "class-level")
        sink = r["chain"][-1]
        stats[f"{r['label_confidence_tier']} {mapping}"] += 1
        if sink.get("cwe_class") == 119 and sink["cwe_id"] == new:
            continue
        old = r["chain_string"]
        sink["cwe_class"], sink["cwe_id"], sink["cwe_mapping"] = 119, new, mapping
        cwes = [link["cwe_id"] for link in r["chain"]]
        r["chain_string"] = "->".join(f"CWE-{c}" for c in cwes)
        r["mitre_chain"] = mitre(cwes)
        log.append({"id": r["id"], "op": "pr17-sink-map", "from": old, "to": r["chain_string"]})
    with open(rel / "dataset.jsonl", "w") as fh:
        fh.writelines(json.dumps(r) + "\n" for r in rows)
    with open(rel / "corrections_changelog.jsonl", "a") as fh:
        fh.writelines(json.dumps(e) + "\n" for e in log)
    Path(args.out).write_text(
        json.dumps({"rule": "PR-17 sinks", "counts": dict(stats)}, indent=1) + "\n"
    )
    print(dict(stats))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
