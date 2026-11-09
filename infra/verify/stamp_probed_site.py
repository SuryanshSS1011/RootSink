#!/usr/bin/env python3
"""Record which site the PR-14 debugger probe ran on (release 1.0.8).

PR-14 (2026-10-21) asked whether the root site executed on the crashing path and stored the
answer as `chain[0].path_observed`. Releases 1.0.7 and 1.0.8 later moved some roots: an origin
with a tested hunk took its tested site, and an origin on a C++ standard-library frame took the
first project frame. Their `path_observed` still describes the site the probe ran on, so this step
adds that site, as the probe supply lists it, as `path_observed.probed_site` (file name, line,
function). A consumer compares it with `evidence.location` before reading the outcome as the
current root's. Changes no label, site or tier. Every stamp is logged. Idempotent.

Usage: stamp_probed_site.py [--release data/release] [--supply data/validation/pr14_supply.json]
"""

from __future__ import annotations

import argparse
import collections
import json
from pathlib import Path

RULE = "PR-14 probed site 2026-11-09 (release 1.0.8)"


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--release", default="data/release")
    ap.add_argument("--supply", default="data/validation/pr14_supply.json")
    args = ap.parse_args(argv)
    rel = Path(args.release)
    cases = json.loads(Path(args.supply).read_text())["cases"]
    by_id = {c["id"]: c for c in cases}
    by_arvo = collections.defaultdict(list)
    for c in cases:
        by_arvo[str(c.get("arvo"))].append(c)
    with open(rel / "dataset.jsonl") as fh:
        rows = [json.loads(line) for line in fh]
    log, stats = [], collections.Counter()
    for r in rows:
        root = (r.get("chain") or [{}])[0]
        po = root.get("path_observed")
        if not isinstance(po, dict):
            continue
        case = by_id.get(r["id"])
        if case is None:  # a record renumbered since the probe: match its OSS-Fuzz alias
            arvo = [a.split("-")[-1] for a in r.get("aliases") or [] if a.startswith("OSS-Fuzz-")]
            hits = [c for a in arvo for c in by_arvo.get(a, [])]
            case = hits[0] if len(hits) == 1 else None
        if case is None:
            stats["no probe case"] += 1
            continue
        site = {"file": case.get("rf"), "line": case.get("rl"), "function": case.get("rfn")}
        loc = (root.get("evidence") or {}).get("location") or {}
        name = (loc.get("file") or "").rsplit("/", 1)[-1]
        here = name == site["file"] and loc.get("line") == site["line"]
        stats["probed the current root" if here else "probed an earlier root site"] += 1
        if po.get("probed_site") != site:
            po["probed_site"] = site
            log.append({"id": r["id"], "op": "probed-site-stamped", "rule": RULE, "current": here})
    with open(rel / "dataset.jsonl", "w") as fh:
        fh.writelines(json.dumps(r) + "\n" for r in rows)
    with open(rel / "corrections_changelog.jsonl", "a") as fh:
        fh.writelines(json.dumps(e) + "\n" for e in log)
    print(dict(stats))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
