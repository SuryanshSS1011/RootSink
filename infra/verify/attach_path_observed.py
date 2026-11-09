#!/usr/bin/env python3
"""Attach PREREGISTRATION PR-14: was the root site on the crashing path?

Input: the runner's `pathprobe` artifacts, each holding a `paths.jsonl` of one JSON line per
case with hit counts (or "unresolved") for the root line, the root function and the sink
function (the control). Outcome per case:

  inconclusive   the run did not crash, the control was unresolved or not hit, the root line was
                 unresolved, or the line was not hit and the function could not be resolved;
  line-hit       the root line executed;
  function-hit   the root function was entered but the line did not execute;
  not-hit        neither executed (or the line did not and no function is recorded).

Stored as `chain[0].path_observed` for each supplied record; changes no label or tier. Also
reports how often the function the debug info gives for the root line matches the recorded one.
Writes data/validation/pr14_result.json. Idempotent.

Usage: attach_path_observed.py <paths.jsonl>... [--release data/release]
"""

from __future__ import annotations

import argparse
import collections
import json
from pathlib import Path


def outcome(p: dict) -> str:
    if p.get("status") != "ok" or not p.get("crashed"):
        return "inconclusive"
    sink, line, func = p.get("sink"), p.get("line"), p.get("func")
    if not isinstance(sink, int) or sink == 0 or not isinstance(line, int):
        return "inconclusive"
    if line > 0:
        return "line-hit"
    if isinstance(func, int):
        return "function-hit" if func > 0 else "not-hit"
    return "not-hit" if func is None else "inconclusive"


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("paths", nargs="+")
    ap.add_argument("--release", default="data/release")
    ap.add_argument("--supply", default="data/validation/pr14_supply.json")
    ap.add_argument("--out", default="data/validation/pr14_result.json")
    args = ap.parse_args(argv)
    probes = {}
    for f in args.paths:
        for line in Path(f).read_text().splitlines():
            if line.strip():
                p = json.loads(line)
                probes[p["arvo_id"]] = p
    supply = json.loads(Path(args.supply).read_text())["cases"]
    case = {c["id"]: c for c in supply}
    rel = Path(args.release)
    with open(rel / "dataset.jsonl") as fh:
        rows = [json.loads(line) for line in fh]
    by_kind: dict = collections.defaultdict(collections.Counter)
    match = collections.Counter()
    log = []
    for r in rows:
        c = case.get(r["id"])
        p = probes.get(c["arvo"]) if c else None
        if not p or not r.get("chain"):
            continue
        root = r["chain"][0]
        obs = {
            "rule": "PR-14",
            "outcome": outcome(p),
            "line_hits": p.get("line"),
            "function_hits": p.get("func"),
            "control_hits": p.get("sink"),
        }
        if "line_fn_matches_label" in p:
            obs["line_function_matches_label"] = p["line_fn_matches_label"]
            match[p["line_fn_matches_label"]] += 1
        by_kind[root.get("site_kind")][obs["outcome"]] += 1
        if root.get("path_observed") != obs:
            root["path_observed"] = obs
            log.append({"id": r["id"], "op": "path-observed", "outcome": obs["outcome"]})
    with open(rel / "dataset.jsonl", "w") as fh:
        fh.writelines(json.dumps(r) + "\n" for r in rows)
    with open(rel / "corrections_changelog.jsonl", "a") as fh:
        fh.writelines(json.dumps(e) + "\n" for e in log)
    res = {
        "rule": "PREREGISTRATION PR-14",
        "supplied": len(supply),
        "probed": len(probes),
        "by_site_kind": {str(k): dict(v) for k, v in by_kind.items()},
        "line_function_matches_label": {str(k): v for k, v in match.items()},
    }
    Path(args.out).write_text(json.dumps(res, indent=1) + "\n")
    print(json.dumps(res))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
