#!/usr/bin/env python3
"""Attach PREREGISTRATION PR-13(b): a 1-minimal set of the proving hunk's added lines.

Input: the decrypted output of the runner's `minimize` workflow (one JSON line per case:
arvo_id, status, added, kept = 0-based indices of the added lines ddmin kept, tests). For each
supplied record with status `ok` whose proving hunk, re-split from its own `patch_diff`, has the
same number of added lines, the root's proof gets
`minimal_lines = {rule, added, kept, lines}`. It refines the site; no CWE, site or tier changes.

Other statuses are reported, not attached. `full_hunk_crashed` (the whole proving hunk did not
stop the crash when re-run) is a failed replication of the proof and is listed by record.
Writes data/validation/pr13_minimize_result.json. Idempotent.

Usage: attach_minimal_lines.py <min.jsonl> [--release data/release]
"""

from __future__ import annotations

import argparse
import collections
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent))
from locate_tested_sites import tested_hunk  # noqa: E402


def added_lines(hunk: str) -> list[str]:
    body = hunk.split("\n@@", 1)[-1].split("\n")[1:]
    return [x[1:] for x in body if x.startswith("+") and not x.startswith("+++")]


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("results")
    ap.add_argument("--release", default="data/release")
    ap.add_argument("--supply", default="data/validation/pr13_minimize.json")
    ap.add_argument("--out", default="data/validation/pr13_minimize_result.json")
    args = ap.parse_args(argv)
    res = {}
    for line in Path(args.results).read_text().splitlines():
        if line.strip():
            x = json.loads(line)
            res[x["arvo_id"]] = x
    supplied = set(json.loads(Path(args.supply).read_text())["records"])
    rel = Path(args.release)
    with open(rel / "dataset.jsonl") as fh:
        rows = [json.loads(line) for line in fh]
    stats, log, not_replicated = collections.Counter(), [], []
    sizes = []
    for r in rows:
        if r["id"] not in supplied:
            continue
        root = r["chain"][0]
        ev = root.get("evidence") or {}
        key = "causal_proof" if ev.get("causal_proof") else "guard_site_proof"
        proof = ev.get(key)
        aid = (proof or {}).get("arvo_id") or ""
        x = res.get(aid)
        if not proof or not x:
            stats["no result"] += 1
            continue
        if x["status"] != "ok":
            stats[x["status"]] += 1
            if x["status"] == "full_hunk_crashed":
                not_replicated.append(r["id"])
            continue
        hunk = tested_hunk(r.get("patch_diff"), proof)
        lines = added_lines(hunk) if hunk else []
        if len(lines) != x["added"]:
            stats["hunk differs from the runner's"] += 1
            continue
        ml = {
            "rule": "PR-13(b)",
            "added": x["added"],
            "kept": x["kept"],
            "lines": [lines[i] for i in x["kept"]],
        }
        sizes.append((x["added"], len(x["kept"])))
        stats["attached"] += 1
        if proof.get("minimal_lines") != ml:
            proof["minimal_lines"] = ml
            log.append(
                {"id": r["id"], "op": "minimal-lines", "kept": len(x["kept"]), "added": x["added"]}
            )
    with open(rel / "dataset.jsonl", "w") as fh:
        fh.writelines(json.dumps(r) + "\n" for r in rows)
    with open(rel / "corrections_changelog.jsonl", "a") as fh:
        fh.writelines(json.dumps(e) + "\n" for e in log)
    out = {
        "rule": "PREREGISTRATION PR-13(b)",
        "supplied": len(supplied),
        "outcomes": dict(stats),
        "added_lines_total": sum(a for a, _ in sizes),
        "kept_lines_total": sum(k for _, k in sizes),
        "single_line": sum(k == 1 for _, k in sizes),
        "nothing_removable": sum(a == k for a, k in sizes),
        "proof_not_replicated": not_replicated,
    }
    Path(args.out).write_text(json.dumps(out, indent=1) + "\n")
    print(json.dumps(out, indent=1))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
