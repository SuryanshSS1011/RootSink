#!/usr/bin/env python3
"""External check of root sites against PatchBench's curated root-cause patches.

PatchBench (arXiv 2609.04075, MIT, github.com/ai-sec-lab/PatchBench) selects ARVO bugs whose
developer patch lies off the crash stack and hand-curates, per task, a reference patch that
fixes the root cause. Its tasks use legacy OSS-Fuzz ids, so they are matched to ARVO by commit
(PatchBench `base_commit` or `inverted_commit` equal to ARVO's `fix_commit`). For every GOLD
record on a matched image, the root site is compared with the reference patch: `function` when
a hunk of the patch is in the root's file within 15 lines of the root line or names the root's
function in its header, `file` when only the file agrees, `other file` otherwise. Reported per
root site kind. Only counts and PatchBench task ids are written; none of its data is copied.

Usage: compare_patchbench.py <PatchBench data/metadata.json> [--db data/cache/arvo.db]
"""

from __future__ import annotations

import argparse
import collections
import json
import re
import sqlite3
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))
from chainforge.evidence import bare_function, same_file  # noqa: E402

HUNK = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+\d+(?:,\d+)? @@ ?(.*)$")


def patch_sites(patch: str) -> list[tuple[str, int, int, str]]:
    out, f = [], None
    for ln in patch.splitlines():
        m = re.match(r"^\+\+\+ b/(\S+)", ln)
        if m:
            f = m.group(1)
            continue
        h = HUNK.match(ln)
        if h and f:
            out.append((f, int(h.group(1)), int(h.group(2) or 1), h.group(3)))
    return out


def verdict(loc: dict, sites: list) -> str:
    fn, line = bare_function(loc.get("function")), loc.get("line")
    infile = [s for s in sites if same_file(s[0], loc["file"])]
    near = [s for s in infile if isinstance(line, int) and s[1] - 15 <= line <= s[1] + s[2] + 15]
    named = [s for s in infile if fn and re.search(rf"\b{re.escape(fn)}\b", s[3])]
    return "function" if near or named else "file" if infile else "other file"


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("metadata")
    ap.add_argument("--db", default="data/cache/arvo.db")
    ap.add_argument("--release", default="data/release/dataset.jsonl")
    ap.add_argument("--out", default="data/validation/patchbench_overlap.json")
    args = ap.parse_args(argv)
    pb = json.loads(Path(args.metadata).read_text())
    fix = collections.defaultdict(list)
    for lid, fc in sqlite3.connect(args.db).execute("select localId, fix_commit from arvo"):
        for s in re.findall(r"[0-9a-f]{40}", fc or ""):
            fix[s].append(str(lid))
    by_img = collections.defaultdict(list)
    with open(args.release) as fh:
        for r in map(json.loads, fh):
            img = ((r.get("docker_image_ref") or {}).get("vulnerable") or "").split("@")[0]
            if img.startswith("n132/arvo:") and r["label_confidence_tier"] == "gold":
                by_img[img.split(":")[1].removesuffix("-vul")].append(r)
    counts, matched, tasks = collections.Counter(), 0, []
    for task, v in sorted(pb.items()):
        lids = fix.get(v.get("base_commit") or "", []) or fix.get(
            v.get("inverted_commit") or "", []
        )
        if not lids:
            continue
        matched += 1
        recs = [r for lid in lids for r in by_img.get(lid, [])]
        if recs:
            tasks.append(task)
        sites = patch_sites(v.get("patch") or "")
        for r in recs:
            loc = (r["chain"][0].get("evidence") or {}).get("location") or {}
            kind = r["chain"][0].get("site_kind") or "none"
            counts[f"{kind}: {verdict(loc, sites) if loc.get('file') else 'unplaced'}"] += 1
    out = {
        "rule": "root sites vs PatchBench curated root-cause patches",
        "patchbench_tasks": len(pb),
        "matched_to_arvo": matched,
        "tasks_with_gold": len(tasks),
        "gold_records": sum(counts.values()),
        "by_site_kind": dict(sorted(counts.items())),
        "task_ids": tasks,
    }
    Path(args.out).write_text(json.dumps(out, indent=1) + "\n")
    print(json.dumps({k: v for k, v in out.items() if k != "task_ids"}, indent=1))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
