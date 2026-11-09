#!/usr/bin/env python3
"""Fill `fix_date` from the runner's `commitdates2` workflow (scripts/git_fix_date.sh).

The runner fetched each fix commit shallowly from its own git remote and read its author date,
the same field `fill_fix_dates.py` uses. A date is taken only for a record that has none and only
when the commit read is the one the record names (`commit_range.fixed`). Mercurial, Subversion
and unfetchable commits stay undated and are counted. Logged as `fix-date-filled` with source
`git author date`. Writes data/validation/fix_dates_result.json. Idempotent.

Usage: import_fix_dates.py <dates.jsonl>... [--release data/release]
"""

from __future__ import annotations

import argparse
import collections
import json
import re
from pathlib import Path


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("results", nargs="+")
    ap.add_argument("--release", default="data/release")
    ap.add_argument("--out", default="data/validation/fix_dates_result.json")
    args = ap.parse_args(argv)
    got = {}
    for f in args.results:
        for line in Path(f).read_text().splitlines():
            if line.strip():
                d = json.loads(line)
                got[d["arvo_id"]] = d
    rel = Path(args.release)
    with open(rel / "dataset.jsonl") as fh:
        rows = [json.loads(line) for line in fh]
    log, stats = [], collections.Counter()
    for r in rows:
        if r.get("fix_date"):
            continue
        img = ((r.get("docker_image_ref") or {}).get("vulnerable") or "").split("@")[0]
        if not img.startswith("n132/arvo:"):
            stats[f"{r['label_confidence_tier']} undated: not ARVO"] += 1
            continue
        d = got.get(img.split(":")[1].removesuffix("-vul"))
        named = re.findall(r"[0-9a-f]{40}", str((r.get("commit_range") or {}).get("fixed") or ""))
        if not d or d.get("status") != "ok":
            stats[
                f"{r['label_confidence_tier']} undated: {d.get('status') if d else 'not asked'}"
            ] += 1
            continue
        if named and d.get("sha") not in named:
            stats[f"{r['label_confidence_tier']} undated: commit differs from the record's"] += 1
            continue
        date = (d.get("author_date") or "")[:10]
        if not re.match(r"\d{4}-\d{2}-\d{2}$", date):
            stats[f"{r['label_confidence_tier']} undated: no date"] += 1
            continue
        r["fix_date"] = date
        stats[f"{r['label_confidence_tier']} filled"] += 1
        log.append(
            {"id": r["id"], "op": "fix-date-filled", "fix_date": date, "source": "git author date"}
        )
    with open(rel / "dataset.jsonl", "w") as fh:
        fh.writelines(json.dumps(r) + "\n" for r in rows)
    with open(rel / "corrections_changelog.jsonl", "a") as fh:
        fh.writelines(json.dumps(e) + "\n" for e in log)
    Path(args.out).write_text(json.dumps({"counts": dict(sorted(stats.items()))}, indent=1) + "\n")
    for k, v in sorted(stats.items()):
        print(f"{v:6d}  {k}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
