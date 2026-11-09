#!/usr/bin/env python3
"""Fill `fix_date` for records that lack one, from the fix commit itself.

fix_date is the fix commit's author date (the `Date:` header of `git format-patch`, the field
fetch_dates.py has always used). Sources, in order, and only for the commit the record names:
  1. a `Date:` header already in the record's patch_diff;
  2. the GitHub API for that commit, on the forge if it is GitHub, else on its official GitHub
     mirror (fetch_fix_diffs.MIRROR), keeping the date only if the API returns the same sha.
Nothing is inferred from a project, an advisory or an issue date. Records that stay undated are
counted. Logged as `fix-date-filled` with the source.

Usage: fill_fix_dates.py [--release data/release] [--db data/cache/arvo.db]
"""

from __future__ import annotations

import argparse
import collections
import email.utils
import json
import os
import re
import sqlite3
import sys
import time
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from fetch_fix_diffs import MIRROR  # noqa: E402

_DATE = re.compile(r"^Date:\s*(.+)$", re.M)
_SHA = re.compile(r"[0-9a-f]{40}(?![0-9a-f])")
_GH = re.compile(r"github\.com/([^/]+)/([^/#?]+)/commit/([0-9a-f]{40})")


def from_patch(diff: str) -> str | None:
    m = _DATE.search(diff or "")
    if not m:
        return None
    try:
        return email.utils.parsedate_to_datetime(m.group(1).strip()).date().isoformat()
    except (TypeError, ValueError):
        return None


def repo_for(url: str) -> str | None:
    """owner/repo on GitHub for a fix pointer: the forge itself, or its official mirror."""
    m = _GH.search(url or "")
    if m:
        return f"{m.group(1)}/{m.group(2).removesuffix('.git')}"
    host = re.match(r"\w+://([^/]+)(/[^?#]*)?", url or "")
    if not host:
        return None
    h, path = host.group(1), host.group(2) or ""
    for key, mirror in MIRROR.items():
        k_host, _, k_proj = key.partition(":")
        if h == k_host and (not k_proj or f"/{k_proj}" in path):
            return mirror
    return None


def from_github(repo: str, sha: str, cache: dict) -> str | None:
    key = f"{repo}@{sha}"
    if key in cache:
        return cache[key]
    req = urllib.request.Request(
        f"https://api.github.com/repos/{repo}/commits/{sha}",
        headers={"Authorization": f"Bearer {os.environ.get('GH_TOKEN', '')}"},
    )
    date = None
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            d = json.load(r)
        if d.get("sha") == sha:
            date = d["commit"]["author"]["date"][:10]
    except Exception:  # noqa: BLE001 - unreachable or unknown commit: stays undated
        date = None
    cache[key] = date
    time.sleep(0.1)
    return date


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--release", default="data/release")
    ap.add_argument("--db", default="data/cache/arvo.db")
    ap.add_argument("--cache", default="data/cache/fix_dates.json")
    ap.add_argument(
        "--dates-tsv",
        help="<owner/repo>\\t<sha>\\t<ISO date> from the runner's commitdates workflow (the GitHub "
        "API answered there for the same sha); used before calling the API from here",
    )
    args = ap.parse_args(argv)
    rel = Path(args.release)
    with open(rel / "dataset.jsonl") as fh:
        rows = [json.loads(line) for line in fh]
    db = sqlite3.connect(f"file:{args.db}?mode=ro", uri=True)
    cpath = Path(args.cache)
    cache = json.loads(cpath.read_text()) if cpath.is_file() else {}
    if args.dates_tsv:
        for line in Path(args.dates_tsv).read_text().splitlines():
            repo, sha, date = (line.split("\t") + ["", ""])[:3]
            if date:
                cache[f"{repo}@{sha}"] = date[:10]
    got, log = collections.Counter(), []
    for r in rows:
        if r.get("fix_date"):
            continue
        fixed = (r.get("commit_range") or {}).get("fixed") or ""
        date, src = from_patch(r.get("patch_diff")), "patch Date header"
        if not date:
            aid = next((a[9:] for a in r["aliases"] if a.startswith("OSS-Fuzz-")), None)
            url = fixed if "://" in fixed else ""
            if aid and not url:
                row = db.execute("select patch_url from arvo where localId=?", (aid,)).fetchone()
                url = row[0] if row else ""
            m = _SHA.search(fixed) or _SHA.search(url)
            repo = repo_for(url)
            if m and repo:
                date, src = from_github(repo, m.group(0), cache), f"GitHub API {repo} (runner)"
        if date:
            r["fix_date"] = date
            got[f"{r['label_confidence_tier']} filled"] += 1
            log.append({"id": r["id"], "op": "fix-date-filled", "fix_date": date, "source": src})
        else:
            got[f"{r['label_confidence_tier']} undated"] += 1
    cpath.write_text(json.dumps(cache, indent=0))
    with open(rel / "dataset.jsonl", "w") as fh:
        fh.writelines(json.dumps(r) + "\n" for r in rows)
    with open(rel / "corrections_changelog.jsonl", "a") as fh:
        fh.writelines(json.dumps(e) + "\n" for e in log)
    print(dict(got))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
