#!/usr/bin/env python3
"""Give every record a canonical fix: `commit_range.fix_commits` and `commit_range.repo`.

`commit_range.fixed` keeps the value as each source gave it, in several shapes: a bare sha, a
commit URL, a repository URL run together with a sha (`...libssh.git07f7fa...`), a gitiles URL
(`.../+/<sha>%5E%21/`), `git://host/repo.git -> <sha>`, or several shas, one per line, where the
source names a range of fixing commits. This stamps, without changing `fixed`:

  fix_commits  every 40-hex sha in `fixed`, in order, deduplicated; when `fixed` holds none and
               the record is an ARVO case, ARVO's own `fix_commit` (data/cache/arvo.db)
  repo         the repository URL in `fixed`, else ARVO's `repo_addr`, else the kernel tree
               for syzbot records, else null

A record with no fix sha anywhere keeps `fix_commits: []`. GOLD criterion (d) requires one
(integrity.gold_violations, I3). Logged as `fix-commits-normalized` when a value changes.
Idempotent.

Usage: normalize_fix_commits.py [--release data/release] [--arvo-db data/cache/arvo.db]
"""

from __future__ import annotations

import argparse
import json
import re
import sqlite3
from pathlib import Path

SHA = re.compile(r"(?<![0-9a-f])[0-9a-f]{40}(?![0-9a-f])")
KERNEL = "https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git"


def repo_of(fixed: str) -> str | None:
    """The repository URL a `fixed` value names, if any."""
    m = re.search(r"((?:https?|git)://\S+?)(?:/commit/|/\+/|\s*->\s*|(?=[0-9a-f]{40}))", fixed)
    if not m:
        return None
    url = m.group(1).rstrip("/")
    return url.removesuffix("/-")


def arvo_id(r: dict) -> int | None:
    for a in r.get("aliases") or []:
        if a.startswith("OSS-Fuzz-") and a[9:].isdigit():
            return int(a[9:])
    return None


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--release", default="data/release")
    ap.add_argument("--arvo-db", default="data/cache/arvo.db")
    args = ap.parse_args(argv)
    db = sqlite3.connect(args.arvo_db) if Path(args.arvo_db).is_file() else None
    rel = Path(args.release)
    with open(rel / "dataset.jsonl") as fh:
        rows = [json.loads(line) for line in fh]
    log = []
    for r in rows:
        cr = r.setdefault("commit_range", {"introduced": None, "fixed": None})
        fixed = cr.get("fixed") or ""
        shas = list(dict.fromkeys(SHA.findall(fixed)))
        repo = repo_of(fixed)
        aid = arvo_id(r)
        row = None
        if db is not None and aid is not None:
            row = db.execute(
                "select fix_commit, repo_addr from arvo where localId=?", (aid,)
            ).fetchone()
        basis = "fixed"
        if not shas and row and row[0] and SHA.fullmatch(row[0].strip()):
            shas, basis = [row[0].strip()], "arvo fix_commit"
        if row is None and db is None:
            # The public release ships without the ARVO cache: keep what it already resolved.
            shas = shas or cr.get("fix_commits") or []
            repo = repo or cr.get("repo")
        if not repo and row and row[1]:
            repo = row[1].rstrip("/")
        if not repo and r.get("provenance") == "syzbot":
            repo = KERNEL
        if repo:
            repo = repo.removesuffix(".git") if repo.startswith("https://github.com/") else repo
        if cr.get("fix_commits") != shas or cr.get("repo") != repo:
            cr["fix_commits"], cr["repo"] = shas, repo
            log.append(
                {
                    "id": r["id"],
                    "op": "fix-commits-normalized",
                    "fix_commits": shas,
                    "repo": repo,
                    "basis": basis,
                }
            )
    with open(rel / "dataset.jsonl", "w") as fh:
        fh.writelines(json.dumps(r) + "\n" for r in rows)
    with open(rel / "corrections_changelog.jsonl", "a") as fh:
        fh.writelines(json.dumps(e) + "\n" for e in log)
    by_tier: dict[str, list[int]] = {}
    for r in rows:
        t = by_tier.setdefault(r["label_confidence_tier"], [0, 0])
        t[0 if r["commit_range"]["fix_commits"] else 1] += 1
    print(f"{len(log)} records stamped; [with fix sha, without] by tier: {by_tier}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
