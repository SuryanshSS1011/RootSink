"""Fetch a fix-commit date per record so a temporal split becomes possible.

The corpus carries no date field at all - 4 of 2262 records contain any date string - so the
only split we can offer is project-disjoint. That cannot answer the contamination question a
reviewer will ask: base models are pretrained on public GitHub including these very projects,
so a model may recall a fix rather than derive it. A temporal split (evaluate only on fixes
disclosed after the base model's cutoff) is the standard control, and it needs dates.

Uses the .patch endpoint rather than .diff: only .patch carries the "Date:" header. The
earlier osv-git run used .diff and recovered a date for 1 record of 158.
"""
import collections
import json
import os
import re
import sqlite3
import sys
import time
import urllib.error
import urllib.request

CF = os.environ.get("CF_HOME") or sys.exit("set CF_HOME to the chainforge working directory")
DATE = re.compile(r"^Date:\s*(.+)$", re.M)


def patch_url_variants(url):
    if not url:
        return []
    u = url.split("#")[0].rstrip("/")
    out = []
    if "/commit/" in u or "/-/commit/" in u or "/commits/" in u:
        out.append(u + ".patch")
    if "git.kernel.org" in u:
        sha = re.search(r"id=([0-9a-f]{8,40})", u)
        if sha:
            out.append("https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/"
                       f"linux.git/patch/?id={sha.group(1)}")
    return out


def get_date(url, timeout=30):
    for u in patch_url_variants(url):
        try:
            req = urllib.request.Request(u, headers={"User-Agent": "chainforge/0.1"})
            with urllib.request.urlopen(req, timeout=timeout) as r:
                body = r.read(8192).decode("utf-8", "replace")
            m = DATE.search(body)
            if m:
                return m.group(1).strip()
        except Exception:
            continue
    return None


def main():
    targets = json.load(open(f"{CF}/date_targets.json"))
    out = json.load(open(f"{CF}/dates.json")) if os.path.exists(f"{CF}/dates.json") else {}
    st = collections.Counter(got=len(out))
    for i, (rid, url) in enumerate(targets.items(), 1):
        if rid in out:
            continue
        d = get_date(url)
        if d:
            out[rid] = d
            st["got"] += 1
        else:
            st["no date"] += 1
        if i % 50 == 0:
            json.dump(out, open(f"{CF}/dates.json", "w"))
            print(f"  {i}/{len(targets)} {dict(st)}", flush=True)
        time.sleep(0.5)
    json.dump(out, open(f"{CF}/dates.json", "w"))
    print(f"DONE {dict(st)}")


if __name__ == "__main__":
    sys.exit(main())
