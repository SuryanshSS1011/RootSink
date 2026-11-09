"""Last pass on dates: build commit URLs from arvo.db's repo_addr + fix_commit.

The first pass keyed on patch_url and left 234 records undated. arvo.db also stores the repo
address and the fix commit for every one of them, which reconstructs a commit URL directly -
a column that was there the whole time and simply was not used.
"""
import collections
import json
import os
import re
import sys
import time
import urllib.request

CF = os.environ.get("CF_HOME") or sys.exit("set CF_HOME to the chainforge working directory")
DATE = re.compile(r"^Date:\s*(.+)$", re.M)
COMMITTER = re.compile(r'"committer".*?"date"\s*:\s*"([0-9T:\-]+Z?)"', re.S)


def norm(repo):
    r = (repo or "").strip().rstrip("/")
    r = re.sub(r"^git@([^:]+):", r"https://\1/", r)
    r = re.sub(r"^git://", "https://", r)
    r = re.sub(r"\.git$", "", r)
    return r


def urls_for(repo, sha):
    r = norm(repo)
    if not r or not sha:
        return []
    out = []
    if "github.com" in r:
        owner_repo = r.split("github.com/", 1)[-1]
        out.append(("api", f"https://api.github.com/repos/{owner_repo}/commits/{sha}"))
        out.append(("patch", f"{r}/commit/{sha}.patch"))
    elif "googlesource.com" in r:
        out.append(("gitiles", f"{r}/+/{sha}?format=JSON"))
    elif "gitlab" in r or "invent.kde" in r or "videolan" in r or "freedesktop" in r:
        out.append(("patch", f"{r}/-/commit/{sha}.patch"))
        out.append(("patch", f"{r}/commit/{sha}.patch"))
    else:
        out.append(("patch", f"{r}/commit/{sha}.patch"))
    return out


def get(u, timeout=25):
    req = urllib.request.Request(u, headers={"User-Agent": "chainforge/0.1"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read(65536).decode("utf-8", "replace")


meta = json.load(open(f"{CF}/undated_arvo_meta.json"))
out, st = {}, collections.Counter()
for i, (rid, m) in enumerate(meta.items(), 1):
    got = None
    for kind, u in urls_for(m.get("repo"), m.get("fix_commit")):
        try:
            body = get(u)
        except Exception:
            continue
        if kind == "api" or kind == "gitiles":
            mm = COMMITTER.search(body)
            if mm:
                got = mm.group(1)[:10]
                break
        else:
            mm = DATE.search(body)
            if mm:
                got = mm.group(1).strip()
                break
        time.sleep(0.4)
    if got:
        out[rid] = got
        st["got"] += 1
    else:
        st["no date"] += 1
    if i % 40 == 0:
        json.dump(out, open(f"{CF}/arvo_dates.json", "w"))
        print(f"  {i}/{len(meta)} {dict(st)}", flush=True)
    time.sleep(0.6)
json.dump(out, open(f"{CF}/arvo_dates.json", "w"))
print(f"DONE {dict(st)}")
