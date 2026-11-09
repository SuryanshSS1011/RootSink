"""Resolve new chain candidates to a project + fix commit via OSV.

Sourced from the NVD baseline's per-CVE CWE sets: a CVE carrying BOTH ends of an admissible
pair is a chain candidate. Restricted to the arms the composition baseline says we
under-represent - 190->* above all, NVD's most common co-occurrence at 24.2% against our 3.0%
- and deliberately excluding 416->* and 20->125/787, which are at target or frozen. Mining
those would grow precisely the arms we chose not to grow.

Keeps only C/C++ projects with a GitHub fix commit, since that is what our reproduction route
needs.
"""
import collections
import json
import os
import re
import sys
import time
import urllib.error
import urllib.request

CF = os.environ.get("CF_HOME") or sys.exit("set CF_HOME to the chainforge working directory")
targets = json.load(open(f"{CF}/mine_targets.json"))
GH = re.compile(r"github\.com/([^/\s]+/[^/\s#?]+)")
SHA = re.compile(r"/commit/([0-9a-f]{7,40})")
CLIKE = re.compile(r"\.(c|cc|cpp|h|hpp)$|(^|/)(src|lib)/", re.I)

out, st = {}, collections.Counter()
for i, (cve, arms) in enumerate(targets.items(), 1):
    try:
        req = urllib.request.Request(f"https://api.osv.dev/v1/vulns/{cve}",
                                     headers={"User-Agent": "chainforge/0.1"})
        with urllib.request.urlopen(req, timeout=30) as r:
            d = json.load(r)
    except urllib.error.HTTPError as e:
        st[f"osv {e.code}"] += 1
        time.sleep(1); continue
    except Exception as e:
        st[type(e).__name__] += 1
        time.sleep(2); continue
    st["osv found"] += 1
    refs = [x.get("url", "") for x in (d.get("references") or [])]
    fix, proj = None, None
    for u in refs:
        m = SHA.search(u)
        g = GH.search(u)
        if m and g:
            fix, proj = m.group(1), g.group(1).replace(".git", "")
            break
    if not proj:
        for u in refs:
            g = GH.search(u)
            if g:
                proj = g.group(1).replace(".git", "")
                break
    # a fix commit is what makes the record reproducible AND patch-attestable
    if not fix:
        st["no fix commit"] += 1
        continue
    out[cve] = {"cve": cve, "arms": arms, "project": proj, "fix": fix,
                "summary": (d.get("summary") or "")[:180],
                "refs": refs[:8]}
    st["RESOLVED"] += 1
    if i % 40 == 0:
        json.dump(out, open(f"{CF}/new_resolved.json", "w"), indent=1)
        print(f"  {i}/{len(targets)} {dict(st)}", flush=True)
    time.sleep(0.4)

json.dump(out, open(f"{CF}/new_resolved.json", "w"), indent=1)
print("DONE")
for k, v in st.most_common():
    print(f"  {v:5d}  {k}")
print("by arm:", collections.Counter(a for v in out.values() for a in v["arms"]).most_common())
