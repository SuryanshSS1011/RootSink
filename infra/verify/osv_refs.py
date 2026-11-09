"""Query OSV for each osv-git CVE and classify what reproducer route each reference offers.

The question is whether these 159 can reach GOLD. GOLD needs a triggered sanitizer report, so
what matters is whether a PoV exists anywhere:
  oss-fuzz    an OSS-Fuzz issue id -> ARVO may already hold the case WITH a baked-in PoV,
              which would make it reproducible with the pipeline we already run
  bug-report  an upstream issue that commonly carries an attached crash file
  advisory    GHSA/NVD text only - no input
"""
import collections
import json
import os
import re
import sys
import time
import urllib.request

CF = os.environ.get("CF_HOME") or sys.exit("set CF_HOME to the chainforge working directory")
recs = json.load(open(f"{CF}/osvgit.json"))
out, st = {}, collections.Counter()
OSSFUZZ = re.compile(r"(oss-fuzz|clusterfuzz|bugs\.chromium\.org/p/oss-fuzz|issues\.oss-fuzz\.com)", re.I)
ISSUEID = re.compile(r"(?:id=|/issues/|detail\?id=)(\d{4,9})")

for i, r in enumerate(recs, 1):
    cve = r.get("cve")
    if not cve or not cve.startswith("CVE-"):
        st["no cve"] += 1
        continue
    try:
        req = urllib.request.Request(f"https://api.osv.dev/v1/vulns/{cve}",
                                     headers={"User-Agent": "chainforge/0.1"})
        with urllib.request.urlopen(req, timeout=30) as resp:
            d = json.load(resp)
    except Exception as e:
        st[f"osv fetch {type(e).__name__}"] += 1
        time.sleep(1)
        continue
    refs = [x.get("url", "") for x in (d.get("references") or [])]
    kinds = set()
    ossids = []
    for u in refs:
        if OSSFUZZ.search(u):
            kinds.add("oss-fuzz")
            m = ISSUEID.search(u)
            if m:
                ossids.append(m.group(1))
        elif re.search(r"/issues?/\d+|/pull/\d+|bugzilla|bugs\.", u, re.I):
            kinds.add("bug-report")
        elif re.search(r"(ghsa|nvd\.nist|security-advisories|cve\.org)", u, re.I):
            kinds.add("advisory")
    out[r["id"]] = {"cve": cve, "arm": r.get("arm"), "project": r.get("project"),
                    "kinds": sorted(kinds), "oss_fuzz_ids": ossids, "n_refs": len(refs)}
    st["queried"] += 1
    for k in kinds:
        st[k] += 1
    if ossids:
        st["with an OSS-Fuzz issue id"] += 1
    if i % 40 == 0:
        print(f"  {i}/{len(recs)} {dict(st)}", flush=True)
    time.sleep(0.4)

json.dump(out, open(f"{CF}/osv_refs.json", "w"), indent=1)
print("\nDONE")
for k, v in st.most_common():
    print(f"  {v:4d}  {k}")
n190 = [v for v in out.values() if (v.get("arm") or "").startswith("CWE-190")]
print(f"\n190-arm queried: {len(n190)}; with oss-fuzz ref: "
      f"{sum(1 for v in n190 if 'oss-fuzz' in v['kinds'])}; "
      f"with a bug report: {sum(1 for v in n190 if 'bug-report' in v['kinds'])}")
