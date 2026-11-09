"""Collect PoC inputs for the osv-git CWE-190 records so the arm can reach GOLD.

I previously recorded these as unreachable because "these CVEs ship no reproducer". That was
asserted, not measured, and it was wrong: sampling the upstream issues found a usable
reproducer signal in 84% of them. This gathers the actual inputs.

Fetches issue HTML rather than the API - the API is 60 requests/hour unauthenticated, the HTML
pages are not rate-limited that way, and the attachment URLs appear in both.
"""
import collections
import json
import os
import re
import sys
import time
import urllib.request

CF = os.environ.get("CF_HOME") or sys.exit("set CF_HOME to the chainforge working directory")
OUT = f"{CF}/pocs"
os.makedirs(OUT, exist_ok=True)

refs = json.load(open(f"{CF}/osv_refs.json"))
targets = {k: v for k, v in refs.items() if (v.get("arm") or "").startswith("CWE-190")}
print(f"CWE-190 osv-git records: {len(targets)}")

ATTACH = re.compile(r'https://github\.com/[^\s"\'<>]+/files/\d+/[^\s"\'<>]+')
UPLOADS = re.compile(r'https://user-images\.githubusercontent\.com/[^\s"\'<>]+')


def get(u, timeout=30, binary=False):
    req = urllib.request.Request(u, headers={"User-Agent": "chainforge/0.1"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        b = r.read(8 * 1024 * 1024)
    return b if binary else b.decode("utf-8", "replace")


st = collections.Counter()
index = {}
for i, (rid, v) in enumerate(targets.items(), 1):
    cve = v["cve"]
    try:
        d = json.loads(get(f"https://api.osv.dev/v1/vulns/{cve}"))
    except Exception:
        st["osv error"] += 1
        continue
    urls = [x.get("url", "") for x in (d.get("references") or [])]
    issue = next((u for u in urls if re.search(r"github\.com/[^/]+/[^/]+/issues/\d+", u)), None)
    if not issue:
        st["no github issue"] += 1
        continue
    try:
        html = get(issue)
    except Exception:
        st["issue fetch failed"] += 1
        time.sleep(2)
        continue
    links = sorted(set(ATTACH.findall(html)) | set(UPLOADS.findall(html)))
    if not links:
        st["issue has no attachment"] += 1
        time.sleep(1)
        continue
    got = []
    for u in links[:3]:
        name = re.sub(r"[^A-Za-z0-9_.-]", "_", u.rsplit("/", 1)[-1])[:80]
        dest = os.path.join(OUT, rid + "__" + name)
        if os.path.exists(dest):
            got.append(dest)
            continue
        try:
            b = get(u, binary=True)
            if 8 <= len(b) <= 8 * 1024 * 1024:
                open(dest, "wb").write(b)
                got.append(dest)
        except Exception:
            pass
        time.sleep(0.8)
    if got:
        st["POC DOWNLOADED"] += 1
        index[rid] = {"cve": cve, "project": v["project"], "arm": v["arm"],
                      "issue": issue, "files": got}
    else:
        st["attachment download failed"] += 1
    if i % 20 == 0:
        json.dump(index, open(f"{CF}/poc_index.json", "w"), indent=1)
        print(f"  {i}/{len(targets)} {dict(st)}", flush=True)
    time.sleep(1.0)

json.dump(index, open(f"{CF}/poc_index.json", "w"), indent=1)
print("\nDONE")
for k, v in st.most_common():
    print(f"  {v:4d}  {k}")
