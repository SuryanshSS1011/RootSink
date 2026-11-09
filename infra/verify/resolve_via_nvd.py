"""Second pass for candidates OSV does not carry.

OSV 404'd on 168 of 320 CVEs - it indexes open-source PACKAGE ecosystems, and many NVD CVEs
sit outside those. NVD itself lists references for every CVE it publishes, including the
upstream commit, so the same resolution is available from the source we already have a key
for. Skipping this would discard half the mining pool for no reason but the choice of API.
"""
import json, os, re, sys, time, urllib.request, urllib.error, collections

API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
GH = re.compile(r"github\.com/([^/\s]+/[^/\s#?]+)")
SHA = re.compile(r"/commit/([0-9a-f]{7,40})")


def key():
    for line in open(".env"):
        if line.startswith("NVD_API_KEY"):
            return line.split("=", 1)[1].strip().strip('"').strip("'")
    return None


K = key()
targets = json.load(open("/tmp/nvd_pass_targets.json"))
out = json.load(open("/tmp/new_resolved_nvd.json")) if os.path.exists("/tmp/new_resolved_nvd.json") else {}
st = collections.Counter(resolved=len(out))
for i, (cve, arms) in enumerate(targets.items(), 1):
    if cve in out:
        continue
    try:
        req = urllib.request.Request(f"{API}?cveId={cve}", headers={"User-Agent": "chainforge/0.1"})
        if K:
            req.add_header("apiKey", K)
        with urllib.request.urlopen(req, timeout=40) as r:
            d = json.load(r)
    except Exception as e:
        st[type(e).__name__] += 1
        time.sleep(2)
        continue
    v = d.get("vulnerabilities") or []
    if not v:
        st["not in nvd"] += 1
        continue
    cve_obj = v[0].get("cve", {})
    refs = [x.get("url", "") for x in (cve_obj.get("references") or [])]
    fix = proj = None
    for u in refs:
        m, g = SHA.search(u), GH.search(u)
        if m and g:
            fix, proj = m.group(1), g.group(1).replace(".git", "")
            break
    if not fix:
        st["no commit in refs"] += 1
    else:
        out[cve] = {"cve": cve, "arms": arms, "project": proj, "fix": fix,
                    "published": (cve_obj.get("published") or "")[:10], "refs": refs[:8]}
        st["RESOLVED"] += 1
    if i % 40 == 0:
        json.dump(out, open("/tmp/new_resolved_nvd.json", "w"), indent=1)
        print(f"  {i}/{len(targets)} {dict(st)}", flush=True)
    time.sleep(0.7)
json.dump(out, open("/tmp/new_resolved_nvd.json", "w"), indent=1)
print(f"DONE {dict(st)}")
print("by arm:", collections.Counter(a for v in out.values() for a in v["arms"]).most_common())
