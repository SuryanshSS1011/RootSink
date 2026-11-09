"""Fetch NVD publication dates for records that carry a CVE but no fix commit.

Kept in a SEPARATE field from fix_date. They are different events: a fix-commit date is when
the patch landed, a disclosure date is when the CVE was published, and they can be months
apart. For a contamination control either can serve - what matters is that a consumer knows
which one they are filtering on, so the two are not blended into one column.
"""
import json, os, time, urllib.request, collections

API = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def key():
    for line in open(".env"):
        if line.startswith("NVD_API_KEY"):
            return line.split("=", 1)[1].strip().strip('"').strip("'")
    return None


K = key()
cves = json.load(open("/tmp/undated_cves.json"))
out = {}
st = collections.Counter()
for i, (rid, cve) in enumerate(cves.items(), 1):
    try:
        req = urllib.request.Request(f"{API}?cveId={cve}", headers={"User-Agent": "chainforge/0.1"})
        if K:
            req.add_header("apiKey", K)
        with urllib.request.urlopen(req, timeout=40) as r:
            d = json.load(r)
        v = (d.get("vulnerabilities") or [])
        if v:
            pub = v[0].get("cve", {}).get("published")
            if pub:
                out[rid] = pub[:10]
                st["got"] += 1
            else:
                st["no published field"] += 1
        else:
            st["cve not found"] += 1
    except Exception as e:
        st[type(e).__name__] += 1
        time.sleep(2)
    if i % 40 == 0:
        print(f"  {i}/{len(cves)} {dict(st)}", flush=True)
    time.sleep(0.7)
json.dump(out, open("/tmp/nvd_dates.json", "w"))
print(f"DONE {dict(st)}")
