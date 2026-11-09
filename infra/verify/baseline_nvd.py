"""Baseline 1: INDEPENDENT real-world CWE co-occurrence.

Deliberately NOT drawn from our mined CVEs. The earlier comparison was self-contaminated:
234 of the 236 CWE-362 CVEs in it came from our own race-seeded arm, so it measured our
sampling. This queries NVD directly per catalog CWE and records what OTHER CWEs co-occur
on the same CVE, giving a prevalence signal independent of ChainForge."""
import json, os, sys, time, urllib.request, collections
API="https://services.nvd.nist.gov/rest/json/cves/2.0"
def key():
    with open(".env") as fh:
        for l in fh:
            if l.startswith("NVD_API_KEY"): return l.split("=",1)[1].strip().strip('"').strip("'")
    return None
K=key()
CATALOG=[20,119,125,190,416,476,787,362,129,843,252,415,457]
out=json.load(open("baseline_nvd.json")) if os.path.exists("baseline_nvd.json") else {}
for cwe in CATALOG:
    if str(cwe) in out: continue
    seen={}
    try:
        for start in (0,2000):
            u=f"{API}?cweId=CWE-{cwe}&resultsPerPage=2000&startIndex={start}"
            r=urllib.request.Request(u)
            if K: r.add_header("apiKey",K)
            with urllib.request.urlopen(r,timeout=60) as resp: d=json.load(resp)
            vs=d.get("vulnerabilities") or []
            for v in vs:
                c=v.get("cve",{})
                cid=c.get("id")
                ws=set()
                for w in c.get("weaknesses",[]):
                    for de in w.get("description",[]):
                        val=de.get("value","")
                        if val.startswith("CWE-") and val[4:].isdigit(): ws.add(int(val[4:]))
                if cid: seen[cid]=sorted(ws)
            if len(vs)<2000: break
            time.sleep(1)
    except Exception as e:
        out[str(cwe)]={"error":str(e)[:90]}; print(f"  CWE-{cwe}: ERROR {str(e)[:60]}",flush=True); time.sleep(3); continue
    out[str(cwe)]={"n":len(seen),"cves":seen}
    print(f"  CWE-{cwe}: {len(seen)} CVEs",flush=True)
    json.dump(out,open("baseline_nvd.json","w"))
    time.sleep(1)
json.dump(out,open("baseline_nvd.json","w"))
print("done")
