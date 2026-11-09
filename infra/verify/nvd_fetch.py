#!/usr/bin/env python3
"""Fetch authoritative CVE->CWE assignments from NVD REST API 2.0 for every CVE in
cve_records.json. Cached + resumable. Rate-limited for a keyed client (50 req/30s)."""

import json
import os
import re
import sys
import time
import urllib.request

API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CACHE = "scratchpad/roar/nvd_cache.json"


def read_json(path):
    with open(path) as fh:
        return json.load(fh)


def write_json(path, obj):
    with open(path, "w") as fh:
        json.dump(obj, fh)


def api_key():
    with open(".env") as fh:
        for line in fh:
            if line.startswith("NVD_API_KEY"):
                return line.split("=", 1)[1].strip().strip('"').strip("'")
    return None


def fetch(cve, key):
    req = urllib.request.Request(f"{API}?cveId={cve}")
    if key:
        req.add_header("apiKey", key)
    with urllib.request.urlopen(req, timeout=45) as r:
        return json.load(r)


def cwes_of(data):
    prim, all_, status = set(), set(), ""
    for v in data.get("vulnerabilities", []):
        cve = v.get("cve", {})
        status = cve.get("vulnStatus", "")
        for w in cve.get("weaknesses", []):
            src = w.get("source", "")
            for d in w.get("description", []):
                m = re.match(r"CWE-(\d+)", d.get("value", ""))
                if m:
                    cid = int(m.group(1))
                    all_.add(cid)
                    if "nvd@nist.gov" in src:
                        prim.add(cid)
    return sorted(prim), sorted(all_), status


def main():
    key = api_key()
    cve2rec = read_json("scratchpad/roar/cve_records.json")
    cache = read_json(CACHE) if os.path.exists(CACHE) else {}
    cves = [c for c in cve2rec if c not in cache]
    print(f"key={'yes' if key else 'no'} | to fetch: {len(cves)} / {len(cve2rec)}", flush=True)
    delay = 0.75 if key else 6.5
    for i, cve in enumerate(cves, 1):
        try:
            prim, all_, status = cwes_of(fetch(cve, key))
            cache[cve] = {"primary": prim, "all": all_, "status": status}
        except Exception as e:  # noqa: BLE001 - record and continue
            cache[cve] = {"error": str(e)[:120]}
        if i % 25 == 0:
            write_json(CACHE, cache)
            print(f"  {i}/{len(cves)} ...", flush=True)
        time.sleep(delay)
    write_json(CACHE, cache)
    ok = sum(1 for v in cache.values() if "all" in v)
    err = sum(1 for v in cache.values() if "error" in v)
    print(f"done: cached={len(cache)} ok={ok} err={err}", flush=True)


if __name__ == "__main__":
    sys.exit(main())
