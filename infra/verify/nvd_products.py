#!/usr/bin/env python3
"""Fetch NVD's affected products (CPE vendor:product) for records whose `project` is unreliable.

The `nvd-race` arm filed every record under project "linux", including Firefox, libvips and
Android vendor-tree CVEs, so neither the project nor the license can be read off the record.
NVD's CPE configurations name what each CVE actually affects. Cached + resumable; uses the
NVD_API_KEY from .env when present.

Usage: nvd_products.py [--release data/release] [--cache data/cache/nvd_products.json]
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from nvd_fetch import api_key, fetch  # noqa: E402


def products(data: dict) -> list[str]:
    """Distinct vendor:product pairs from every vulnerable CPE match, in first-seen order."""
    seen: dict[str, None] = {}
    for v in data.get("vulnerabilities", []):
        for conf in v.get("cve", {}).get("configurations", []):
            for node in conf.get("nodes", []):
                for m in node.get("cpeMatch", []):
                    if not m.get("vulnerable"):
                        continue
                    parts = m.get("criteria", "").split(":")
                    if len(parts) > 4:
                        seen.setdefault(f"{parts[3]}:{parts[4]}", None)
    return list(seen)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--release", default="data/release")
    ap.add_argument("--cache", default="data/cache/nvd_products.json")
    args = ap.parse_args(argv)
    cache_p = Path(args.cache)
    cache = json.loads(cache_p.read_text()) if cache_p.is_file() else {}
    with open(Path(args.release) / "dataset.jsonl") as fh:
        rows = [json.loads(line) for line in fh]
    cves = sorted(
        {
            a
            for r in rows
            if r.get("provenance") == "nvd-race"
            for a in r["aliases"]
            if a.startswith("CVE-")
        }
        - set(cache)
    )
    key = api_key()
    print(f"key={'yes' if key else 'no'} | to fetch: {len(cves)}", flush=True)
    for i, cve in enumerate(cves, 1):
        try:
            cache[cve] = {"products": products(fetch(cve, key))}
        except Exception as e:  # noqa: BLE001 - record and continue
            cache[cve] = {"error": str(e)[:120]}
        if i % 25 == 0:
            cache_p.write_text(json.dumps(cache, indent=0, sort_keys=True))
            print(f"  {i}/{len(cves)}", flush=True)
        time.sleep(0.75 if key else 6.5)
    cache_p.parent.mkdir(parents=True, exist_ok=True)
    cache_p.write_text(json.dumps(cache, indent=0, sort_keys=True))
    print(
        f"done: {sum('products' in v for v in cache.values())} ok, "
        f"{sum('error' in v for v in cache.values())} errors",
        flush=True,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
