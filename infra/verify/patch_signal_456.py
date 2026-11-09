#!/usr/bin/env python3
"""Detect a CWE-456 (Missing Initialization of a Variable) source signal in a fix commit.

Needed because CWE-456 cannot be found by dataflow. Our silver harness traces
source-call -> sink-call, but a *missing* initialization is an ABSENCE - there is no call
to trace. The fix commit is the observable evidence instead: if the patch that silences an
MSan use-of-uninitialized-value ADDS an initialization, the missing initialization was the
cause, and CWE-456 -> CWE-457 is attested rather than assumed.

Signals looked for in ADDED lines only (a removed memset is the opposite of this claim):
  memset/bzero/ZeroMemory      explicit zeroing
  calloc replacing malloc      zero-allocating instead of raw
  = 0 / = NULL / = '\\0'        scalar/pointer initialisation at declaration
  {0} / {} designated init     aggregate initialisation
  std::optional / value-init   C++ value initialisation

Reports a confidence, and deliberately distinguishes "no signal" from "could not fetch" -
an unfetchable patch is unknown, not negative.

Usage: patch_signal_456.py <cases.tsv> [--ids ids.txt] [--out out.json]
"""

import argparse
import json
import re
import sys
import time
import urllib.error
import urllib.request

# Added-line patterns that indicate an initialization being introduced.
SIGNALS = [
    (re.compile(r"^\+.*\b(memset|bzero|ZeroMemory|SecureZeroMemory)\s*\(", re.I), "memset", 3),
    (re.compile(r"^\+.*\bcalloc\s*\("), "calloc", 3),
    (re.compile(r"^\+.*=\s*(0|NULL|nullptr|'\\0'|\{\s*0?\s*\})\s*;"), "zero-init", 2),
    (re.compile(r"^\+.*\b\w+\s+\w+\s*\{\s*\}\s*;"), "value-init", 2),
    (re.compile(r"^\+.*\b(std::)?optional<"), "optional", 1),
    (re.compile(r"^\+.*\binit(iali[sz]e)?[A-Za-z_]*\s*\("), "init-call", 1),
]


def fetch_diff(url, timeout=45):
    """GitHub/GitLab commit pages serve a unified diff at .diff or .patch."""
    for suffix in (".diff", ".patch", ""):
        try:
            req = urllib.request.Request(url + suffix, headers={"User-Agent": "chainforge"})
            with urllib.request.urlopen(req, timeout=timeout) as r:
                body = r.read().decode("utf-8", "replace")
            if "\n+" in body or "diff --git" in body:
                return body
        except Exception:
            continue
    return None


def score(diff):
    hits = []
    total = 0
    for pat, name, weight in SIGNALS:
        n = sum(1 for line in diff.splitlines() if pat.match(line))
        if n:
            hits.append({"signal": name, "added_lines": n})
            total += weight * min(n, 3)
    return total, hits


def main(argv):
    ap = argparse.ArgumentParser()
    ap.add_argument("cases", help="tsv: id, sink, project, patch_url")
    ap.add_argument("--ids", help="restrict to these ids (one per line)")
    ap.add_argument("--out", default="scratchpad/patch456.json")
    args = ap.parse_args(argv)

    keep = None
    if args.ids:
        with open(args.ids) as fh:
            keep = {x.strip() for x in fh if x.strip()}

    rows = []
    with open(args.cases) as fh:
        for line in fh:
            p = line.rstrip("\n").split("\t")
            if len(p) >= 4 and (keep is None or p[0] in keep):
                rows.append(p)

    out = {}
    for i, (cid, _sink, proj, url) in enumerate(rows, 1):
        diff = fetch_diff(url)
        if diff is None:
            out[cid] = {"project": proj, "status": "unfetchable"}
        else:
            s, hits = score(diff)
            out[cid] = {
                "project": proj,
                "status": "ok",
                "score": s,
                "hits": hits,
                "attested": s >= 2,
            }
        if i % 10 == 0:
            print(f"  {i}/{len(rows)}", flush=True)
        time.sleep(0.4)

    with open(args.out, "w") as fh:
        json.dump(out, fh, indent=1)
    ok = [v for v in out.values() if v.get("status") == "ok"]
    att = [v for v in ok if v.get("attested")]
    print(f"\ncases={len(out)} fetched={len(ok)} unfetchable={len(out) - len(ok)}")
    print(
        f"CWE-456 signal attested: {len(att)}/{len(ok)} "
        f"({100 * len(att) // max(len(ok), 1)}% of fetched)"
    )
    agg = {}
    for v in att:
        for h in v["hits"]:
            agg[h["signal"]] = agg.get(h["signal"], 0) + 1
    print(f"  signals: {agg}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
