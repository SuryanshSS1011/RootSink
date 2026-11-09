#!/usr/bin/env python3
"""Backfill per-link file:line from ARVO's archived crash_output.

Why this is sound rather than a shortcut: crash_output stores the sanitizer report ARVO
observed at the vulnerable revision. On the 177 cases we independently reproduced two-sided,
parsing it recovers OUR OWN answer on 175 (98.9%) at exact file AND line for both links. It is
therefore a validated source of sites for the records we never re-ran.

What it is NOT is a source of records or of tier. These sites are upstream-observed, so they
are stamped stage="crash (ARVO archived report)" and the record's dataflow_evidence says so.
A reader can tell a site we witnessed ourselves from one we inherited.

Conservative on which links get a site - only the two the sanitizer names directly:
  sink   the SUMMARY frame, the instruction that actually faulted
  416    the "freed by thread" frame, when CWE-416 is the chain's source: the free is what
         makes the pointer dangling, so it IS the source event
A CWE-20 (improper input validation) source has no witnessed site in a crash report. Those
links stay unlocalized, because a guessed line is worse than an absent one.

Usage: backfill_locations.py <dataset.jsonl> <backfill_locs.json> --out <out.jsonl>
"""

from __future__ import annotations

import argparse
import collections
import json
import re
import sys

NOTE = (
    " Per-link sites recovered from ARVO's archived crash_output (upstream-observed); that "
    "parse reproduces our own two-sided witnesses on 175/177 cases at exact file:line."
)


def arvo_id(rec):
    m = re.search(r"OSS-Fuzz-(\d+)", json.dumps(rec.get("aliases") or []))
    if m:
        return m.group(1)
    m = re.search(r"arvo:(\d+)-", json.dumps(rec.get("docker_image_ref") or {}))
    return m.group(1) if m else None


def links(rec):
    return [c for c in (rec.get("chain") or []) if isinstance(c, dict)]


def main(argv):
    ap = argparse.ArgumentParser()
    ap.add_argument("dataset")
    ap.add_argument("sites")
    ap.add_argument("--out", required=True)
    args = ap.parse_args(argv)

    with open(args.dataset) as fh:
        rows = [json.loads(x) for x in fh if x.strip()]
    with open(args.sites) as fh:
        sites = json.load(fh)

    st = collections.Counter()
    for rec in rows:
        chain = links(rec)
        if not chain:
            continue
        site = sites.get(arvo_id(rec) or "")
        if not site:
            continue
        touched = False

        sink = chain[-1]
        ev = sink.setdefault("evidence", {})
        if not (ev.get("location") or {}).get("file") and site.get("sink"):
            ev["location"] = dict(site["sink"], stage="crash (ARVO archived report)")
            st["sink localized"] += 1
            touched = True

        src = chain[0]
        sev = src.setdefault("evidence", {})
        if (
            src.get("cwe_id") == 416
            and not (sev.get("location") or {}).get("file")
            and site.get("freed")
        ):
            sev["location"] = dict(site["freed"], stage="freed (ARVO archived report)")
            st["CWE-416 source localized at the free site"] += 1
            touched = True

        if touched:
            st["records touched"] += 1
            if NOTE.strip() not in (rec.get("dataflow_evidence") or ""):
                rec["dataflow_evidence"] = (rec.get("dataflow_evidence") or "").rstrip() + NOTE

    with open(args.out, "w") as fh:
        for rec in rows:
            fh.write(json.dumps(rec) + "\n")
    for k, v in st.most_common():
        print(f"  {v:5d}  {k}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
