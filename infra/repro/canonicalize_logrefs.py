#!/usr/bin/env python3
"""Point every ARVO log_ref at the evidence actually shipped in the repo.

The audit found 1524 log_refs that were bare filenames ("vul.sanitizer.txt") carrying no
path - unresolvable by construction, because nothing says WHICH case's log they are. The
logs themselves are small (1607 cases, ~26MB), so they are now vendored under
data/evidence/arvo/<arvo_id>/ and the refs rewritten to match. A reviewer can then
dereference any cited witness straight from the repository.

Usage: canonicalize_logrefs.py <dataset.jsonl> --out <out.jsonl>
       [--evidence-root data/evidence/arvo]
"""

import argparse
import json
import os
import re
import sys


def arvo_id(rec):
    m = re.search(r"arvo:(\d+)-", json.dumps(rec.get("docker_image_ref") or {}))
    if m:
        return m.group(1)
    m = re.search(r"OSS-Fuzz-(\d+)", json.dumps(rec.get("aliases") or []))
    return m.group(1) if m else None


def main(argv):
    ap = argparse.ArgumentParser()
    ap.add_argument("dataset")
    ap.add_argument("--out", required=True)
    ap.add_argument("--evidence-root", default="data/evidence/arvo")
    a = ap.parse_args(argv)
    with open(a.dataset) as fh:
        rows = [json.loads(x) for x in fh if x.strip()]
    fixed = missing = skipped = 0
    for rec in rows:
        aid = arvo_id(rec)
        for rep in rec.get("sanitizer_reports") or []:
            ref = str(rep.get("log_ref") or "")
            if "/" in ref:  # already a path (or an external URL)
                skipped += 1
                continue
            if not aid or not re.fullmatch(r"(vul|fix)\.sanitizer\.txt", ref):
                skipped += 1
                continue
            cand = os.path.join(a.evidence_root, aid, ref)
            if os.path.exists(cand):
                rep["log_ref"] = cand
                fixed += 1
            else:
                missing += 1
    with open(a.out, "w") as fh:
        for rec in rows:
            fh.write(json.dumps(rec) + "\n")
    print(f"  rewritten to a shipped path: {fixed}")
    print(f"  bare ref with no shipped log: {missing}")
    print(f"  left alone (already a path/URL): {skipped}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
