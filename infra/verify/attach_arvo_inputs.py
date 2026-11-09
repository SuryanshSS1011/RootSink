#!/usr/bin/env python3
"""Point each ARVO record's `pov_input` at its crashing input, shipped with the release (1.0.9).

Until 1.0.9 an OSS-Fuzz record's crashing input existed only inside ARVO's vulnerable image
(`/tmp/poc`), hosted in an unarchived Docker Hub account. `infra/repro/extract_arvo_inputs.py`
copies each input out of the image the record pins, by digest, into
`data/evidence/arvo/<arvo_id>/poc`, and lists each copy with its image digest and sha256 in
`data/evidence/arvo_inputs.jsonl`. This step sets `pov_input` to that file for every record whose
pinned vulnerable image matches a listed copy and whose file is present with the listed sha256.
It changes no label, site or tier. Every change is logged. Idempotent.

Usage: attach_arvo_inputs.py [--release data/release] [--root .]
"""

from __future__ import annotations

import argparse
import collections
import hashlib
import json
from pathlib import Path

RULE = "ARVO crashing inputs 2026-11-09 (release 1.0.9)"


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--release", default="data/release")
    ap.add_argument("--root", default=".")
    args = ap.parse_args(argv)
    root, rel = Path(args.root), Path(args.release)
    listing = root / "data/evidence/arvo_inputs.jsonl"
    copies = {}
    if listing.exists():
        for line in listing.read_text().splitlines():
            c = json.loads(line)
            copies[(c["arvo"], c["digest"])] = c
    with open(rel / "dataset.jsonl") as fh:
        rows = [json.loads(line) for line in fh]
    log, stats = [], collections.Counter()
    for r in rows:
        ref = (r.get("docker_image_ref") or {}).get("vulnerable") or ""
        if not ref.startswith("n132/arvo:") or "@" not in ref:
            continue
        tag, digest = ref.split("@", 1)
        arvo = tag.split(":", 1)[1].split("-", 1)[0]
        c = copies.get((arvo, digest))
        path = f"data/evidence/arvo/{arvo}/poc"
        if c is None:
            stats["no copy"] += 1
            continue
        f = root / path
        if not f.exists() or hashlib.sha256(f.read_bytes()).hexdigest() != c["sha256"]:
            stats["copy missing or altered"] += 1
            continue
        if r.get("pov_input") == path:
            stats["already attached"] += 1
            continue
        if r.get("pov_input"):
            stats["has another input; kept"] += 1
            continue
        r["pov_input"] = path
        stats[f"attached {r.get('label_confidence_tier')}"] += 1
        log.append(
            {
                "id": r["id"],
                "op": "input-attached",
                "rule": RULE,
                "path": path,
                "sha256": c["sha256"],
            }
        )
    with open(rel / "dataset.jsonl", "w") as fh:
        fh.writelines(json.dumps(r) + "\n" for r in rows)
    with open(rel / "corrections_changelog.jsonl", "a") as fh:
        fh.writelines(json.dumps(e) + "\n" for e in log)
    print(dict(stats))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
