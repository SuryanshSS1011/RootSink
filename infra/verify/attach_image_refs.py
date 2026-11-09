#!/usr/bin/env python3
"""Pin every ARVO-backed record's docker_image_ref to its bundle's digest (`tag@sha256:...`).

Only 616 records named an image at all, and by mutable tag. GOLD asserts "you can re-run this",
so the record itself must carry the exact environment, not leave it to be guessed from an alias.

Usage: attach_image_refs.py [--release data/release] [--bundles infra/repro/bundles]
"""

from __future__ import annotations

import argparse
import collections
import json
from pathlib import Path


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--release", default="data/release")
    ap.add_argument("--bundles", default="infra/repro/bundles")
    args = ap.parse_args(argv)
    path = Path(args.release) / "dataset.jsonl"
    with open(path) as fh:
        rows = [json.loads(line) for line in fh]
    stats = collections.Counter()
    for r in rows:
        b = Path(args.bundles) / f"{r['id']}.json"
        if not b.is_file():
            continue
        imgs = json.loads(b.read_text())["images"]
        ref = {
            side: f"{i['ref']}@{i['digest']}" if i.get("digest") else i["ref"]
            for side, i in (("vulnerable", imgs["vulnerable"]), ("patched", imgs["patched"]))
        }
        stats["pinned" if "@" in ref["vulnerable"] else "tag only"] += 1
        r["docker_image_ref"] = ref
    with open(path, "w") as fh:
        fh.writelines(json.dumps(r) + "\n" for r in rows)
    print(dict(stats))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
