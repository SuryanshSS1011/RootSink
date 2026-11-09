#!/usr/bin/env python3
"""Point each sanitizer report at its archived log, where the log exists in the repository.

Earlier assemblers wrote refs relative to wherever they ran (`fix.sanitizer.txt`,
`len3_repro/<id>/vul.sanitizer.txt`), so 548 GOLD refs resolved to nothing. A ref is rewritten
only when the file is actually present at the canonical path; nothing is assumed to exist.

Usage: relink_logs.py [--release data/release] [--root .]
"""

from __future__ import annotations

import argparse
import collections
import json
from pathlib import Path


def candidates(rec: dict, ref: str) -> list[str]:
    name = ref.rsplit("/", 1)[-1]
    ids = [a.split("-")[-1] for a in rec.get("aliases") or [] if a.startswith("OSS-Fuzz-")]
    ids += [p for p in ref.split("/")[:-1] if p.isdigit()]
    return [f"data/evidence/{d}/{i}/{name}" for i in ids for d in ("arvo", "arvo-len3")]


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--release", default="data/release")
    ap.add_argument("--root", default=".")
    args = ap.parse_args(argv)
    rel, root = Path(args.release), Path(args.root)
    with open(rel / "dataset.jsonl") as fh:
        rows = [json.loads(line) for line in fh]
    log, stats = [], collections.Counter()
    for r in rows:
        for s in r.get("sanitizer_reports") or []:
            ref = s.get("log_ref") or ""
            if not ref or ref.startswith(("http", "syzbot:")) or (root / ref).is_file():
                continue
            new = next((c for c in candidates(r, ref) if (root / c).is_file()), None)
            if new:
                log.append({"id": r["id"], "op": "relink-log", "from": ref, "to": new})
                s["log_ref"] = new
                stats["relinked"] += 1
            else:
                stats["still missing"] += 1
    with open(rel / "dataset.jsonl", "w") as fh:
        fh.writelines(json.dumps(r) + "\n" for r in rows)
    with open(rel / "corrections_changelog.jsonl", "a") as fh:
        fh.writelines(json.dumps(e) + "\n" for e in log)
    print(dict(stats))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
