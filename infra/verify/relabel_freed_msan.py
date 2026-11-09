#!/usr/bin/env python3
"""Relabel an MSan origin created by a heap deallocation as a use after free (release 1.0.7).

MSan poisons freed memory, so reading it is reported as a use of an uninitialized value whose
origin block says "created by a heap deallocation" and points at the free. The MSan arm labelled
every origin CWE-456 with a CWE-457 sink. Per the rule-log entry of 2026-11-09 such a record
becomes CWE-416 (use after free) with a CWE-125 sink, the read of freed memory (PR-2's label for
a use-after-free read):

  - the root keeps its site (the free), whose stage becomes `freed (MSan: heap deallocation)`
    so `site_kind` reads it as a use-after-free origin; a root moved to its tested site keeps
    that site and the stage goes on `evidence.origin_site`;
  - only CWE-456 -> CWE-457 records whose archived vulnerable report has that origin change.

Runs after move_origin_roots.py in rebuild_derived.sh. Every change is logged with its rule.
Idempotent.

Usage: relabel_freed_msan.py [--release data/release] [--dry-run]
"""

from __future__ import annotations

import argparse
import collections
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))
from chainforge.evidence import site_kind  # noqa: E402
from chainforge.integrity import FREED_ORIGIN, vul_log  # noqa: E402

RULE = "MSan heap-deallocation origin 2026-11-09 (release 1.0.7)"
STAGE = "freed (MSan: heap deallocation)"


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--release", default="data/release")
    ap.add_argument("--root", default=".", help="where the archived logs are")
    ap.add_argument("--dry-run", action="store_true", help="count only, write nothing")
    args = ap.parse_args(argv)
    rel = Path(args.release)
    with open(rel / "dataset.jsonl") as fh:
        rows = [json.loads(line) for line in fh]
    log, stats = [], collections.Counter()
    for r in rows:
        chain = r.get("chain") or []
        if len(chain) != 2 or chain[0].get("cwe_id") != 456 or chain[-1].get("cwe_id") != 457:
            continue
        p = vul_log(r, Path(args.root))
        if not (p and FREED_ORIGIN.search(p.read_text(errors="replace"))):
            continue
        root, sink = chain
        ev = root.setdefault("evidence", {})
        origin = ev.get("origin_site") or ev.get("location")
        if origin is not None:
            origin["stage"] = STAGE
        # The CWE now comes from the MSan origin block, whatever an earlier note said.
        ev["patch_hunk_ref"] = "MSan origin block: memory freed here (heap deallocation)"
        root["cwe_id"], sink["cwe_id"] = 416, 125
        r["chain_string"] = "CWE-416->CWE-125"
        prov = r.get("provenance") or ""
        root["site_kind"] = site_kind(root, prov)
        stats[f"relabelled {r.get('label_confidence_tier')} ({root['site_kind']})"] += 1
        log.append(
            {
                "id": r["id"],
                "op": "freed-msan-origin-relabel",
                "rule": RULE,
                "from": "CWE-456->CWE-457",
                "to": "CWE-416->CWE-125",
            }
        )
    if not args.dry_run:
        with open(rel / "dataset.jsonl", "w") as fh:
            fh.writelines(json.dumps(r) + "\n" for r in rows)
        with open(rel / "corrections_changelog.jsonl", "a") as fh:
            fh.writelines(json.dumps(e) + "\n" for e in log)
    print(dict(stats))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
