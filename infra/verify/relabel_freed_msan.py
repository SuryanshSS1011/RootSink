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
  - only CWE-456 -> CWE-457 records change, and only when the first MemorySanitizer report in
    the archived vulnerable log is a use of an uninitialized value with that origin; a root whose
    CWE a single-hunk test named (causally-proven) is left to the guard rule;
  - the record's `dataflow_evidence` note is updated to the new labels;
  - a record relabelled before that update (release 1.0.7) gets the same note and hunk
    reference, logged as `freed-msan-note-rewritten` (release 1.0.8).

Runs after move_origin_roots.py in rebuild_derived.sh. Every change is logged with its rule.
Idempotent.

Usage: relabel_freed_msan.py [--release data/release] [--dry-run]
"""

from __future__ import annotations

import argparse
import collections
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))
from chainforge.evidence import site_kind  # noqa: E402
from chainforge.integrity import freed_msan_origin, vul_log  # noqa: E402

RULE = "MSan heap-deallocation origin 2026-11-09 (release 1.0.7)"
STAGE = "freed (MSan: heap deallocation)"
HUNK_REF = "MSan origin block: memory freed at the origin site (heap deallocation)"
_NOTE_PAIRED = re.compile(
    r"CWE-456 at (\S+) is the origin block's creation site; "
    r"CWE-457 at (\S+) is the SUMMARY use site"
)


def rewrite_note(note):
    """The record's dataflow note with the CWE-456/CWE-457 wording replaced by the new labels."""
    if not isinstance(note, str):
        return note
    return _NOTE_PAIRED.sub(
        r"CWE-416 at \1 is the origin block's free (a heap deallocation); CWE-125 at \2 "
        r"is the SUMMARY use of the freed memory",
        note.replace(
            "CWE-456 at the origin block's creation site, CWE-457 at the SUMMARY use site",
            "CWE-416 at the origin block's free (a heap deallocation), CWE-125 at the SUMMARY use",
        ),
    )


def _relabelled(chain: list) -> bool:
    """A CWE-416 -> CWE-125 record this rule relabelled (its origin carries the rule's stage)."""
    if len(chain) != 2 or chain[0].get("cwe_id") != 416 or chain[-1].get("cwe_id") != 125:
        return False
    ev = chain[0].get("evidence") or {}
    return (ev.get("origin_site") or ev.get("location") or {}).get("stage") == STAGE


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
        if _relabelled(chain):
            # Relabelled in 1.0.7 before the note was updated: bring note and reference up to date.
            ev = chain[0]["evidence"]
            if ev.get("causal_proof") or chain[0].get("evidence_kind") == "causally-proven":
                continue
            fields = []
            if ev.get("patch_hunk_ref") != HUNK_REF:
                ev["patch_hunk_ref"] = HUNK_REF
                fields.append("chain[0].evidence.patch_hunk_ref")
            note = rewrite_note(r.get("dataflow_evidence"))
            if note != r.get("dataflow_evidence"):
                r["dataflow_evidence"] = note
                fields.append("dataflow_evidence")
            if fields:
                stats[f"note rewritten {r.get('label_confidence_tier')}"] += 1
                op = "freed-msan-note-rewritten"
                log.append({"id": r["id"], "op": op, "rule": RULE, "fields": fields})
            continue
        if len(chain) != 2 or chain[0].get("cwe_id") != 456 or chain[-1].get("cwe_id") != 457:
            continue
        root, sink = chain
        ev = root.setdefault("evidence", {})
        if ev.get("causal_proof") or root.get("evidence_kind") == "causally-proven":
            continue  # a hunk-named CWE is the guard rule's; this rule does not override it
        p = vul_log(r, Path(args.root))
        if not (p and freed_msan_origin(p.read_text(errors="replace"))):
            continue
        origin = ev.get("origin_site") or ev.get("location")
        if origin is not None:
            origin["stage"] = STAGE
        # The CWE now comes from the MSan origin block, whatever an earlier note said.
        ev["patch_hunk_ref"] = HUNK_REF
        if "dataflow_evidence" in r:
            r["dataflow_evidence"] = rewrite_note(r["dataflow_evidence"])
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
