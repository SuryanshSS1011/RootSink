#!/usr/bin/env python3
"""Derive each bundle's expected witness from the vulnerable-side log the release ships.

The bundle verifier compares an observed crash against a declared one, so the declaration must
come from evidence anyone can re-read, not from an unversioned parse. Sources, per ARVO id: the
record's own vulnerable log_ref, else data/evidence/arvo/<id>/vul.sanitizer.txt.

Usage: facts_from_logs.py [data/release/dataset.jsonl] --out facts_by_id.json
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))
from chainforge.integrity import crash_facts  # noqa: E402

_SANITIZER = re.compile(r"(Address|Memory|UndefinedBehavior)Sanitizer")
_FRAME = re.compile(r"#\d+ 0x[0-9a-f]+ in .*? (/src/[^\s:]+:\d+)")
_RUNTIME = re.compile(r"compiler-rt|llvm|libfuzzer|sanitizer", re.I)
_SINK = {"READ": 125, "WRITE": 787}


def facts_for(text: str) -> dict:
    f = crash_facts(text)
    san = _SANITIZER.search(text)
    site = next(
        (m.group(1) for m in _FRAME.finditer(text) if not _RUNTIME.search(m.group(1))), None
    )
    return {
        "sanitizer": {"Address": "address", "Memory": "memory"}.get(
            san.group(1) if san else "", "undefined" if san else None
        ),
        "bug_class": f["class"],
        "direction": f["access"],
        "crash_site": site,
        "suggested_sink_cwe": 476 if f["null_deref"] else _SINK.get(f["access"] or ""),
    }


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("dataset", nargs="?", default="data/release/dataset.jsonl")
    ap.add_argument("--out", required=True)
    args = ap.parse_args(argv)
    out = {}
    with open(args.dataset) as fh:
        for line in fh:
            r = json.loads(line)
            aid = next((a[9:] for a in r.get("aliases") or [] if a.startswith("OSS-Fuzz-")), None)
            if not aid or aid in out:
                continue
            refs = [
                s.get("log_ref")
                for s in r.get("sanitizer_reports") or []
                if s.get("revision") == "vulnerable"
            ]
            refs.append(f"data/evidence/arvo/{aid}/vul.sanitizer.txt")
            p = next((Path(x) for x in refs if x and Path(x).is_file()), None)
            if p:
                out[aid] = facts_for(p.read_text(errors="replace"))
    with open(args.out, "w") as fh:
        json.dump(out, fh, indent=0, sort_keys=True)
    print(f"facts for {len(out)} ARVO ids -> {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
