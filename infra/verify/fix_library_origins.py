#!/usr/bin/env python3
"""Move an origin site off a C++ standard-library frame to the first project frame (1.0.8).

An origin site is a frame of the report's origin stack: ASan's "freed by thread" stack for a use
after free, MSan's "Uninitialized value was created by" stack otherwise. In C++ code the stored
frame is often inside libc++ (`std::allocator::deallocate`, `operator delete` wrappers,
`unique_ptr`, `std::function`), which says nothing about the program. Per the rule-log entry of
2026-11-09 (release 1.0.8, OPEN_ISSUES #38), such an origin moves to the first frame of the same
stack that has a file and line and is neither sanitizer runtime nor standard-library code. That
frame is the project's own code or a library it builds from source:

  - for a root whose site is that origin (`site_kind: origin-site`), `evidence.location` moves;
  - for a root already moved to its tested site, `evidence.origin_site` moves;
  - the path is normalised as every witnessed path is (`chainforge.evidence.normalize_path`),
    and the record's `dataflow_evidence` note names the new site (independent check, 1.0.8);
  - the stage, CWE and evidence kind stay; a stack with no such frame is left as it is.

The new frame can be fuzz-harness code, which the Reproduced-tier contract then judges as for
any other root site. Runs after relabel_freed_msan.py in rebuild_derived.sh. Every move is
logged with its rule. Idempotent.

Usage: fix_library_origins.py [--release data/release] [--root .] [--dry-run]
"""

from __future__ import annotations

import argparse
import collections
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))
from chainforge.evidence import normalize_path  # noqa: E402
from chainforge.integrity import vul_log  # noqa: E402

RULE = "library origin frame 2026-11-09 (release 1.0.8)"
# C++ standard-library headers (libc++ and libstdc++), as compiled into OSS-Fuzz images.
LIBRARY = re.compile(r"/include/c\+\+/|^/v1/|/c\+\+/v1/|libcxx|libc\+\+|^/usr/include/")
# Sanitizer and libFuzzer runtime (compiler-rt), not LLVM itself: an LLVM project frame counts.
RUNTIME = re.compile(r"compiler-rt|sanitizer_common|libfuzzer", re.I)
FRAME = re.compile(r"^\s*#\d+ 0x[0-9a-f]+ in (.*?) (\S+?):(\d+)(?::\d+)?\s*$")
_HEADERS = (
    re.compile(r"^\s*freed by thread "),
    re.compile(r"^\s*Uninitiali[sz]ed value was created by "),
)


def origin_stack(log_text: str, cwe: int) -> list[str]:
    """The frame lines of the origin stack: ASan's free stack for CWE-416 if there is one,
    else the first MSan origin block."""
    lines = log_text.splitlines()
    order = _HEADERS if cwe == 416 else _HEADERS[1:]
    for header in order:
        for i, ln in enumerate(lines):
            if header.match(ln):
                out = []
                for nxt in lines[i + 1 :]:
                    if not re.match(r"^\s*#\d+ ", nxt):
                        break
                    out.append(nxt)
                return out
    return []


def project_frame(stack: list[str]) -> dict | None:
    for ln in stack:
        m = FRAME.match(ln)
        if not m:
            continue  # a frame with no file:line (a binary offset) cannot be a site
        fn, path, line = m.group(1), m.group(2), int(m.group(3))
        if RUNTIME.search(path) or LIBRARY.search(path):
            continue
        return {"file": normalize_path(path), "line": line, "function": fn}
    return None


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
        root = (r.get("chain") or [{}])[0]
        ev = root.get("evidence") or {}
        if ev.get("origin_site"):
            key = "origin_site"
        elif root.get("site_kind") == "origin-site":
            key = "location"
        else:
            continue
        old = ev.get(key) or {}
        if not LIBRARY.search(old.get("file") or ""):
            continue
        tier = r.get("label_confidence_tier")
        p = vul_log(r, Path(args.root))
        stack = origin_stack(p.read_text(errors="replace"), root.get("cwe_id")) if p else []
        new = project_frame(stack)
        if not new:
            stats[f"{'no project frame' if stack else 'no origin stack in the log'} {tier}"] += 1
            continue
        new["stage"] = old.get("stage")
        ev[key] = new
        note = r.get("dataflow_evidence")
        was, now = f"{old.get('file')}:{old.get('line')}", f"{new['file']}:{new['line']}"
        if isinstance(note, str) and was in note:
            r["dataflow_evidence"] = note.replace(was, now)
        stats[f"moved {tier} {key}"] += 1
        log.append(
            {
                "id": r["id"],
                "op": "library-origin-moved",
                "rule": RULE,
                "field": f"evidence.{key}",
                "site": f"{new['file']}:{new['line']} ({new['function']})",
                "previous": f"{old.get('file')}:{old.get('line')} ({old.get('function')})",
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
