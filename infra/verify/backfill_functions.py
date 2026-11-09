#!/usr/bin/env python3
"""Fill a located link's missing function, and attribute an unattributed sink, from our own log.

Sink sites recovered from ARVO's archived crash output carry file and line but no function, so
locality could not tell "same function" from "same file". The function is in the stack frame
at that file:line in the vulnerable-side log we ship; take it from there and nowhere else. A link
is filled only on an exact file (normalised, suffix match) and line match.

Usage: backfill_functions.py [--release data/release]
"""

from __future__ import annotations

import argparse
import collections
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))
from chainforge.evidence import same_file  # noqa: E402

_RUNTIME = re.compile(r"compiler-rt|llvm-project|libfuzzer|sanitizer_common|/asan/|/msan/|/ubsan/")
_FRAME = re.compile(r"#\d+ 0x[0-9a-f]+ in (.*?) (\S+?):(\d+)(?::\d+)?\s*$", re.M)


def frames(log_text: str) -> list[tuple[str, str, int]]:
    return [(m.group(1), m.group(2), int(m.group(3))) for m in _FRAME.finditer(log_text)]


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--release", default="data/release")
    args = ap.parse_args(argv)
    rel = Path(args.release)
    with open(rel / "dataset.jsonl") as fh:
        rows = [json.loads(line) for line in fh]
    log, stats = [], collections.Counter()
    for r in rows:
        logs = [
            Path(s["log_ref"])
            for s in r.get("sanitizer_reports") or []
            if s.get("revision") == "vulnerable"
            and s.get("witnesses") != "intermediate"  # a UBSan rebuild is not the sink crash
            and Path(s.get("log_ref") or "").is_file()
        ]
        stack = [f for p in logs for f in frames(p.read_text(errors="replace"))]
        for link in r.get("chain") or []:
            loc = (link.get("evidence") or {}).get("location") or {}
            if not loc.get("file") or loc.get("function") or loc.get("line") is None:
                continue
            fn = next(
                (fn for fn, f, ln in stack if ln == loc["line"] and same_file(f, loc["file"])),
                None,
            )
            if fn:
                loc["function"] = fn
                log.append(
                    {
                        "id": r["id"],
                        "op": "backfill-function",
                        "cwe": link["cwe_id"],
                        "file": loc["file"],
                        "line": loc["line"],
                        "function": fn,
                    }
                )
                stats["filled"] += 1
            else:
                stats["no matching frame"] += 1
        # A sink with no site at all takes the crash's first project frame from our own log (the
        # same evidence the ARVO-archived backfill used, here from our run).
        sink = (r.get("chain") or [{}])[-1]
        sev = sink.setdefault("evidence", {})
        own = [
            p
            for p in logs
            if any(
                s.get("log_ref") == str(p) and s.get("observed_by") == "self"
                for s in r.get("sanitizer_reports") or []
            )
        ]
        if own and not (sev.get("location") or {}).get("file"):
            first = next(
                (
                    (fn, f, ln)
                    for fn, f, ln in frames(own[0].read_text(errors="replace"))
                    if not _RUNTIME.search(f)
                ),
                None,
            )
            if first:
                sev["location"] = {
                    "file": first[1],
                    "line": first[2],
                    "function": first[0],
                    "stage": "crash (our vulnerable-side run)",
                }
                log.append(
                    {"id": r["id"], "op": "localize-sink", "file": first[1], "line": first[2]}
                )
                stats["sink localized"] += 1
        # The sink link is execution-witnessed only if a log is attributed to it: attribute our
        # own vulnerable log when it has a frame at the sink's file:line.
        sink = (r.get("chain") or [{}])[-1]
        ev = sink.get("evidence") or {}
        loc = ev.get("location") or {}
        if (
            logs
            and not ev.get("sanitizer_report_ref")
            and loc.get("file")
            and loc.get("line")
            and any(ln == loc["line"] and same_file(f, loc["file"]) for _, f, ln in stack)
        ):
            ev["sanitizer_report_ref"] = str(logs[0])
            log.append({"id": r["id"], "op": "attribute-sink", "log": str(logs[0])})
            stats["sink attributed"] += 1
    with open(rel / "dataset.jsonl", "w") as fh:
        fh.writelines(json.dumps(r) + "\n" for r in rows)
    with open(rel / "corrections_changelog.jsonl", "a") as fh:
        fh.writelines(json.dumps(e) + "\n" for e in log)
    print(dict(stats))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
