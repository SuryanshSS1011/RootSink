#!/usr/bin/env python3
"""Restore site function names that an earlier parser cut at the first space.

Some C++ frame names were stored up to their first space, so `Foo::bar(int, char**)` became
`Foo::bar(int,` and `(anonymous namespace)::load(...)` became `(anonymous`, which names no
function. For each such site, the full name is taken from the frame in the record's own archived
sanitizer report with the same file and line whose name starts with the stored text. A site with
no such frame is left as it is and counted. Logged as `function-name-repaired`. Idempotent.

Usage: repair_function_names.py [--release data/release]
"""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path

_FRAME = re.compile(r"#\d+ 0x[0-9a-f]+ in (.*?) (\S+?):(\d+)(?::\d+)?\s*$", re.M)


def truncated(name: str | None) -> bool:
    return bool(name) and name.count("(") > name.count(")")


def full_name(loc: dict, logs: list[str]) -> str | None:
    want = Path(loc.get("file") or "").name
    for text in logs:
        for m in _FRAME.finditer(text):
            if (
                m.group(3) == str(loc.get("line"))
                and Path(m.group(2)).name == want
                and m.group(1).startswith(loc["function"])
            ):
                return m.group(1)
    return None


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--release", default="data/release")
    args = ap.parse_args(argv)
    rel = Path(args.release)
    with open(rel / "dataset.jsonl") as fh:
        rows = [json.loads(line) for line in fh]
    log, stats = [], {"repaired": 0, "no matching frame": 0}
    for r in rows:
        sites = [
            (i, (link.get("evidence") or {}).get("location") or {})
            for i, link in enumerate(r.get("chain") or [])
        ]
        sites = [(i, loc) for i, loc in sites if truncated(loc.get("function"))]
        if not sites:
            continue
        logs = [
            Path(s["log_ref"]).read_text(errors="replace")
            for s in r.get("sanitizer_reports") or []
            if s.get("log_ref") and Path(s["log_ref"]).is_file()
        ]
        for i, loc in sites:
            name = full_name(loc, logs)
            if not name:
                stats["no matching frame"] += 1
                continue
            log.append(
                {
                    "id": r["id"],
                    "op": "function-name-repaired",
                    "link": i,
                    "from": loc["function"],
                    "to": name,
                }
            )
            loc["function"] = name
            stats["repaired"] += 1
    with open(rel / "dataset.jsonl", "w") as fh:
        fh.writelines(json.dumps(r) + "\n" for r in rows)
    with open(rel / "corrections_changelog.jsonl", "a") as fh:
        fh.writelines(json.dumps(e) + "\n" for e in log)
    print(stats)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
