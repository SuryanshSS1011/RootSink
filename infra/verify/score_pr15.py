#!/usr/bin/env python3
"""Score PREREGISTRATION PR-15: reproduction from upstream source.

Input: merged output of the runner's `fromsource` workflow on data/validation/pr15_sample.json
(`<out>/<arvo id>/{result.json, run_vul_1.log, run_fix_{1,2}.log}`). Per case:

  reproduced      both sides built; the vulnerable build crashed with the same sanitizer class
                  and first project frame (file basename and function) as the record's archived
                  vulnerable report; both fixed-build runs read the input and stayed clean;
  not reproduced  both sides built and any of those three conditions failed (the reason is kept);
  build failed    either side did not build, or the OSS-Fuzz image did not build. A limitation of
                  rebuilding old projects, never a failure to reproduce (PR-15).

The frame is compared by file name and function, not line: the upstream revision is the fix's
first parent, which can differ from the ARVO image's revision by unrelated commits.
Writes data/validation/pr15_result.json.

Usage: score_pr15.py <fromsource_out_dir> [--out data/validation/pr15_result.json]
"""

from __future__ import annotations

import argparse
import collections
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent))
from import_gh_runs import _CLASS, _FRAME, _RUNTIME, wilson  # noqa: E402

from chainforge.evidence import bare_function  # noqa: E402
from chainforge.integrity import _CRASHED, ran_clean, vul_log  # noqa: E402

_ANSI = re.compile(r"\x1b\[[0-9;]*m")


def first_frame(text: str) -> tuple[str, str, str | None]:
    """(sanitizer class, file basename, bare function) of a report; empty strings if absent."""
    c = _CLASS.search(text)
    cls = (c.group(1) or c.group(2) or "").strip() if c else ""
    for m in _FRAME.finditer(text):
        if not _RUNTIME.search(m.group(2)):
            return cls, Path(m.group(2)).name, bare_function(m.group(1))
    return cls, "", None


def score_case(d: Path, archived: str | None) -> dict:
    res = json.loads((d / "result.json").read_text())
    out = {"arvo_id": res.get("arvo_id"), "status": res.get("status")}
    built = res.get("vul_build") == "built" and res.get("fix_build") == "built"
    out["vul_build"], out["fix_build"] = res.get("vul_build"), res.get("fix_build")
    if res.get("status") != "ok" or not built:
        out["outcome"] = "build failed"
        return out
    # The helper's runs are colourised; escape codes would split the sanitizer's class line.
    read = lambda p: _ANSI.sub("", p.read_text(errors="replace")) if p.is_file() else ""  # noqa: E731
    vul = read(d / "run_vul_1.log")
    fixes = [read(d / f"run_fix_{i}.log") for i in (1, 2)]
    why = []
    if not _CRASHED.search(vul):
        why.append("vulnerable build did not crash")
    elif archived is None:
        why.append("no archived report to compare")
    else:
        new, old = first_frame(vul), first_frame(archived)
        out["signature_matches"] = new == old
        if new != old:
            why.append("crash differs from the archived report")
    # OSS-Fuzz's helper mounts the input at /testcase, so libFuzzer's completion line names that
    # path; it is the same marker the release rule uses for /tmp/poc.
    if not all(ran_clean(t, declared_marker="Executed /testcase") for t in fixes):
        why.append("fixed build not clean twice")
    out["outcome"] = "not reproduced" if why else "reproduced"
    if why:
        out["why"] = why
    return out


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("out_dir")
    ap.add_argument("--sample", default="data/validation/pr15_sample.json")
    ap.add_argument("--release", default="data/release/dataset.jsonl")
    ap.add_argument("--out", default="data/validation/pr15_result.json")
    args = ap.parse_args(argv)
    sample = json.loads(Path(args.sample).read_text())["sample"]
    with open(args.release) as fh:
        rows = {r["id"]: r for r in map(json.loads, fh)}
    cases = []
    for c in sample:
        d = Path(args.out_dir) / c["arvo_id"]
        if not (d / "result.json").is_file():
            cases.append({"arvo_id": c["arvo_id"], "outcome": "not run"})
            continue
        rec = rows.get(c["id"])
        p = vul_log(rec, Path(".")) if rec else None
        cases.append(score_case(d, p.read_text(errors="replace") if p else None) | {"id": c["id"]})
    n = collections.Counter(x["outcome"] for x in cases)
    both = n["reproduced"] + n["not reproduced"]
    res = {
        "rule": "PREREGISTRATION PR-15",
        "sampled": len(sample),
        "outcomes": dict(n),
        "build_success": {
            "vulnerable": sum(x.get("vul_build") == "built" for x in cases),
            "fixed": sum(x.get("fix_build") == "built" for x in cases),
            "both": both,
        },
        "reproduced_of_built": [n["reproduced"], both],
        "wilson95": wilson(n["reproduced"], both) if both else None,
        "statuses": dict(collections.Counter(x.get("status") for x in cases)),
        "cases": cases,
    }
    Path(args.out).write_text(json.dumps(res, indent=1) + "\n")
    print(json.dumps({k: v for k, v in res.items() if k != "cases"}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
