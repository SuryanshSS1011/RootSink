#!/usr/bin/env python3
"""Stamp two derived, harness-only fields on every record.

`fix_attribution` asks whether the recorded fix ALONE removes the crash. GOLD's patched runs use
the fixed image the source ships, which for ARVO is ARVO's fixed build: the fix-distance probe
(2026-10-23) found it differs from "vulnerable image + recorded fix" in most images (other
commits, other repositories). So:
  - ARVO: true when PR-12 scoring found the unmodified build crashing and the recorded fix,
    applied with exact context, passing (`rl_ready`); false only when that fix applied exactly,
    built and still crashed; null when the fix alone could not be run (it did not apply exactly
    or did not build, or the unmodified build failed), which is no result, or was not scored.
  - kernel: true when our own differential built the fix's parent and the fix in one tree and
    the parent crashed while the fix stayed clean (`data/evidence/kernel/<id>/differential.json`
    with status `differential`); null otherwise.

`root_site_relation` places the root site against our own vulnerable report: `crash-line` (the
crashing function, within 5 lines of the crash line), `crash-function` (the crashing function,
farther away), `on-stack` (another function on the crash stack), `off-stack` (a function not on
it), `file-only` (no function name), or null when either end is unplaced. A root close to the
crash may be a symptom guard rather than the defect, which the label audit judges.

Logged as `attribution-stamped` only when a value changes. Idempotent.

Usage: stamp_attribution.py [--release data/release]
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
from backfill_functions import frames  # noqa: E402

from chainforge.evidence import bare_function, same_file  # noqa: E402
from chainforge.integrity import vul_log  # noqa: E402


def fix_attribution(r: dict, root: Path) -> dict:
    if r.get("provenance") == "syzbot":
        for s in r.get("sanitizer_reports") or []:
            ref = s.get("log_ref") or ""
            if ref.startswith("data/evidence/kernel/"):
                d = root / Path(ref).parent / "differential.json"
                if d.is_file() and json.loads(d.read_text()).get("status") == "differential":
                    return {"status": True, "basis": "fix^ and fix built in one tree"}
        return {"status": None, "basis": "no own fix^/fix differential"}
    s = r.get("rl_scoring") or {}
    if r.get("rl_ready") is True:
        return {"status": True, "basis": "vulnerable image + recorded fix passes"}
    if s.get("nopatch") == "crash" and s.get("devfix") == "crash" and r.get("rl_ready") is False:
        return {"status": False, "basis": "fix applied with exact context does not stop the crash"}
    if s.get("nopatch") == "crash" and r.get("rl_ready") is False:
        # Not a negative result: the fix alone was never run (R10).
        why = {"patch_fail": "fix does not apply", "build_fail": "fix does not build"}.get(
            s.get("devfix"), "fix applies only with shifted context"
        )
        return {"status": None, "basis": f"untested: {why}"}
    if s.get("nopatch"):
        return {"status": None, "basis": "untested: unmodified build failed"}
    return {"status": None, "basis": "not scored"}


def crash_stack(log: str) -> str:
    """The first contiguous run of stack frames (`#0` onwards): the crash itself, not the
    allocation, free or origin stacks a report adds after it."""
    lines = log.splitlines()
    start = next((i for i, ln in enumerate(lines) if re.match(r"\s*#0 ", ln)), None)
    if start is None:
        return ""
    out = []
    for ln in lines[start:]:
        if not re.match(r"\s*#\d+ ", ln):
            break
        out.append(ln)
    return "\n".join(out)


_KFRAME = re.compile(r"^(\?\s+)?([A-Za-z_][\w.]*)(?:\+0x[0-9a-f]+/0x[0-9a-f]+|\s+\S+\.[chS]:\d+)")
_KPREFIX = re.compile(r"^((?:\[[^\]]*\])*)")
_KTASK = re.compile(r"\[\s*[TC]\d+\]")
_KMARKS = ("<TASK>", "<IRQ>", "</IRQ>", "<NMI>", "</NMI>", "<SOFTIRQ>", "</SOFTIRQ>")
_KSTOP = ("RIP:", "Code:", "RSP:", "Allocated by", "Freed by", "The buggy address")


def kernel_crash_stack(log: str) -> list[str]:
    """Functions on the call trace of a KASAN report (the crash), reliable frames only.

    KASAN frames read `name+0x32a/0x5a0` (or, symbolized, `name file.c:123`), without the ASan
    `#N ... in` form `frames()` parses, so until release 1.0.10 no kernel root was ever placed on
    the stack. The trace is the first after the `BUG: KASAN:` line. Console lines from other tasks
    or CPUs, interleaved with it, are skipped by the trace's `[T..]`/`[C..]` tag. Frames marked `?`
    are stale stack words, not calls, and are skipped; compiler suffixes such as `.constprop.0` are
    cut. The trace ends at `</TASK>`, a blank line, the register dump or the next stack."""
    lines = log.splitlines()
    bug = next((i for i, ln in enumerate(lines) if "BUG: KASAN:" in ln), 0)
    start = next(
        (i for i in range(bug, len(lines)) if lines[i].rstrip().endswith("Call Trace:")), None
    )
    if start is None:
        return []
    tag = _KTASK.search(_KPREFIX.match(lines[start]).group(1))
    out = []
    for ln in lines[start + 1 :]:
        prefix = _KPREFIX.match(ln).group(1)
        if tag and prefix and tag.group(0) not in prefix:
            continue  # another task's console line
        body = ln[len(prefix) :].strip()
        if body == "</TASK>" or not body or body.startswith(_KSTOP):
            break
        if body in _KMARKS:
            continue
        m = _KFRAME.match(body)
        if m and not m.group(1):
            out.append(m.group(2).split(".", 1)[0])
    return out


def site_relation(r: dict, root: Path) -> str | None:
    chain = r.get("chain") or []
    if len(chain) < 2:
        return None
    a = (chain[0].get("evidence") or {}).get("location") or {}
    b = (chain[-1].get("evidence") or {}).get("location") or {}
    if not (a.get("file") and b.get("file")):
        return None
    fa, fb = bare_function(a.get("function")), bare_function(b.get("function"))
    if not fa:
        return "file-only"
    if fb and fa == fb and same_file(a["file"], b["file"]):
        la, lb = a.get("line"), b.get("line")
        near = isinstance(la, int) and isinstance(lb, int) and abs(la - lb) <= 5
        return "crash-line" if near else "crash-function"
    p = vul_log(r, root)
    if p is None:
        return None  # no archived crash report to place the root against (release 1.0.10)
    text = p.read_text(errors="replace")
    if "BUG: KASAN:" in text:  # release 1.0.10: the kernel's frames are read too
        names = kernel_crash_stack(text)
    else:
        names = [fn for fn, _, _ in frames(crash_stack(text))]
    if any(bare_function(fn) == fa for fn in names):
        return "on-stack"
    return "off-stack"


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--release", default="data/release")
    args = ap.parse_args(argv)
    rel = Path(args.release)
    root = Path(".")
    with open(rel / "dataset.jsonl") as fh:
        rows = [json.loads(line) for line in fh]
    log, stats = [], collections.Counter()
    for r in rows:
        fa, sr = fix_attribution(r, root), site_relation(r, root)
        stats[f"{r['label_confidence_tier']} fix_attribution={fa['status']}"] += 1
        stats[f"{r['label_confidence_tier']} root_site_relation={sr}"] += 1
        if r.get("fix_attribution") != fa or r.get("root_site_relation") != sr:
            log.append(
                {
                    "id": r["id"],
                    "op": "attribution-stamped",
                    "fix_attribution": fa["status"],
                    "root_site_relation": sr,
                }
            )
            r["fix_attribution"], r["root_site_relation"] = fa, sr
    with open(rel / "dataset.jsonl", "w") as fh:
        fh.writelines(json.dumps(r) + "\n" for r in rows)
    with open(rel / "corrections_changelog.jsonl", "a") as fh:
        fh.writelines(json.dumps(e) + "\n" for e in log)
    for k, v in sorted(stats.items()):
        if k.startswith("gold "):
            print(f"{v:6d}  {k}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
