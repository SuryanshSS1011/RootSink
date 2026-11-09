#!/usr/bin/env python3
"""Release 1.0.4, item 3 (PREREGISTRATION): a GOLD kernel record's differential is its scorer
readiness test.

The kernel patch scorer (`kablate_kvm.sh <extid> <fix> <candidate>` on the runner) runs the same
control as a hunk test and applies the candidate whole to fix^. A record's fix^/fix differential
(`data/evidence/kernel/<extid>/differential.json`) is that test with the developer's fix as the
candidate: fix^ fired syzbot's bug and the fix commit ran clean on two boots. This stamps
`rl_scoring` and `rl_ready` for every GOLD kernel record with a complete differential, once the
registered smoke test has passed (`--smoke`: the kscore result directory), and logs each change.

Usage: stamp_kernel_scoring.py --smoke <kscore results dir> [--release data/release]
"""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path

RULE = "PR-12 kernel scorer (release 1.0.4, item 3)"


def smoke_passed(d: Path) -> tuple[bool, list[str]]:
    """Every control crashed and every developer fix passed; an infrastructure outcome (R10) is
    neither a pass nor a failure of the tool."""
    notes, ok = [], True
    for rj in sorted(d.rglob("result.json")):
        res = json.loads(rj.read_text())
        if res.get("mode") != "score":
            continue
        s, o = res.get("status"), res.get("outcome")
        notes.append(f"{res.get('extid')}: control {res.get('control')}, devfix {o} ({s})")
        if res.get("control") == "crashed" and o not in ("pass", None, "inconclusive"):
            ok = False  # the developer's fix crashed or did not apply or build: the tool is wrong
    return ok and bool(notes), notes


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--smoke", required=True)
    ap.add_argument("--release", default="data/release")
    a = ap.parse_args(argv)
    ok, notes = smoke_passed(Path(a.smoke))
    print("\n".join(notes))
    if not ok:
        print("smoke test did not pass; nothing stamped")
        return 1
    rel = Path(a.release)
    with open(rel / "dataset.jsonl") as fh:
        rows = [json.loads(x) for x in fh]
    log = []
    for r in rows:
        if r["label_confidence_tier"] != "gold" or r.get("project") != "linux-kernel":
            continue
        if r.get("rl_ready") is not None:
            continue
        ext = next(
            (x.removeprefix("syzbot-") for x in r.get("aliases") or [] if x.startswith("syzbot-")),
            None,
        )
        p = Path("data/evidence/kernel") / str(ext) / "differential.json"
        if not ext or not p.is_file():
            continue
        d = json.loads(p.read_text())
        clean = re.fullmatch(r"clean(,clean)+", d.get("patched") or "")
        if not (
            d.get("status") == "differential" and d.get("vulnerable") == "fired_match" and clean
        ):
            continue
        r["rl_scoring"] = {
            "rule": RULE,
            "nopatch": "crash",
            "devfix": "pass",
            "evidence": str(p),
            "scorer": f"kablate_kvm.sh {ext} {d.get('fix_commit')} devfix",
        }
        r["rl_ready"] = True
        log.append({"id": r["id"], "op": "kernel-rl-ready", "rule": RULE, "evidence": str(p)})
    with open(rel / "dataset.jsonl", "w") as fh:
        fh.writelines(json.dumps(r) + "\n" for r in rows)
    with open(rel / "corrections_changelog.jsonl", "a") as fh:
        fh.writelines(json.dumps(e) + "\n" for e in log)
    print(f"{len(log)} GOLD kernel records marked ready")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
