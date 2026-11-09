#!/usr/bin/env python3
"""Release 1.0.3, item 2 (PREREGISTRATION): a one-hunk fix's scorer runs are its single-hunk test.

A record qualifies when its recorded fix is one hunk in one library file (not a harness or test,
PR-3 I6), its root has no hunk test yet, and the PR-12 scorer applied the fix whole at fuzz 0 with
the unmodified build crashing and the fixed build passing (`rl_scoring`). For each one this finds
the scorer's run in the downloaded chainforge-runner `score-*` artifacts and lays it out the way
apply_pr4.py reads an ablation batch:

  <out>/<arvo id>/result.json          control "crashed", the hunk, fuzz 0, the run's provenance
  <out>/<arvo id>/hunks/hunk00.patch   the scorer's applied patch (the whole fix, one hunk)
  <out>/<arvo id>/control.log          the unmodified build's replays (nopatch/score.log)
  <out>/<arvo id>/hunk00.patch.log     the fixed build's replays (devfix/score.log)

apply_pr4.py then applies PR-4 unchanged: the crash and ran_clean checks on these logs, the guard
rule's CWE, origin roots keeping their site and CWE, and re-tiering.

Usage: onehunk_from_scorer.py <extracted score artifacts dir> --out <batch dir>
  (artifacts: gh api repos/SuryanshSS1011/chainforge-runner/actions/artifacts/<id>/zip, each
   unzipped into <dir>/<artifact id>/)
"""

from __future__ import annotations

import argparse
import json
import re
import shutil
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))
from chainforge.evidence import is_non_guard_path  # noqa: E402


def candidates(rows: list[dict]) -> dict[str, dict]:
    out = {}
    for r in rows:
        s = r.get("rl_scoring") if isinstance(r.get("rl_scoring"), dict) else None
        if not s or s.get("nopatch") != "crash" or s.get("devfix") != "pass":
            continue
        ap = s.get("devfix_apply") or {}
        if ap.get("mode") != "whole" or ap.get("fuzz") != 0:
            continue
        diff = r.get("patch_diff") or ""
        files = re.findall(r"^\+\+\+ b/(\S+)", diff, re.M)
        if len(re.findall(r"^@@", diff, re.M)) != 1 or len(files) != 1:
            continue
        if is_non_guard_path(files[0]):
            continue
        ev = r["chain"][0].get("evidence") or {}
        if ev.get("causal_proof") or ev.get("guard_site_proof"):
            continue
        aid = next(
            (
                a.removeprefix("OSS-Fuzz-")
                for a in r.get("aliases") or []
                if a.startswith("OSS-Fuzz-")
            ),
            None,
        )
        if aid:
            out[aid] = {"id": r["id"], "file": files[0]}
    return out


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("artifacts")
    ap.add_argument("--out", required=True)
    ap.add_argument("--release", default="data/release")
    a = ap.parse_args(argv)
    with open(Path(a.release) / "dataset.jsonl") as fh:
        want = candidates([json.loads(x) for x in fh])
    out = Path(a.out)
    found = 0
    for res_path in sorted(Path(a.artifacts).glob("*/*/devfix/result.json")):
        run = res_path.parent.parent
        aid = run.name
        if aid not in want or (out / aid / "result.json").exists():
            continue
        dv = json.loads(res_path.read_text())
        npj = run / "nopatch" / "result.json"
        nv = json.loads(npj.read_text()) if npj.is_file() else {}
        logs = (run / "nopatch" / "score.log", run / "devfix" / "score.log")
        patch = run / "devfix" / "files" / "000.patch"
        if not (
            dv.get("outcome") == "pass"
            and (dv.get("apply") or {}).get("fuzz") == 0
            and nv.get("outcome") == "crash"
            and all(p.is_file() for p in (*logs, patch))
        ):
            continue
        hunk = patch.read_text(errors="replace")
        added = sum(1 for x in hunk.splitlines() if x.startswith("+") and not x.startswith("+++"))
        d = out / aid
        (d / "hunks").mkdir(parents=True, exist_ok=True)
        shutil.copy(patch, d / "hunks" / "hunk00.patch")
        shutil.copy(logs[0], d / "control.log")
        shutil.copy(logs[1], d / "hunk00.patch.log")
        (d / "result.json").write_text(
            json.dumps(
                {
                    "arvo_id": aid,
                    "control": "crashed",
                    "fuzz": 0,
                    "guard_hunk": {
                        "hunk": "hunk00.patch",
                        "file": want[aid]["file"],
                        "added": added,
                    },
                    "basis": "PR-12 scorer runs of a one-hunk fix (release 1.0.3, item 2)",
                    "score_artifact": run.parent.name,
                },
                indent=1,
            )
            + "\n"
        )
        found += 1
    print(f"{found} of {len(want)} qualifying records laid out in {out}")
    return 0 if found == len(want) else 1


if __name__ == "__main__":
    raise SystemExit(main())
