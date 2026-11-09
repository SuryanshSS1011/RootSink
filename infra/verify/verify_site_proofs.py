#!/usr/bin/env python3
"""Hold site proofs (`guard_site_proof`) to the PR-4 addendum: a proof counts only if its archived
logs show the unmodified control CRASHED and the guard-only run EXECUTED the input with nothing
firing (`integrity.ran_clean`).

Site proofs were stored without log paths. For each one, the runner output that produced it is
looked up by ARVO id and hunk name in the given output dirs (newest given last wins). When the
control log shows a sanitizer crash and the hunk's log passes `ran_clean`, both logs are archived
under data/evidence/ablation/<arvo id>/ (`control.log`, `guard_only.log` for the proving hunk) and
their paths are recorded on the proof. Otherwise the proof moves to `evidence.unverified_test`,
with the reason, until a re-run with logs: a missing log is no result (R10), but nothing unproven
is counted as tested. Logged as `site-proof-verified` or `site-proof-unverified`. Idempotent.

Usage: verify_site_proofs.py <ablation out dir>... [--release data/release]
"""

from __future__ import annotations

import argparse
import collections
import json
import shutil
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))
from chainforge.integrity import _CRASHED as CRASH  # noqa: E402
from chainforge.integrity import ran_clean  # noqa: E402


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("dirs", nargs="+")
    ap.add_argument("--release", default="data/release")
    args = ap.parse_args(argv)
    rel = Path(args.release)
    with open(rel / "dataset.jsonl") as fh:
        rows = [json.loads(line) for line in fh]
    log, stats = [], collections.Counter()
    for r in rows:
        ev = (r.get("chain") or [{}])[0].get("evidence") or {}
        p = ev.get("guard_site_proof")
        if not p or p.get("guard_only_log"):
            continue
        aid, hunk = str(p.get("arvo_id") or ""), p.get("hunk") or ""
        found = None
        for d in args.dirs:
            c, g = Path(d) / aid / "control.log", Path(d) / aid / f"{hunk}.log"
            h = Path(d) / aid / "hunks" / hunk
            # Hunk names are stable only within one run: the run's hunk must touch the same file.
            same = h.is_file() and (p.get("file") or "") in h.read_text(errors="replace")
            if c.is_file() and g.is_file() and same:
                found = (c, g)
        why = None
        if not found:
            why = "no archived log of the guard-only run"
        else:
            ctext = found[0].read_text(errors="replace")
            gtext = found[1].read_text(errors="replace")
            if not CRASH.search(ctext):
                why = "control log shows no crash"
            elif not ran_clean(gtext):
                why = "guard-only log does not show the input executing cleanly"
        tier = r["label_confidence_tier"]
        if why:
            p["why_unverified"] = why
            ev.setdefault("unverified_test", {})["guard_site_proof"] = ev.pop("guard_site_proof")
            stats[f"{tier} unverified: {why}"] += 1
            log.append({"id": r["id"], "op": "site-proof-unverified", "why": why})
            continue
        dst = Path("data/evidence/ablation") / aid
        dst.mkdir(parents=True, exist_ok=True)
        shutil.copy(found[0], dst / "control.log")
        shutil.copy(found[1], dst / "guard_only.log")
        p["control_log"], p["guard_only_log"] = (
            str(dst / "control.log"),
            str(dst / "guard_only.log"),
        )
        stats[f"{tier} verified"] += 1
        log.append({"id": r["id"], "op": "site-proof-verified", "logs": str(dst)})
    with open(rel / "dataset.jsonl", "w") as fh:
        fh.writelines(json.dumps(r) + "\n" for r in rows)
    with open(rel / "corrections_changelog.jsonl", "a") as fh:
        fh.writelines(json.dumps(e) + "\n" for e in log)
    for k, v in sorted(stats.items()):
        print(f"{v:6d}  {k}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
