#!/usr/bin/env python3
"""Repair records damaged by attach_arvo_reruns.py rewriting UBSan intermediate witnesses.

Before 2026-10-19, attach_arvo_reruns.py updated every vulnerable-side report when it attached a
re-run, including the report a UBSan rebuild adds to witness a CWE-190 intermediate link
(``witnesses: "intermediate"``). On a record whose UBSan witness was attached first, that pointed
the intermediate report at the ASan re-run log, left the record with no sink-side vulnerable
report, and copied ``sanitizer: ubsan`` onto the patched runs. integrity.py then saw no triggered
sink run and the record failed PR-3 I5 although our own two-sided run passed.

This script restores what the archived logs already show, and nothing else:
  * an intermediate report points back at its own ``ubsan.vul.txt``;
  * a record with no sink-side vulnerable report gets one for ``vul.rerun.sanitizer.txt``, only if
    the changelog records our re-run of that case with the vulnerable side crashing;
  * patched reports take the sink run's sanitizer;
  * the sink link is attributed to that log only where a stack frame sits at the sink's file:line
    (the rule attach_arvo_reruns.py itself applies).
Every touched record is re-tiered by chainforge.integrity in either direction and logged.

Usage: repair_intermediate_overwrite.py [--release data/release] [--dry-run]
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
from backfill_functions import frames  # noqa: E402  (sibling script, same directory)

from chainforge.evidence import classify_link, floor, same_file  # noqa: E402
from chainforge.integrity import gold_violations, tier_for  # noqa: E402

EVID = Path("data/evidence/arvo")
RULE = "repair-intermediate-overwrite"
# A crash header. UBSan's counts only as a deadly signal ("ERROR: UndefinedBehaviorSanitizer:
# SEGV ..."); its "runtime error:" lines are overflow witnesses, never a sink crash.
_SAN = re.compile(r"ERROR: (Address|Memory|Thread|UndefinedBehavior)Sanitizer")


def sanitizer_of(log: Path) -> str | None:
    m = _SAN.search(log.read_text(errors="replace")) if log.is_file() else None
    return (
        {"Address": "asan", "Memory": "msan", "Thread": "tsan", "UndefinedBehavior": "ubsan"}[
            m.group(1)
        ]
        if m
        else None
    )


def arvo_id(rec: dict) -> str | None:
    return next((a[9:] for a in rec.get("aliases") or [] if a.startswith("OSS-Fuzz-")), None)


def repair(rec: dict, crashed_reruns: set[str], unparseable_reruns: set[str]) -> list[str]:
    aid = arvo_id(rec)
    if not aid:
        return []
    ev, done = EVID / aid, []
    reps = rec.get("sanitizer_reports") or []
    inter = [s for s in reps if s.get("witnesses") == "intermediate"]
    ubsan_vul = ev / "ubsan.vul.txt"
    for s in inter:
        if s.get("log_ref") != str(ubsan_vul) and ubsan_vul.is_file():
            s.update(log_ref=str(ubsan_vul), sanitizer="ubsan")
            done.append("intermediate report restored to ubsan.vul.txt")
    rerun, archived = ev / "vul.rerun.sanitizer.txt", ev / "vul.sanitizer.txt"
    sink_vul = [
        s
        for s in reps
        if s.get("revision") == "vulnerable" and s.get("witnesses") != "intermediate"
    ]
    witnessed = any(s.get("triggered") and s.get("observed_by") == "self" for s in sink_vul)
    # Our crashing re-run is archived either as vul.rerun.sanitizer.txt, or, when no crash log was
    # archived before it ("shipped log unparseable"), as vul.sanitizer.txt itself: an unparseable
    # earlier log cannot carry the sanitizer crash header this one does.
    ours = None
    if rec["id"] in crashed_reruns and sanitizer_of(rerun):
        ours = rerun
    elif rec["id"] in unparseable_reruns and not rerun.is_file() and sanitizer_of(archived):
        ours = archived
    if ours and not witnessed:
        san = sanitizer_of(ours)
        fields = {"triggered": True, "observed_by": "self", "log_ref": str(ours)}
        if sink_vul:
            sink_vul[0].update(fields, sanitizer=san)
            done.append(f"sink report marked as our crashing re-run ({ours.name}, {san})")
        else:
            reps.append({"revision": "vulnerable", "sanitizer": san, **fields})
            sink_vul = reps[-1:]
            done.append(f"sink report re-added for our re-run ({ours.name}, {san})")
    sink_san = next((s.get("sanitizer") for s in sink_vul if s.get("sanitizer")), None)
    for s in reps:
        if s.get("revision") == "patched" and sink_san and s.get("sanitizer") != sink_san:
            s["sanitizer"] = sink_san
            done.append(f"patched report sanitizer -> {sink_san}")
    sink_ev = rec["chain"][-1].setdefault("evidence", {})
    sloc = sink_ev.get("location") or {}
    vref = next((s["log_ref"] for s in sink_vul if s.get("log_ref")), None)
    attributable = (
        vref
        and Path(vref).is_file()
        and not sink_ev.get("sanitizer_report_ref")
        and any(
            ln == sloc.get("line") and same_file(f, sloc.get("file") or "")
            for _, f, ln in frames(Path(vref).read_text(errors="replace"))
        )
    )
    if attributable:
        sink_ev["sanitizer_report_ref"] = vref
        done.append("sink link attributed (frame at sink file:line)")
    rec["sanitizer_reports"] = reps
    return done


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--release", default="data/release")
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args(argv)
    rel = Path(args.release)
    with open(rel / "dataset.jsonl") as fh:
        rows = [json.loads(line) for line in fh]
    crashed, unparseable = set(), set()
    with open(rel / "corrections_changelog.jsonl") as fh:
        for e in map(json.loads, fh):
            if e.get("op") == "arvo-rerun-attempt" and e.get("vul") == "crashed":
                crashed.add(e["id"])
                if e.get("status") == "differential (shipped log unparseable)":
                    unparseable.add(e["id"])
    log, stats = [], collections.Counter()
    for r in rows:
        changes = repair(r, crashed, unparseable)
        if not changes:
            continue
        stats["records repaired"] += 1
        for link in r["chain"]:
            link["evidence_kind"] = str(classify_link(link.get("evidence")))
        r["evidence_floor"] = str(floor(r))
        op = RULE if any("intermediate" in c for c in changes) else "repair-rerun-witness"
        entry = {"id": r["id"], "op": op, "changes": changes}
        if r["label_confidence_tier"] in ("silver", "gold"):
            v = gold_violations(r, Path("."))
            new = tier_for(r, v)
            if new != r["label_confidence_tier"]:
                entry.update({"from": r["label_confidence_tier"], "to": new})
                stats[f"retier {r['label_confidence_tier']} -> {new}"] += 1
                r["label_confidence_tier"] = new
            if v:
                r["gold_contract_gaps"] = v
            else:
                r.pop("gold_contract_gaps", None)
        log.append(entry)
    for k, n in sorted(stats.items()):
        print(f"{n:6d}  {k}")
    if args.dry_run:
        for e in log:
            print(json.dumps(e))
        return 0
    with open(rel / "dataset.jsonl", "w") as fh:
        fh.writelines(json.dumps(r) + "\n" for r in rows)
    with open(rel / "corrections_changelog.jsonl", "a") as fh:
        fh.writelines(json.dumps(e) + "\n" for e in log)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
