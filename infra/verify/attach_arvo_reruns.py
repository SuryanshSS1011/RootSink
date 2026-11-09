#!/usr/bin/env python3
"""Attach archived ARVO re-runs (roar/arvo_rerun.sh) to their records, then re-tier those records.

For each `<rerun_out>/<arvo_id>/result.json`, every outcome is logged (R10). A re-run is used only
if the vulnerable crash matches the shipped one (class + first project frame), or the shipped log
has no parseable crash to compare - otherwise it is a different crash and says nothing about this
record. When used:

  data/evidence/arvo/<id>/vul.sanitizer.txt    kept if already shipped, else the re-run's
  data/evidence/arvo/<id>/vul.rerun.sanitizer.txt  the re-run's crash, when the shipped log
                                               showed none (it then witnesses the vulnerable side)
  data/evidence/arvo/<id>/fix{1,2}.sanitizer.txt  both patched runs (tracked)

and the record's patched reports are replaced by ours with the observed outcome. Records touched
are re-tiered by chainforge.integrity in either direction; nothing else is.

Usage: attach_arvo_reruns.py <rerun_out_dir> [--release data/release]
"""

from __future__ import annotations

import argparse
import collections
import json
import shutil
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent))
from backfill_functions import frames  # noqa: E402  (sibling script, same directory)

from chainforge.evidence import classify_link, floor, same_file  # noqa: E402
from chainforge.integrity import gold_violations, tier_for  # noqa: E402

EVID = Path("data/evidence/arvo")


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("rerun_out")
    ap.add_argument("--release", default="data/release")
    args = ap.parse_args(argv)
    rel = Path(args.release)
    with open(rel / "dataset.jsonl") as fh:
        rows = [json.loads(line) for line in fh]
    with open(rel / "corrections_changelog.jsonl") as fh:
        seen = {
            (e["id"], e.get("status"))
            for e in map(json.loads, fh)
            if e.get("op") == "arvo-rerun-attempt"
        }
    by_aid = collections.defaultdict(list)
    for r in rows:
        for a in r.get("aliases") or []:
            if a.startswith("OSS-Fuzz-"):
                by_aid[a[9:]].append(r)

    log, stats = [], collections.Counter()
    for rj in sorted(Path(args.rerun_out).glob("*/result.json")):
        res = json.loads(rj.read_text())
        aid = rj.parent.name
        # A shipped log with no parseable crash class gives nothing to compare against: that is
        # "unverifiable", not "differs", and the re-run is then the better witness.
        if (res.get("shipped_vul_signature") or "|").startswith("|"):
            res["signature_matches_shipped"] = None
        recs = by_aid.get(aid, [])
        status = res.get("status")
        if status == "pull_failed":
            status = f"pull_failed:{res.get('side')}"
        elif res.get("signature_matches_shipped") is False:
            status = "vul_signature_differs"
        elif res.get("signature_matches_shipped") is None and res.get("vul") == "crashed":
            status = (
                "differential (shipped log unparseable)"
                if all(o == "clean" for o in res.get("fix") or [None])
                else "not_differential"
            )
        stats[status] += 1
        for r in recs:
            if (r["id"], status) not in seen:
                log.append(
                    {
                        "id": r["id"],
                        "op": "arvo-rerun-attempt",
                        "status": status,
                        "vul": res.get("vul"),
                        "fix": res.get("fix"),
                    }
                )
        if res.get("vul") != "crashed" or res.get("signature_matches_shipped") is False or not recs:
            continue

        ev = EVID / aid
        ev.mkdir(parents=True, exist_ok=True)
        # The shipped vulnerable log stays as history; where it showed no parseable crash, our
        # re-run's crash becomes the vulnerable-side witness.
        # A record whose sink report is not already our own triggered run needs THIS run as its
        # witness even when the crash matches the archived one; otherwise its I5 can never pass.
        unwitnessed = any(
            not any(
                s.get("revision") == "vulnerable"
                and s.get("witnesses") != "intermediate"
                and s.get("triggered")
                and s.get("observed_by") == "self"
                for s in r.get("sanitizer_reports") or []
            )
            for r in recs
        )
        rewitness = res.get("signature_matches_shipped") is None or unwitnessed
        ours = rj.parent / "vul.sanitizer.txt"
        if not (ev / "vul.sanitizer.txt").is_file():
            shutil.copy(ours, ev / "vul.sanitizer.txt")
        elif rewitness and (ev / "vul.sanitizer.txt").read_bytes() != ours.read_bytes():
            shutil.copy(ours, ev / "vul.rerun.sanitizer.txt")
        # True when the archived vul.sanitizer.txt IS this run's log (copied above, or identical).
        archived_is_ours = (ev / "vul.sanitizer.txt").read_bytes() == ours.read_bytes()
        fixes = sorted(rj.parent.glob("fix[0-9].sanitizer.txt"))
        for f in fixes:
            shutil.copy(f, ev / f.name)

        for r in recs:
            reps = [s for s in r.get("sanitizer_reports") or [] if s.get("revision") != "patched"]
            # A UBSan rebuild witnessing an intermediate link is not a replay of the sink: never
            # rewrite it, and never take the patched runs' sanitizer from it. Rewriting it here
            # once pointed 12 hdf5 witnesses at the ASan sink log and dropped the sink report.
            sink_vul = [
                s
                for s in reps
                if s.get("revision") == "vulnerable" and s.get("witnesses") != "intermediate"
            ]
            rerun_log = ev / "vul.rerun.sanitizer.txt"
            witness = rerun_log if rerun_log.is_file() else ev / "vul.sanitizer.txt"
            if not sink_vul:
                sink_vul = [{"revision": "vulnerable", "sanitizer": "asan"}]
                reps.append(sink_vul[0])
            for s in sink_vul:
                if rerun_log.is_file() or archived_is_ours:
                    # Our run crashed (checked above) and its log is archived at `witness`.
                    s.update(log_ref=str(witness), triggered=True, observed_by="self")
                elif not Path(s.get("log_ref") or "").is_file():
                    s["log_ref"] = str(ev / "vul.sanitizer.txt")
            san = next((s.get("sanitizer") for s in sink_vul if s.get("sanitizer")), "asan")
            for f, outcome in zip(fixes, res.get("fix") or [], strict=False):
                reps.append(
                    {
                        "revision": "patched",
                        "sanitizer": san,
                        "observed_by": "self",
                        "triggered": outcome == "crashed",
                        "log_ref": str(ev / f.name),
                    }
                )
            r["sanitizer_reports"] = reps
            # Attribute the sink link to our vulnerable log when it has a frame at the sink's
            # file:line (as backfill_functions.py does), so one import pass suffices.
            vref = next((s["log_ref"] for s in sink_vul if s.get("log_ref")), None)
            sink_ev = r["chain"][-1].setdefault("evidence", {})
            sloc = sink_ev.get("location") or {}
            if vref and Path(vref).is_file() and not sink_ev.get("sanitizer_report_ref"):
                stack = frames(Path(vref).read_text(errors="replace"))
                if any(
                    ln == sloc.get("line") and same_file(f, sloc.get("file") or "")
                    for _, f, ln in stack
                ):
                    sink_ev["sanitizer_report_ref"] = vref
                    for link in r["chain"]:
                        link["evidence_kind"] = str(classify_link(link.get("evidence")))
                    r["evidence_floor"] = str(floor(r))
            # Recomputed from the observed outcomes: the remote flag also folded in the signature
            # comparison, which is now judged here.
            fix_outcomes = res.get("fix") or []
            r["differential_complete"] = bool(fix_outcomes) and all(
                o == "clean" for o in fix_outcomes
            )
            old = r["label_confidence_tier"]
            if old == "bronze":
                continue
            v = gold_violations(r, Path("."))
            new = tier_for(r, v)
            if new != old:
                log.append(
                    {"id": r["id"], "op": "arvo-rerun-retier", "from": old, "to": new, "rules": v}
                )
                stats[f"retier {old} -> {new}"] += 1
                r["label_confidence_tier"] = new
            if v:
                r["gold_contract_gaps"] = v
            else:
                r.pop("gold_contract_gaps", None)

    with open(rel / "dataset.jsonl", "w") as fh:
        fh.writelines(json.dumps(r) + "\n" for r in rows)
    with open(rel / "corrections_changelog.jsonl", "a") as fh:
        fh.writelines(json.dumps(e) + "\n" for e in log)
    for k, n in sorted(stats.items()):
        print(f"{n:6d}  {k}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
