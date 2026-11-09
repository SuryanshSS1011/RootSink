#!/usr/bin/env python3
"""Attach the reproduced execution witness to the len-3 records and promote them.

The 59 len-3 chains (CWE-20 -> CWE-190 -> sink) already carried `patch_diff` but had NO
sanitizer_reports at all, so the schema correctly refused GOLD. Reproducing each ARVO case
supplies the missing half. These are the dataset's only chains longer than 2, which the
causality-aware RL goal needs, so they are worth the round trip.

Two things are done carefully:
  * log_ref is written as a per-case PATH (len3_repro/<id>/vul.sanitizer.txt), not the bare
    "vul.sanitizer.txt" used elsewhere. An evidence audit found 1524 bare-name refs that
    identify nothing; new evidence should not add to that.
  * differential_complete is set from BOTH revisions: fired at vulnerable and clean at
    patched. A case whose fix still crashes is left SILVER rather than counted.

Usage: attach_len3_witness.py <dataset.jsonl> <witness.json> --out <out.jsonl>
"""

import argparse
import json
import re
import sys


def arvo_id(rec):
    m = re.search(r"OSS-Fuzz-(\d+)", json.dumps(rec.get("aliases") or []))
    if m:
        return m.group(1)
    m = re.search(r"arvo:(\d+)-", json.dumps(rec.get("docker_image_ref") or {}))
    return m.group(1) if m else None


def main(argv):
    ap = argparse.ArgumentParser()
    ap.add_argument("dataset")
    ap.add_argument(
        "witness",
        help="json: {arvo_id: {vul_crashed, fix_crashed, sanitizer, "
        "bug_class, direction, crash_site}}",
    )
    ap.add_argument("--out", required=True)
    args = ap.parse_args(argv)

    with open(args.witness) as fh:
        wit = json.load(fh)
    with open(args.dataset) as fh:
        rows = [json.loads(x) for x in fh if x.strip()]

    stats = {"attached": 0, "promoted": 0, "dirty_pair": 0, "no_witness": 0, "localized": 0}

    for rec in rows:
        chain = [c for c in (rec.get("chain") or []) if isinstance(c, dict)]
        if len(chain) < 3:
            continue
        aid = arvo_id(rec)
        w = wit.get(aid) if aid else None
        if not w or not w.get("vul_crashed"):
            stats["no_witness"] += 1
            continue

        san = (w.get("sanitizer") or "asan").lower()
        reports = [
            {
                "revision": "vulnerable",
                "sanitizer": san,
                "log_ref": f"len3_repro/{aid}/vul.sanitizer.txt",
                "triggered": True,
            }
        ]
        if w.get("fix_ran"):
            reports.append(
                {
                    "revision": "patched",
                    "sanitizer": san,
                    "log_ref": f"len3_repro/{aid}/fix.sanitizer.txt",
                    "triggered": bool(w.get("fix_crashed")),
                }
            )
        rec["sanitizer_reports"] = reports
        stats["attached"] += 1

        clean_fix = w.get("fix_ran") and not w.get("fix_crashed")
        rec["differential_complete"] = bool(clean_fix)

        # Localize the SINK link from the crash site; the 190 middle link is localized
        # separately by the UBSan rebuild (infra/mac/ubsan_rebuild.sh).
        site = w.get("crash_site")
        if site:
            m = re.match(r"(.+?):(\d+)", site)
            if m:
                ev = chain[-1].get("evidence") or {}
                ev["location"] = {
                    "file": m.group(1),
                    "line": int(m.group(2)),
                    "function": w.get("crash_function"),
                    "stage": "crash",
                }
                ev["sanitizer_report_ref"] = reports[0]["log_ref"]
                chain[-1]["evidence"] = ev
                stats["localized"] += 1

        if not clean_fix:
            # Vulnerable fires but the patch does not silence it: not a clean differential,
            # so this stays SILVER instead of being counted as a reproduced fix.
            stats["dirty_pair"] += 1
            continue
        if (rec.get("label_confidence_tier") or "").lower() != "gold" and rec.get("patch_diff"):
            rec["label_confidence_tier"] = "gold"
            stats["promoted"] += 1

    with open(args.out, "w") as fh:
        for rec in rows:
            fh.write(json.dumps(rec) + "\n")
    for k, v in stats.items():
        print(f"  {k}: {v}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
