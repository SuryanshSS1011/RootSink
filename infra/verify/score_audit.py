#!/usr/bin/env python3
"""Score every returned audit sheet (PR-9) against its snapshot, for the paper's macros.

Reads data/irr/returned/sheet_<initials>.csv and data/irr/sample.json (the snapshot sample) and
writes paper_artifacts/irr_precision.json: each rater's `irr.py precision` result, keyed by
initials, plus the eligible GOLD population per root site kind at the snapshot, which PR-9 uses
to reweight any figure pooled over GOLD. With two sheets it also writes
paper_artifacts/irr_agreement.json (`irr.py score`: raw agreement, Cohen's kappa, Gwet's AC1).
With no sheet it writes nothing, and the paper says the audit has no result yet.

Usage: score_audit.py [--returned data/irr/returned] [--sample data/irr/sample.json]
"""

from __future__ import annotations

import argparse
import collections
import csv
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parents[1] / "src"))
import irr  # noqa: E402

POPULATION_CACHE = Path("data/irr/snapshot_population.json")


def population(snap: dict) -> dict[str, int]:
    """GOLD root site kinds among records the sample could draw (archived vulnerable report and a
    located root), from data/irr/snapshot_population.json. The snapshot is a past state of the
    dataset, so the counts never change; they were taken once from that state and are keyed by the
    date the sample was drawn, which the public release can check."""
    cached = json.loads(POPULATION_CACHE.read_text())
    if cached["drawn"] != snap["drawn"]:
        raise SystemExit(f"{POPULATION_CACHE} is for {cached['drawn']}, not {snap['drawn']}")
    return cached["population"]


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--returned", default="data/irr/returned")
    ap.add_argument("--sample", default="data/irr/sample.json")
    ap.add_argument("--out", default="paper_artifacts")
    args = ap.parse_args(argv)
    # Raters in the order their sheets came back (raters.json "returned"), so the first rater's
    # figures do not change when a second sheet arrives; a sheet without an entry goes last.
    meta_p = Path(args.returned) / "raters.json"
    meta = json.loads(meta_p.read_text()) if meta_p.is_file() else {}
    sheets = sorted(
        Path(args.returned).glob("sheet_*.csv"),
        key=lambda p: (meta.get(p.stem.removeprefix("sheet_"), {}).get("returned", "9999"), p.name),
    )
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    if not sheets:
        for f in ("irr_precision.json", "irr_agreement.json"):
            (out / f).unlink(missing_ok=True)
        print("no returned sheet")
        return 0
    picked = json.loads(Path(args.sample).read_text())
    with open("data/release/dataset.jsonl") as fh:
        current = {r["id"]: r for r in map(json.loads, fh)}
    snap = json.loads(Path("data/irr/snapshot.json").read_text())
    pop_now: collections.Counter = collections.Counter()
    for r in current.values():  # the same population, as the current release stands
        if r["label_confidence_tier"] == "gold" and irr._vul_log(r):
            t = irr.truth(r)
            if t["root_fn"]:
                pop_now[t["root_kind"]] += 1
    result = {
        "order": [p.stem.removeprefix("sheet_") for p in sheets],
        "raters": {},
        "gold_population": population(snap),
        "gold_population_current": dict(pop_now),
    }
    for p in sheets:
        with open(p) as fh:
            sheet = list(csv.DictReader(fh))
        result["raters"][p.stem.removeprefix("sheet_")] = irr.precision(sheet, picked, current)
    (out / "irr_precision.json").write_text(json.dumps(result, indent=1) + "\n")
    if len(sheets) >= 2:
        load = [list(csv.DictReader(open(p))) for p in sheets[:2]]  # noqa: SIM115
        agree = {"raters": result["order"][:2]} | irr.score(*load)
        agree["source_site_detail"] = irr.site_detail(*load, picked)  # added 2026-11-08
        (out / "irr_agreement.json").write_text(json.dumps(agree, indent=1) + "\n")
    else:
        (out / "irr_agreement.json").unlink(missing_ok=True)
    print(f"{len(sheets)} sheet(s) scored -> {out / 'irr_precision.json'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
