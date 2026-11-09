#!/usr/bin/env python3
"""Score the exploratory AI raters (PREREGISTRATION, PR-9 entry of 2026-11-05).

Each AI sheet under data/irr/ai/<model>/sheet.csv is scored exactly like a human sheet: label
precision against the audit snapshot (irr.precision), root-site precision per root site kind on
the Reproduced tier (irr.location_precision), the same population-weighted pooled figure the paper
reports for humans, and agreement (raw, Cohen's kappa, Gwet's AC1) with every human sheet in
data/irr/returned/. Human sheets are never modified, and AI sheets never enter the human figures.

Writes paper_artifacts/irr_ai.json. Usage: score_ai_raters.py [--ai data/irr/ai]
"""

from __future__ import annotations

import argparse
import csv
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent))
import irr  # noqa: E402
from score_audit import population  # noqa: E402


def load(p: Path) -> list[dict]:
    with open(p) as fh:
        return list(csv.DictReader(fh))


def pooled(loc: dict, pop: dict) -> float | None:
    ks = [k for k in ("tested-repair-site", "origin-site", "annotated-site") if k in loc]
    tot = sum(pop.get(k, 0) for k in ks)
    if not tot:
        return None
    return round(sum(pop.get(k, 0) / tot * loc[k]["strict"]["value"] for k in ks), 3)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--ai", default="data/irr/ai")
    ap.add_argument("--returned", default="data/irr/returned")
    ap.add_argument("--sample", default="data/irr/sample.json")
    ap.add_argument("--out", default="paper_artifacts/irr_ai.json")
    a = ap.parse_args(argv)
    sheets = sorted(Path(a.ai).glob("*/sheet.csv"))
    out = Path(a.out)
    if not sheets:
        out.unlink(missing_ok=True)
        print("no AI sheet")
        return 0
    picked = json.loads(Path(a.sample).read_text())
    with open("data/release/dataset.jsonl") as fh:
        current = {r["id"]: r for r in map(json.loads, fh)}
    snap = json.loads(Path("data/irr/snapshot.json").read_text())
    pop = population(snap)
    humans = {
        p.stem.removeprefix("sheet_"): load(p) for p in sorted(Path(a.returned).glob("sheet_*.csv"))
    }
    result = {"gold_population": pop, "models": {}}
    for p in sheets:
        sheet = load(p)
        raw = p.parent / "raw.jsonl"
        recs = [json.loads(x) for x in raw.read_text().splitlines()] if raw.exists() else []
        finals = [r for r in recs if r.get("final")]
        loc = irr.location_precision(sheet, picked, gold=True)
        result["models"][p.parent.name] = {
            "answered": len(sheet),
            "invalid_after_retry": sum(1 for r in finals if not r.get("valid")),
            "models_reported": sorted({r.get("model_reported", "") for r in finals} - {""}),
            "precision": irr.precision(sheet, picked, current),
            "location_gold": loc,
            "pooled_strict": pooled(loc, pop),
            "agreement_with": {h: irr.score(sheet, s) for h, s in humans.items()},
        }
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(result, indent=1) + "\n")
    print(f"{len(sheets)} AI sheet(s) scored -> {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
