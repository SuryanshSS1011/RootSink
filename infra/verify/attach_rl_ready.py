#!/usr/bin/env python3
"""PREREGISTRATION PR-12: stamp `rl_ready` from the runner's scoring of each ARVO case.

Input: merged output of the runner's `score` workflow on data/validation/pr12_supply.json
(`<out>/<arvo id>/{smoke.json, nopatch/result.json, devfix/result.json}`). For every record of a
scored case:

  rl_ready = True   the unmodified vulnerable build scored `crash` AND the developer's fix scored
                    `pass` (every replay read the input to completion with no report);
  rl_ready = False  any other pair of scored outcomes (kept in rl_scoring);
  rl_ready = None   not scored, the fix diff could not be fetched, or either side was `not_run`
                    (infrastructure, R10): listed for retry, never scored.

The flag changes nothing else in the record. Small result files are archived under
data/evidence/score/<arvo id>/; the funnel is written to data/validation/pr12_funnel.json, and
the cases owed a retry to data/validation/pr12_retry.json.

Usage: attach_rl_ready.py <score_out_dir>... [--release data/release]
"""

from __future__ import annotations

import argparse
import collections
import json
import shutil
from pathlib import Path

EVID = Path("data/evidence/score")


def outcome(case_dir: Path) -> dict | None:
    """The scored pair for one case, or None if this directory holds no usable scoring."""
    smoke = case_dir / "smoke.json"
    if not smoke.is_file():
        return None
    s = json.loads(smoke.read_text())
    if s.get("status") == "diff_unfetchable":
        return {"nopatch": None, "devfix": None, "infra": "fix diff unfetchable"}
    out = {"nopatch": s.get("nopatch"), "devfix": s.get("devfix")}
    dev = case_dir / "devfix" / "result.json"
    if dev.is_file():
        d = json.loads(dev.read_text())
        out["resources"] = d.get("resources")
        if d.get("apply"):
            out["apply"] = d["apply"]
    # Seed-corpus coverage of the unpatched and the developer-fixed builds (libFuzzer only).
    for side in ("nopatch", "devfix"):
        c = s.get(f"corpus_{side}") or {}
        if c.get("ft"):
            out.setdefault("corpus", {})[f"{side}_ft"] = c["ft"]
            out["corpus"]["inputs"] = c.get("inputs")
    if "not_run" in (out["nopatch"], out["devfix"]) or None in (out["nopatch"], out["devfix"]):
        out["infra"] = "a side never reached the input"
    return out


def verdict(o: dict | None) -> bool | None:
    if not o or o.get("infra"):
        return None
    # The developer's fix must apply with its context intact (PR-12 amendment, 2026-10-22): a
    # fuzzed application may have placed a hunk elsewhere, so it does not verify the scorer.
    strict = ((o.get("apply") or {}).get("fuzz") or 0) == 0
    return o["nopatch"] == "crash" and o["devfix"] == "pass" and strict


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("out", nargs="+", help="score output dirs; a later dir wins unless it is infra")
    ap.add_argument("--release", default="data/release")
    args = ap.parse_args(argv)
    rel = Path(args.release)
    # Every supply scored so far (PR-12 and its dated second supply). A case covers every record
    # whose vulnerable image is that ARVO case, including records admitted after the supply.
    supply = []
    for f in ("data/validation/pr12_supply.json", "data/validation/pr12_supply2.json"):
        if Path(f).is_file():
            supply += json.loads(Path(f).read_text())["cases"]

    scored: dict[str, tuple[Path, dict]] = {}
    for d in map(Path, args.out):
        for c in supply:
            o = outcome(d / c["arvo_id"])
            old = scored.get(c["arvo_id"])
            if o and (old is None or not o.get("infra") or old[1].get("infra")):
                scored[c["arvo_id"]] = (d / c["arvo_id"], o)
    if not scored:
        raise SystemExit("no scored case under the given directories; nothing written")

    with open(rel / "dataset.jsonl") as fh:
        rows = [json.loads(line) for line in fh]
    by_id = {r["id"]: r for r in rows}
    by_arvo = collections.defaultdict(list)
    for r in rows:
        img = ((r.get("docker_image_ref") or {}).get("vulnerable") or "").split("@")[0]
        if img.startswith("n132/arvo:"):
            by_arvo[img.split(":")[1].removesuffix("-vul")].append(r["id"])
    funnel, pairs, retry, log = collections.Counter(), collections.Counter(), [], []
    by_tier = collections.Counter()
    for c in supply:
        d, o = scored.get(c["arvo_id"], (None, None))
        v = verdict(o)
        funnel["supplied"] += 1
        if o is None or o.get("infra"):
            funnel["not scored (infrastructure; retry)"] += 1
            retry.append(c | {"why": (o or {}).get("infra", "no scoring result")})
        else:
            funnel["scored"] += 1
            funnel["rl_ready" if v else "not rl_ready"] += 1
            ap = o.get("apply") or {}
            fz = " (fuzzed)" if (ap.get("fuzz") or 0) > 0 else ""
            pairs[f"{o['nopatch']}/{o['devfix']}{fz}"] += 1
            if ap:
                funnel[f"developer fix applied {ap.get('mode')}, fuzz {ap.get('fuzz')}"] += 1
            dst = EVID / c["arvo_id"]
            dst.mkdir(parents=True, exist_ok=True)
            shutil.copy(d / "smoke.json", dst / "smoke.json")
            for side in ("nopatch", "devfix"):
                if (d / side / "result.json").is_file():
                    shutil.copy(d / side / "result.json", dst / f"{side}.result.json")
        for rid in sorted(set(c["records"]) | set(by_arvo.get(c["arvo_id"], ()))):
            r = by_id.get(rid)
            if r is None:
                continue
            before = r.get("rl_ready")
            if o is None or o.get("infra"):
                if before is None:
                    r["rl_ready"] = None
                continue  # an infrastructure outcome never overwrites a scored verdict
            r["rl_ready"] = v
            r["rl_scoring"] = {
                "rule": "PR-12",
                "nopatch": o["nopatch"],
                "devfix": o["devfix"],
                "evidence": str(EVID / c["arvo_id"]),
                **(o.get("resources") or {}),
                **({"corpus": o["corpus"]} if o.get("corpus") else {}),
                **({"devfix_apply": o["apply"]} if o.get("apply") else {}),
            }
            by_tier[(r["label_confidence_tier"], v)] += 1
            if before != v:
                log.append({"id": rid, "op": "PR12-rl-ready", "rl_ready": v})

    with open(rel / "dataset.jsonl", "w") as fh:
        fh.writelines(json.dumps(r) + "\n" for r in rows)
    with open(rel / "corrections_changelog.jsonl", "a") as fh:
        fh.writelines(json.dumps(e) + "\n" for e in log)
    report = {
        "rule": "PREREGISTRATION PR-12",
        "funnel": dict(funnel),
        "outcome_pairs": dict(pairs.most_common()),
        "records_by_tier": {
            f"{t} {'ready' if v else 'not ready'}": n for (t, v), n in by_tier.items()
        },
    }
    Path("data/validation/pr12_funnel.json").write_text(json.dumps(report, indent=1))
    Path("data/validation/pr12_retry.json").write_text(json.dumps({"cases": retry}, indent=1))
    print(json.dumps(report, indent=1))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
