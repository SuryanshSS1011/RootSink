#!/usr/bin/env python3
"""PREREGISTRATION PR-10: admit execution-witnessed length-3 views of GOLD length-2 chains.

Input is the merged output of the runner's `ubsan` workflow on `data/validation/pr10_supply.json`
(`<out>/<arvo_id>/{vul,fix}/result.json` and `ubsan.txt`). For each supplied case:

  1. `attach_ubsan_witness.verdict` decides, unchanged: both builds conclusive, and an integer
     overflow in application code at the vulnerable revision whose file:line is absent at the fix;
  2. PR-10's added requirement: that overflow's file is in our own vulnerable crash stack or among
     the non-test files the developer's fix changes;
  3. the view [source -> CWE-190 -> sink] must be admissible (PR-5).

A case passing all three becomes a NEW record cross-linked to its length-2 record, which is left
unchanged. Its source and sink links are copied with their evidence; the CWE-190 link carries the
UBSan site and both logs. It shares the length-2 record's split and duplicate group. The tier is
whatever `integrity.py` assigns. Every supplied case is logged with the step it stopped at, and
the funnel is written to data/validation/pr10_funnel.json.

Usage: admit_len3_views.py <ubsan_out_dir> [--release data/release]
       [--supply data/validation/pr10_supply2.json --funnel data/validation/pr10_funnel2.json]
"""

from __future__ import annotations

import argparse
import collections
import copy
import json
import re
import shutil
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent))
from apply_pr4 import mitre  # noqa: E402
from attach_ubsan_witness import side, verdict  # noqa: E402
from backfill_functions import frames  # noqa: E402

from chainforge.cwe import validate_chain  # noqa: E402
from chainforge.evidence import (  # noqa: E402
    chain_kind,
    classify_link,
    floor,
    is_non_guard_path,
    locality,
    same_file,
)
from chainforge.integrity import gold_violations, tier_for, vul_log  # noqa: E402

RULE = "PR-10"
EVID = Path("data/evidence/arvo")
_FILE_HDR = re.compile(r"^diff --git a/\S+ b/(\S+)", re.M)


def tied_to_chain(rec: dict, finding: dict) -> str | None:
    """Why the overflow belongs to this chain, or None if it does not (PR-10 added requirement)."""
    p = vul_log(rec, Path("."))
    stack = frames(p.read_text(errors="replace")) if p else []
    if any(same_file(f, finding["file"]) for _, f, _ in stack):
        return "overflow file is in our vulnerable crash stack"
    fixed = [f for f in _FILE_HDR.findall(rec.get("patch_diff") or "") if not is_non_guard_path(f)]
    if any(same_file(f, finding["file"]) for f in fixed):
        return "overflow file is changed by the developer's fix"
    return None


def view_id(aid: str) -> str:
    return f"CHAINFORGE-3{int(aid):010d}"


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("ubsan_out")
    ap.add_argument("--release", default="data/release")
    ap.add_argument(
        "--supply",
        default="data/validation/pr10_supply.json",
        help="the supply list (PR-10's first, or the second supply of 2026-10-20)",
    )
    ap.add_argument("--funnel", default="data/validation/pr10_funnel.json")
    args = ap.parse_args(argv)
    root, rel = Path(args.ubsan_out), Path(args.release)
    supply = json.loads(Path(args.supply).read_text())["supply"]
    with open(rel / "dataset.jsonl") as fh:
        rows = [json.loads(line) for line in fh]
    by_id = {r["id"]: r for r in rows}

    have = sum((root / c["arvo_id"] / "vul" / "result.json").is_file() for c in supply)
    if have == 0:
        # A wrong or empty output directory must not write "missing side" for every case.
        sys.exit(f"no supplied case has results under {root}; nothing written")

    log, funnel, new = [], collections.Counter(), []
    for case in supply:
        aid = case["arvo_id"]
        funnel["supplied"] += 1
        status, finding = verdict(side(root, aid, "vul"), side(root, aid, "fix"))
        step = status
        if status == "witnessed":
            funnel["overflow at vulnerable, absent at fix"] += 1
        for rid in case["records"]:
            base = by_id.get(rid)
            if not base or base["label_confidence_tier"] != "gold" or len(base["chain"]) != 2:
                step = "length-2 record no longer GOLD"
            elif status == "witnessed":
                why = tied_to_chain(base, finding)
                cwes = [base["chain"][0]["cwe_id"], 190, base["chain"][-1]["cwe_id"]]
                if not why:
                    step = "overflow not tied to this chain"
                elif not validate_chain(cwes).admissible:
                    step = "view inadmissible"
                elif view_id(aid) in by_id:
                    step = "view already present"
                else:
                    step = "admitted"
                    ev_dir = EVID / aid
                    ev_dir.mkdir(parents=True, exist_ok=True)
                    for s in ("vul", "fix"):
                        src = root / aid / s / "ubsan.txt"
                        if src.is_file():
                            shutil.copy(src, ev_dir / f"ubsan.{s}.txt")
                    v = copy.deepcopy(base)
                    v["id"] = view_id(aid)
                    mid = {
                        "cwe_id": 190,
                        "role": "intermediate",
                        "evidence": {
                            "dataflow_path": None,
                            "sanitizer_report_ref": str(ev_dir / "ubsan.vul.txt"),
                            "patch_hunk_ref": None,
                            "absent_at_fix_ref": str(ev_dir / "ubsan.fix.txt"),
                            "location": {
                                "file": finding["file"],
                                "line": finding["line"],
                                "function": finding.get("function"),
                                "stage": "UBSan rebuild, vulnerable revision; absent at fix; "
                                + why,
                            },
                        },
                    }
                    v["chain"] = [v["chain"][0], mid, v["chain"][1]]
                    v["chain_string"] = "->".join(f"CWE-{c}" for c in cwes)
                    v["chain_kind"] = chain_kind(cwes)
                    v["mitre_chain"] = mitre(cwes)
                    v["provenance"] = "arvo-len3-exec"
                    v["eval_stratum"] = "length3"
                    v["related_records"] = [rid]
                    v["sanitizer_reports"].append(
                        {
                            "revision": "vulnerable",
                            "sanitizer": "ubsan",
                            "triggered": True,
                            "observed_by": "self",
                            "log_ref": str(ev_dir / "ubsan.vul.txt"),
                            "witnesses": "intermediate",
                        }
                    )
                    for link in v["chain"]:
                        link["evidence_kind"] = str(classify_link(link.get("evidence")))
                    v["evidence_floor"] = str(floor(v))
                    v["locality"] = locality(v)
                    viol = gold_violations(v, Path("."))
                    v["label_confidence_tier"] = tier_for(v, viol)
                    if viol:
                        v["gold_contract_gaps"] = viol
                    else:
                        v.pop("gold_contract_gaps", None)
                    base.setdefault("related_records", []).append(v["id"])
                    new.append(v)
                    by_id[v["id"]] = v
                    funnel[f"admitted as {v['label_confidence_tier']}"] += 1
            if step == "overflow not tied to this chain":
                funnel["overflow not tied to this chain"] += 1
            log.append(
                {
                    "id": rid,
                    "op": "pr10-attempt",
                    "arvo_id": aid,
                    "status": step,
                    "site": finding and f"{finding['file']}:{finding['line']}",
                }
            )
        funnel[f"verdict: {status}"] += 1

    rows.extend(new)
    with open(rel / "dataset.jsonl", "w") as fh:
        fh.writelines(json.dumps(r) + "\n" for r in rows)
    with open(rel / "corrections_changelog.jsonl", "a") as fh:
        fh.writelines(json.dumps(e) + "\n" for e in log)
    Path(args.funnel).write_text(json.dumps(dict(funnel), indent=1))
    for k, n in sorted(funnel.items()):
        print(f"{n:6d}  {k}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
