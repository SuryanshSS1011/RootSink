#!/usr/bin/env python3
"""Attach UBSan rebuild witnesses (chainforge-runner `ubsan` workflow) to CWE-190 links.

Each case was rebuilt from the ARVO image's own source with SANITIZER=undefined at BOTH
revisions and its PoV replayed directly (ubsan_rebuild.sh). Per the length-3 rule (decided
2026-08-04) and PR-1, a CWE-190 link is execution-witnessed when:
  - the vulnerable rebuild is conclusive (built, no suspected OOM) and reports an integer
    overflow in application code (fuzzer / sanitizer runtime frames are not the program), and
  - the fixed rebuild is conclusive and reports nothing at that same file:line.
The UBSan logs are archived under data/evidence/arvo/<id>/ubsan.{vul,fix}.txt; the link gets the
site and the log, and every touched record is re-tiered by chainforge.integrity. Every outcome
is logged, including inconclusive builds (R10: a build that never finished is not a negative).

Usage: attach_ubsan_witness.py <ubsan_out_dir> [--release data/release]
"""

from __future__ import annotations

import argparse
import collections
import json
import re
import shutil
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))
from chainforge.evidence import classify_link, floor, normalize_path  # noqa: E402
from chainforge.integrity import gold_violations, tier_for  # noqa: E402

_RUNTIME = re.compile(r"compiler-rt|llvm-project|libfuzzer|/fuzzer/Fuzzer|sanitizer", re.I)
EVID = Path("data/evidence/arvo")


def side(root: Path, aid: str, s: str) -> dict | None:
    p = root / aid / s / "result.json"
    return json.loads(p.read_text()) if p.is_file() else None


def verdict(vul: dict | None, fix: dict | None) -> tuple[str, dict | None]:
    if not vul or not fix:
        return "missing side", None
    if not (vul.get("conclusive") and fix.get("conclusive")):
        return "inconclusive build", None
    overflow = [
        f
        for f in vul.get("findings") or []
        if "overflow" in f.get("kind", "") and not _RUNTIME.search(f.get("file", ""))
    ]
    if not overflow:
        return "no application overflow at vul", None
    fixed_sites = {(normalize_path(f["file"]), f["line"]) for f in fix.get("findings") or []}
    for f in overflow:
        if (normalize_path(f["file"]), f["line"]) not in fixed_sites:
            return "witnessed", f
    return "overflow persists at fix", None


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("ubsan_out")
    ap.add_argument("--release", default="data/release")
    args = ap.parse_args(argv)
    root, rel = Path(args.ubsan_out), Path(args.release)
    with open(rel / "dataset.jsonl") as fh:
        rows = [json.loads(line) for line in fh]
    by_aid = collections.defaultdict(list)
    for r in rows:
        for a in r.get("aliases") or []:
            if a.startswith("OSS-Fuzz-"):
                by_aid[a[9:]].append(r)

    log, stats = [], collections.Counter()
    for d in sorted(p for p in root.iterdir() if p.is_dir()):
        aid = d.name
        status, finding = verdict(side(root, aid, "vul"), side(root, aid, "fix"))
        stats[status] += 1
        recs = [r for r in by_aid.get(aid, []) if any(c["cwe_id"] == 190 for c in r["chain"])]
        for r in recs:
            log.append(
                {
                    "id": r["id"],
                    "op": "ubsan-attempt",
                    "status": status,
                    "site": finding and f"{finding['file']}:{finding['line']}",
                }
            )
        if status != "witnessed" or not recs:
            continue
        ev_dir = EVID / aid
        ev_dir.mkdir(parents=True, exist_ok=True)
        for s in ("vul", "fix"):
            src = d / s / "ubsan.txt"
            if src.is_file():
                shutil.copy(src, ev_dir / f"ubsan.{s}.txt")
        for r in recs:
            link = next(c for c in r["chain"] if c["cwe_id"] == 190)
            ev = link.setdefault("evidence", {})
            ev["sanitizer_report_ref"] = str(ev_dir / "ubsan.vul.txt")
            ev["location"] = {
                "file": finding["file"],
                "line": finding["line"],
                "function": finding.get("function"),
                "stage": "UBSan rebuild, vulnerable revision; absent at fix",
            }
            # The fixed-side log shows THIS overflow is gone; it is not a replay of the sink, so it
            # sits on the link, not among the patched reports I5 judges (an unrelated UBSan
            # finding elsewhere in the fixed build must not be read as the sink crashing).
            ev["absent_at_fix_ref"] = str(ev_dir / "ubsan.fix.txt")
            reps = r.setdefault("sanitizer_reports", [])
            if not any(s.get("sanitizer") == "ubsan" for s in reps):
                reps.append(
                    {
                        "revision": "vulnerable",
                        "sanitizer": "ubsan",
                        "triggered": True,
                        "observed_by": "self",
                        "log_ref": str(ev_dir / "ubsan.vul.txt"),
                        "witnesses": "intermediate",
                    }
                )
            for c in r["chain"]:
                c["evidence_kind"] = str(classify_link(c.get("evidence")))
            r["evidence_floor"] = str(floor(r))
            if r["label_confidence_tier"] in ("silver", "gold"):
                v = gold_violations(r, Path("."))
                new = tier_for(r, v)
                if new != r["label_confidence_tier"]:
                    log.append(
                        {
                            "id": r["id"],
                            "op": "ubsan-retier",
                            "from": r["label_confidence_tier"],
                            "to": new,
                            "rules": v,
                        }
                    )
                    stats[f"retier {r['label_confidence_tier']} -> {new}"] += 1
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
