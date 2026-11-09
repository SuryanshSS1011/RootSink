#!/usr/bin/env python3
"""Attach our own two-sided kernel runs (cse-kvm/kdiff_kvm.sh) to syzbot records, then re-tier.

For each `<kdiff_out>/<extid>/differential.json`:
  - every outcome is recorded in the changelog, including failures (R10: a non-reproduction is
    a result, and "could not test" is kept distinct from "did not crash");
  - a `differential` outcome archives the evidence and adds OUR reports beside upstream's:
      data/evidence/kernel/<extid>/vul.kasan.txt   the KASAN report at fix^ (tracked)
      data/evidence/kernel/<extid>/fixN.tail.txt   banner, env-up line and tail of each patched
                                                   boot, which show the reproducer ran (tracked)
      data/evidence/kernel/<extid>/repro.c, kernel.config, differential.json   (tracked)
      data/evidence_full/kernel/<extid>/*.console.log.gz   full consoles (Zenodo, not git)
  - the record is re-tiered by chainforge.integrity, the same rules conformance enforces.

Usage: attach_kernel_differentials.py <kdiff_out_dir> [--release data/release]
"""

from __future__ import annotations

import argparse
import collections
import gzip
import json
import re
import shutil
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))
from chainforge.evidence import classify_link, floor  # noqa: E402
from chainforge.integrity import (  # noqa: E402
    crash_facts,
    gold_violations,
    kasan_same_bug,
    tier_for,
)

EVID = Path("data/evidence/kernel")
FULL = Path("data/evidence_full/kernel")
# The serial console carries terminal escapes from the firmware; excerpts are for reading.
_ESC = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]|\x1bc|[\x00-\x08\x0b-\x1f]")


def clean(text: str) -> str:
    return _ESC.sub("", text)


def kasan_excerpt(console: str, signature: str = "", access: str = "") -> str:
    """The KASAN report the harness matched: with kasan_multi_shot a console can hold several,
    and the first is not necessarily the syzbot bug (hci_send_acl READ before the matched
    __hci_acl_create_connection_sync WRITE)."""
    lines = console.splitlines()
    reports = [i for i, ln in enumerate(lines) if "BUG: KASAN:" in ln]

    def same_access(i: int) -> bool:  # several reports in one function: syzbot's was this access
        return not access or any(
            re.search(rf"\b{access} of size", ln, re.I) for ln in lines[i + 1 : i + 3]
        )

    matched = kasan_same_bug(lines, signature)
    start = next(
        (i for i in matched if same_access(i)), matched[0] if matched else (reports or [None])[0]
    )
    if start is None:
        return ""
    out = []
    for ln in lines[start : start + 400]:
        out.append(ln)
        if len(out) > 3 and re.search(r"={20,}\s*$", ln):
            break
    head = next((ln for ln in lines if "Linux version" in ln), "")
    return "\n".join([head, *lines[max(0, start - 2) : start], *out]) + "\n"


def run_tail(console: str) -> str:
    lines = console.splitlines()
    keep = [ln for ln in lines if "Linux version" in ln or "[init] environment up" in ln]
    return "\n".join([*keep, "...", *lines[-40:]]) + "\n"


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("kdiff_out")
    ap.add_argument("--release", default="data/release")
    args = ap.parse_args(argv)
    rel = Path(args.release)
    with open(rel / "dataset.jsonl") as fh:
        rows = [json.loads(line) for line in fh]
    by_extid = collections.defaultdict(list)
    for r in rows:
        for a in r.get("aliases") or []:
            if a.startswith("syzbot-"):
                by_extid[a[7:]].append(r)

    log, stats = [], collections.Counter()
    with open(rel / "corrections_changelog.jsonl") as fh:
        seen = {
            (e["id"], e.get("status"))
            for e in map(json.loads, fh)
            if e.get("op") == "kernel-differential-attempt"
        }
    for dj in sorted(Path(args.kdiff_out).glob("*/differential.json")):
        d = json.loads(dj.read_text())
        extid, status = d["extid"], d["status"]
        recs = by_extid.get(extid, [])
        stats[status] += 1
        for r in recs:
            if (r["id"], status) in seen:
                continue
            log.append(
                {
                    "id": r["id"],
                    "op": "kernel-differential-attempt",
                    "status": status,
                    "detail": d.get("detail"),
                    "vulnerable_commit": d.get("vulnerable_commit"),
                    "fix_commit": d.get("fix_commit"),
                }
            )
        if status != "differential" or not recs:
            continue
        src, ev, full = dj.parent, EVID / extid, FULL / extid
        ev.mkdir(parents=True, exist_ok=True)
        full.mkdir(parents=True, exist_ok=True)
        vul = clean((src / "vul.console.log").read_text(errors="replace"))
        access = {787: "Write", 125: "Read"}.get(recs[0]["chain"][-1]["cwe_id"], "")
        (ev / "vul.kasan.txt").write_text(
            kasan_excerpt(vul, d.get("expected_signature") or "", access)
        )
        fixes = sorted(src.glob("fix[0-9].console.log"))
        for f in fixes:
            (ev / f.name.replace(".console.log", ".tail.txt")).write_text(
                run_tail(clean(f.read_text(errors="replace")))
            )
        for name in ("repro.c", "kernel.config", "differential.json"):
            shutil.copy(src / name, ev / name)
        for f in src.glob("*.console.log"):
            with open(f, "rb") as i, gzip.open(full / (f.name + ".gz"), "wb") as o:
                shutil.copyfileobj(i, o)

        for r in recs:
            reps = [
                s for s in r.get("sanitizer_reports") or [] if s.get("observed_by") == "upstream"
            ]
            reps.append(
                {
                    "revision": "vulnerable",
                    "sanitizer": "kasan",
                    "triggered": True,
                    "observed_by": "self",
                    "log_ref": str(ev / "vul.kasan.txt"),
                }
            )
            for f in fixes:
                reps.append(
                    {
                        "revision": "patched",
                        "sanitizer": "kasan",
                        "triggered": False,
                        "observed_by": "self",
                        "log_ref": str(ev / f.name.replace(".console.log", ".tail.txt")),
                    }
                )
            r["sanitizer_reports"] = reps
            # PR-5: in a race -> use-after-free -> access chain, our own KASAN use-after-free
            # report (alloc, free and use stacks) execution-witnesses the CWE-416 intermediate.
            chain = r["chain"]
            kasan = ev / "vul.kasan.txt"
            if (
                len(chain) == 3
                and chain[1]["cwe_id"] == 416
                and "use-after-free" in (crash_facts(kasan.read_text()).get("class") or "")
            ):
                chain[1].setdefault("evidence", {})["sanitizer_report_ref"] = str(kasan)
                for link in chain:
                    link["evidence_kind"] = str(classify_link(link.get("evidence")))
                r["evidence_floor"] = str(floor(r))
            r["differential_complete"] = True
            r["pov_input"] = str(ev / "repro.c")
            r["commit_range"] = {
                **(r.get("commit_range") or {}),
                "vulnerable_tested": d["vulnerable_commit"],
            }
            v = gold_violations(r, Path("."))
            new = tier_for(r, v)
            if new != r["label_confidence_tier"]:
                log.append(
                    {
                        "id": r["id"],
                        "op": "kernel-differential-retier",
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
