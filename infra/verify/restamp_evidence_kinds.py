#!/usr/bin/env python3
"""Re-derive every link's `evidence_kind` and `cwe_basis`, and every record's `evidence_floor`
and `chain_kind`, from its evidence (cwe_basis is not logged per record: it is a pure function of
the evidence and the provenance).

`classify_link` once fell back to EXECUTION for a bare sanitizer reference with no site, which
its own comment rules out: a log that is not attributed to a site witnesses that the run
crashed, not where this link is. The fallback is gone (2026-10-20). Stored kinds were written by
whichever step last touched a record, so this recomputes them all; a record whose tier depends
on a kind (PR-3 I4) is re-tiered by chainforge.integrity, in either direction. Every change is
logged. Run from rebuild_derived.sh; idempotent.

One repair rides along, from the archived log only: a kernel intermediate whose KASAN report
names the accessing function ("BUG: KASAN: use-after-free in <fn>") but whose link carries no
location gets that function as its site, since the report is the site at function granularity.

Usage: restamp_evidence_kinds.py [--release data/release]
"""

from __future__ import annotations

import argparse
import collections
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))
from chainforge.evidence import (  # noqa: E402
    C_KEYWORDS,
    chain_kind,
    classify_link,
    cwe_basis,
    floor,
    site_kind,
)
from chainforge.integrity import gold_violations, tier_for  # noqa: E402

_KASAN = re.compile(r"BUG: KASAN: ([\w-]+) (?:\w+ )?in (\w+)")


def kasan_site(link: dict) -> dict | None:
    ev = link.get("evidence") or {}
    ref = ev.get("sanitizer_report_ref") or ""
    if not ref.endswith(".kasan.txt") or (ev.get("location") or {}).get("function"):
        return None
    p = Path(ref)
    m = _KASAN.search(p.read_text(errors="replace")) if p.is_file() else None
    if not m:
        return None
    return {
        "file": None,
        "line": None,
        "function": m.group(2),
        "stage": f"KASAN {m.group(1)} report names the accessing function",
    }


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--release", default="data/release")
    args = ap.parse_args(argv)
    rel = Path(args.release)
    with open(rel / "dataset.jsonl") as fh:
        rows = [json.loads(line) for line in fh]
    log, stats = [], collections.Counter()
    for r in rows:
        changes = []
        for i, link in enumerate(r.get("chain") or []):
            loc = (link.get("evidence") or {}).get("location") or {}
            if loc.get("function") in C_KEYWORDS:
                changes.append(f"link {i}: function {loc['function']!r} is a statement, dropped")
                loc["function"] = None
            if link.get("role") == "intermediate":
                site = kasan_site(link)
                if site:
                    link["evidence"]["location"] = site
                    changes.append(f"link {i}: site from KASAN report ({site['function']})")
            kind = str(classify_link(link.get("evidence")))
            if link.get("evidence_kind") != kind:
                changes.append(
                    f"link {i} ({link.get('role')}): {link.get('evidence_kind')} -> {kind}"
                )
                link["evidence_kind"] = kind
        for link in r.get("chain") or []:
            link["cwe_basis"] = cwe_basis(link, r.get("provenance") or "")
            link["site_kind"] = site_kind(link, r.get("provenance") or "")
        kind = chain_kind([link["cwe_id"] for link in r.get("chain") or []])
        if r.get("chain_kind") != kind:
            changes.append(f"chain_kind {r.get('chain_kind')} -> {kind}")
            r["chain_kind"] = kind
        fl = str(floor(r))
        if r.get("evidence_floor") != fl:
            changes.append(f"floor {r.get('evidence_floor')} -> {fl}")
            r["evidence_floor"] = fl
        if not changes:
            continue
        entry = {"id": r["id"], "op": "evidence-kind-restamp", "changes": changes}
        stats["records changed"] += 1
        if r["label_confidence_tier"] in ("gold", "silver"):
            v = gold_violations(r, Path("."))
            new = tier_for(r, v)
            if new != r["label_confidence_tier"]:
                entry.update({"from": r["label_confidence_tier"], "to": new, "rules": v})
                stats[f"retier {r['label_confidence_tier']} -> {new}"] += 1
                r["label_confidence_tier"] = new
            if v:
                r["gold_contract_gaps"] = v
            else:
                r.pop("gold_contract_gaps", None)
        log.append(entry)
    with open(rel / "dataset.jsonl", "w") as fh:
        fh.writelines(json.dumps(r) + "\n" for r in rows)
    with open(rel / "corrections_changelog.jsonl", "a") as fh:
        fh.writelines(json.dumps(e) + "\n" for e in log)
    print(dict(stats))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
