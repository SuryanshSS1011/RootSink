#!/usr/bin/env python3
"""Apply the build's `oob-direction` correction to ARVO records added after the build ran.

`build_corrected.py` sets the sink of an ARVO chain from its own crash: an out-of-bounds report
that READs is CWE-125 and one that WRITEs is CWE-787 (PR-3 I1, "sink per access direction"). It
ran before the length-3, new-arm and execution-first records joined, so some of those still carry
a CWE-787 sink on a READ crash, which PR-3 I2-sink then demotes. This applies the same correction,
unchanged, to exactly those records:

  * the record's own vulnerable log is an out-of-bounds class (the build's OOB set), with a
    parseable READ or WRITE access, and that direction contradicts a CWE-125/787 sink;
  * the corrected chain must stay admissible (every edge MITRE-grounded or a declared modelling
    edge), or the record is left as it is.

Use-after-free and use-after-poison reports are NOT touched: there the sink question is the PR-2
convention (a CWE-416 link before the sink), not the access direction. Every touched record is
re-tiered by chainforge.integrity and logged as `oob-direction`.

Usage: apply_oob_direction.py [--release data/release] [--dry-run]
"""

from __future__ import annotations

import argparse
import collections
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent))
from apply_pr4 import mitre  # noqa: E402

from chainforge.cwe import ADMISSIBLE_PAIRS  # noqa: E402
from chainforge.evidence import classify_link, floor  # noqa: E402
from chainforge.integrity import crash_facts, gold_violations, tier_for, vul_log  # noqa: E402

OOB = {
    "heap-buffer-overflow",
    "stack-buffer-overflow",
    "global-buffer-overflow",
    "dynamic-stack-buffer-overflow",
}  # exactly build_corrected.OOB


def admissible(chain: list[int]) -> bool:
    edges = mitre(chain)["edges"]
    return all(
        (a, b) in ADMISSIBLE_PAIRS or e["kind"].startswith("mitre")
        for (a, b), e in zip(zip(chain, chain[1:], strict=False), edges, strict=True)
    )


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--release", default="data/release")
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args(argv)
    rel, root = Path(args.release), Path(".")
    with open(rel / "dataset.jsonl") as fh:
        rows = [json.loads(line) for line in fh]

    log, stats = [], collections.Counter()
    for r in rows:
        if r["label_confidence_tier"] not in ("silver", "gold") or "arvo" not in r["provenance"]:
            continue
        p = vul_log(r, root)
        f = crash_facts(p.read_text(errors="replace")) if p else None
        if not f or f.get("class") not in OOB or f.get("access") not in ("READ", "WRITE"):
            continue
        cwes = [c["cwe_id"] for c in r["chain"]]
        want = 125 if f["access"] == "READ" else 787
        if cwes[-1] not in (125, 787) or cwes[-1] == want:
            continue
        new = cwes[:-1] + [want]
        if not admissible(new):
            stats["skipped: corrected chain not admissible"] += 1
            continue
        entry = {
            "id": r["id"],
            "op": "oob-direction",
            "from": r["chain_string"],
            "to": "->".join(f"CWE-{c}" for c in new),
            "access": f["access"],
            "class": f["class"],
        }
        r["chain"][-1]["cwe_id"] = want
        r["chain_string"] = entry["to"]
        r["mitre_chain"] = mitre(new)
        for link in r["chain"]:
            link["evidence_kind"] = str(classify_link(link.get("evidence")))
        r["evidence_floor"] = str(floor(r))
        v = gold_violations(r, root)
        tier = tier_for(r, v)
        if tier != r["label_confidence_tier"]:
            entry.update({"tier_from": r["label_confidence_tier"], "tier_to": tier})
            stats[f"retier {r['label_confidence_tier']} -> {tier}"] += 1
            r["label_confidence_tier"] = tier
        if v:
            r["gold_contract_gaps"] = v
        else:
            r.pop("gold_contract_gaps", None)
        stats["sink corrected"] += 1
        log.append(entry)

    for k, n in sorted(stats.items()):
        print(f"{n:6d}  {k}")
    for e in log:
        print(json.dumps(e))
    if not args.dry_run:
        with open(rel / "dataset.jsonl", "w") as fh:
            fh.writelines(json.dumps(r) + "\n" for r in rows)
        with open(rel / "corrections_changelog.jsonl", "a") as fh:
            fh.writelines(json.dumps(e) + "\n" for e in log)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
