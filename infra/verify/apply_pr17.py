#!/usr/bin/env python3
"""Apply PREREGISTRATION PR-17: map CWE-20 roots to the MITRE-allowed child the check validates.

CWE 4.20 marks CWE-20 DISCOURAGED for mapping real vulnerabilities. For every record whose root
is CWE-20 (or was, `cwe_class: 20`, so the step is idempotent), the check is read from the tested
hunk when the root has a single-hunk test and the hunk can be rebuilt from the record's own diff,
and otherwise from the fix's added lines. `evidence.input_validation_child` names CWE-1285
(index, offset or position) or CWE-1284 (quantity); otherwise the root stays CWE-20, marked
class-level. The original CWE is kept in `cwe_class`, the mapping in `cwe_mapping`, and which
text was read in `cwe_mapping_input`. The chain string and MITRE grounding are recomputed; no
site, evidence or tier changes here (rebuild_derived.sh re-tiers). Logged as `pr17-cwe-map`.

Usage: apply_pr17.py [--release data/release]
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
from locate_tested_sites import tested_hunk  # noqa: E402

from chainforge.evidence import input_validation_child  # noqa: E402

KIND = {1285: "index", 1284: "quantity", None: "class-level"}


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--release", default="data/release")
    args = ap.parse_args(argv)
    rel = Path(args.release)
    with open(rel / "dataset.jsonl") as fh:
        rows = [json.loads(line) for line in fh]
    log, stats = [], collections.Counter()
    for r in rows:
        root = (r.get("chain") or [{}])[0]
        if root.get("cwe_id") != 20 and root.get("cwe_class") != 20:
            continue
        ev = root.get("evidence") or {}
        proof = ev.get("causal_proof") or ev.get("guard_site_proof")
        hunk = tested_hunk(r.get("patch_diff"), proof) if proof else None
        text, source = (hunk, "tested hunk") if hunk else (r.get("patch_diff") or "", "fix")
        child = input_validation_child(text)
        new = child or 20
        mapping = KIND[child]
        stats[f"{r['label_confidence_tier']} {mapping} ({source})"] += 1
        if (
            root.get("cwe_id") == new
            and root.get("cwe_mapping") == mapping
            and root.get("cwe_class") == 20
        ):
            continue
        old = r["chain_string"]
        root["cwe_class"] = 20
        root["cwe_id"] = new
        root["cwe_mapping"] = mapping
        root["cwe_mapping_input"] = source
        cwes = [link["cwe_id"] for link in r["chain"]]
        r["chain_string"] = "->".join(f"CWE-{c}" for c in cwes)
        r["mitre_chain"] = mitre(cwes)
        if r["chain_string"] != old or mapping == "class-level":
            log.append(
                {
                    "id": r["id"],
                    "op": "pr17-cwe-map",
                    "from": old,
                    "to": r["chain_string"],
                    "mapping": mapping,
                    "input": source,
                }
            )
    with open(rel / "dataset.jsonl", "w") as fh:
        fh.writelines(json.dumps(r) + "\n" for r in rows)
    with open(rel / "corrections_changelog.jsonl", "a") as fh:
        fh.writelines(json.dumps(e) + "\n" for e in log)
    for k, v in sorted(stats.items()):
        print(f"{v:6d}  {k}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
