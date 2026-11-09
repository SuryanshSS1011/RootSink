#!/usr/bin/env python3
"""Re-derive every credited guard CWE under the current guard rule, offline (PR-4 amendment of
2026-10-29: a line the fix only re-indents or re-braces is not a line it adds).

PR-4 credits a root CWE from the hunk that alone stopped the crash (`evidence.source_for_guard`).
The hunk is recovered exactly as the runner made it: `split_hunks.py` over the record's own
`patch_diff`, taking the proof's hunk name, and accepted only when that hunk's file and added-line
count match the proof (otherwise the record is left alone and counted as unlocated).

For each `causal_proof`:
  - same CWE: nothing changes;
  - another CWE: the root is relabelled to it (PR-17 then maps a CWE-20 root), logged
    `PR4-amend-relabel`;
  - no CWE (undetermined or inadmissible): a record PR-7 admitted is dropped, since PR-7 admits
    a mined case only when PR-4 derives its root CWE (`PR4-amend-dropped`, dropped.jsonl). Any
    other record keeps the test as `guard_site_proof` crediting no CWE, as PR-4 does for any
    underived proof, and the relabel PR-4 made from this proof is withdrawn: the root returns to
    the CWE that `PR4-relabel-source` replaced, logged `PR4-amend-withdrawn`.
`rebuild_derived.sh` then restamps evidence categories and re-tiers. Idempotent.

Usage: reapply_guard_rule.py [--release data/release]
"""

from __future__ import annotations

import argparse
import collections
import json
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parents[1] / "src"))
from chainforge.cwe import is_admissible_edge  # noqa: E402
from chainforge.evidence import (  # noqa: E402
    chain_kind,
    hunk_site_note_no_cwe,
    is_hunk_test_note,
    source_for_guard,
)

sys.path.insert(0, str(HERE))
from apply_pr4 import mitre  # noqa: E402


def proving_hunk(diff: str, proof: dict) -> str | None:
    with tempfile.TemporaryDirectory() as d:
        (Path(d) / "fix.diff").write_text(diff)
        subprocess.run(
            [sys.executable, str(HERE / "split_hunks.py"), f"{d}/fix.diff", f"{d}/h"],
            capture_output=True,
        )
        idx = Path(d) / "h" / "index.json"
        if not idx.is_file():
            return None
        hunks = json.loads(idx.read_text())["hunks"]

        def fits(h: dict) -> bool:
            return h.get("file") == proof.get("file") and str(h.get("added")) == str(
                proof.get("added_lines")
            )

        named = [h for h in hunks if h["name"] == proof.get("hunk") and fits(h)]
        # The runner's diff can differ from the stored one by hunks outside the split (renamed
        # names); then accept the one hunk of that file with the proof's added-line count.
        pick = named or [h for h in hunks if fits(h)]
        if len(pick) != 1:
            return None
        return (Path(d) / "h" / pick[0]["name"]).read_text()


def relabel(r: dict, cwe: int) -> None:
    root = r["chain"][0]
    root["cwe_id"] = cwe
    # PR-17's record of a CWE-20 mapping belongs to the old label; apply_pr17 re-maps a new 20.
    for k in ("cwe_class", "cwe_mapping", "cwe_mapping_input"):
        root.pop(k, None)
    cwes = [c["cwe_id"] for c in r["chain"]]
    r["chain_string"] = "->".join(f"CWE-{c}" for c in cwes)
    r["chain_kind"] = chain_kind(cwes)
    r["mitre_chain"] = mitre(cwes)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--release", default="data/release")
    args = ap.parse_args(argv)
    rel = Path(args.release)
    with open(rel / "dataset.jsonl") as fh:
        rows = [json.loads(line) for line in fh]
    replaced: dict[str, int] = {}  # id -> the CWE PR-4's last relabel replaced
    mined: set[str] = set()  # admitted by PR-7, which requires a derived root CWE
    with open(rel / "corrections_changelog.jsonl") as fh:
        for line in fh:
            e = json.loads(line)
            if e.get("op") == "PR4-relabel-source":
                replaced[e["id"]] = e["from"]
            elif e.get("op") == "PR7-admit":
                mined.add(e["id"])
    log, stats, drop = [], collections.Counter(), []
    for r in rows:
        ev = (r.get("chain") or [{}])[0].get("evidence") or {}
        p = ev.get("causal_proof")
        if not p or len(r["chain"]) < 2:
            continue
        hunk = proving_hunk(r.get("patch_diff") or "", p)
        if hunk is None:
            stats["proving hunk not located (left alone)"] += 1
            continue
        old = int(p["source_cwe"])
        # Admissibility against the next link as PR-4 saw it: a CWE-119 sink PR-17 later mapped
        # to 125/787 keeps `cwe_class: 119`.
        nxt = r["chain"][1].get("cwe_class") or r["chain"][1]["cwe_id"]
        new = source_for_guard(hunk, nxt, is_admissible_edge)
        tier = r["label_confidence_tier"]
        if new == old:
            stats["unchanged"] += 1
            continue
        if new is not None:
            p["source_cwe"] = new
            for k in ("patch_hunk_ref",):
                if is_hunk_test_note(ev.get(k)):
                    ev[k] = ev[k].replace(f"CWE-{old} (PR-4)", f"CWE-{new} (PR-4)")
            relabel(r, new)
            log.append({"id": r["id"], "op": "PR4-amend-relabel", "from": old, "to": new})
            stats[f"{tier}: CWE-{old} -> CWE-{new}"] += 1
            continue
        ev.pop("causal_proof")
        ev.pop("minimal_guard_patch", None)
        ev["guard_site_proof"] = {
            **p,
            "source_cwe": None,
            "why": "PR-4 amendment 2026-10-29: the class came only from re-indented lines",
        }
        if is_hunk_test_note(ev.get("patch_hunk_ref")):
            ev["patch_hunk_ref"] = hunk_site_note_no_cwe(p.get("file"))
        if r["id"] in mined:
            # PR-7: "a case with a proven site but no derived CWE is logged, not added".
            drop.append(
                {
                    "id": r["id"],
                    "reason": "PR7-no-derived-cwe (PR-4 amendment 2026-10-29)",
                    "was": r.get("chain_string"),
                    "tier_was": tier,
                }
            )
            log.append({"id": r["id"], "op": "PR4-amend-dropped", "rule": "PR-7 step 2"})
            stats[f"{tier}: mined record dropped (PR-7 needs a derived CWE)"] += 1
            continue
        back = replaced.get(r["id"])
        if back is not None and back != r["chain"][0]["cwe_id"]:
            relabel(r, back)
        log.append(
            {"id": r["id"], "op": "PR4-amend-withdrawn", "from": old, "to": r["chain"][0]["cwe_id"]}
        )
        stats[f"{tier}: CWE-{old} credit withdrawn (root now CWE-{r['chain'][0]['cwe_id']})"] += 1
    gone = {d["id"] for d in drop}
    with open(rel / "dataset.jsonl", "w") as fh:
        fh.writelines(json.dumps(r) + "\n" for r in rows if r["id"] not in gone)
    with open(rel / "dropped.jsonl", "a") as fh:
        fh.writelines(json.dumps(d) + "\n" for d in drop)
    with open(rel / "corrections_changelog.jsonl", "a") as fh:
        fh.writelines(json.dumps(e) + "\n" for e in log)
    for k, v in sorted(stats.items()):
        print(f"{v:6d}  {k}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
