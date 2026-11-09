#!/usr/bin/env python3
"""Attest a CWE-362 source on kernel records whose fix adds synchronisation.

The race arm was recorded as unwitnessable: 243 records, 7 GOLD, zero with an execution
witness, because `nvd-race` CVEs ship no reproducer and syzbot cannot reproduce a bare KCSAN
data-race (confirmed in syzkaller's own docs). All true, and the conclusion still did not
follow. A race that manifests as a use-after-free is a KASAN bug, and those DO ship C
reproducers - so the arm is reachable through the sink, not through the race detector.

49 syzbot records have fixes adding two or more lines of synchronisation (`spin_lock`,
`mutex_lock`, `rcu_read_lock`, `WRITE_ONCE`, ...). That is the same attestation standard already
used for CWE-190 (fix adds an overflow guard) and CWE-456 (fix adds an initialisation).

Only the 28 whose source is CWE-416 are extended, to `CWE-362 -> CWE-416 -> <sink>`: both edges
are admissible and `362 -> 416` is mitre-direct. The other 21 have a CWE-20 source, and neither
`362 -> 125` nor `362 -> 787` is in the catalogue, so they cannot be relabelled without
inventing an edge. They are FLAGGED instead - their CWE-20 is unevidenced and the added locking
is evidence it is probably wrong, which a reader should be told rather than left to infer.

Usage: attest_race_source.py <dataset.jsonl> --out <out.jsonl> [--dry-run]
"""

from __future__ import annotations

import argparse
import collections
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))
from chainforge.cwe import validate_chain  # noqa: E402
from chainforge.evidence import patch_is_content  # noqa: E402

LOCK = re.compile(
    r"^\+.*\b(spin_lock|spin_unlock|mutex_lock|mutex_unlock|down_read|down_write|read_lock|"
    r"write_lock|rcu_read_lock|synchronize_rcu|refcount_inc|kref_get|smp_[wr]mb|READ_ONCE|"
    r"WRITE_ONCE|atomic_|_bh\(|raw_spin_lock)\b"
)
MIN_SYNC_LINES = 2


def sync_lines(diff: str) -> list[str]:
    return [ln for ln in diff.splitlines() if LOCK.match(ln)]


def primitives(hits: list[str]) -> list[str]:
    out = []
    for h in hits:
        m = LOCK.match(h)
        if m and m.group(1) not in out:
            out.append(m.group(1))
    return out


def main(argv):
    ap = argparse.ArgumentParser()
    ap.add_argument("dataset")
    ap.add_argument("--out", required=True)
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args(argv)

    with open(args.dataset) as fh:
        rows = [json.loads(x) for x in fh if x.strip()]

    st = collections.Counter()
    for rec in rows:
        if rec.get("provenance") != "syzbot":
            continue
        diff = rec.get("patch_diff") or ""
        if not patch_is_content(diff):
            continue
        hits = sync_lines(diff)
        if len(hits) < MIN_SYNC_LINES:
            continue
        chain = [c for c in (rec.get("chain") or []) if isinstance(c, dict)]
        if not chain:
            continue
        prims = ", ".join(primitives(hits)[:3])
        src = chain[0].get("cwe_id")

        if src == 416:
            seq = [362] + [c["cwe_id"] for c in chain]
            if not validate_chain(seq).admissible:
                st["416 source but the extended chain is inadmissible"] += 1
                continue
            race_link = {
                "cwe_id": 362,
                "role": "source",
                "evidence": {
                    "dataflow_path": None,
                    "sanitizer_report_ref": None,
                    "patch_hunk_ref": (
                        f"fix adds synchronisation ({prims}); CWE-362 source attested by the "
                        "patch, not assumed"
                    )[:160],
                    "location": None,
                },
            }
            chain[0]["role"] = "intermediate"
            rec["chain"] = [race_link] + chain
            rec["chain_string"] = "->".join(f"CWE-{c['cwe_id']}" for c in rec["chain"])
            rec["dataflow_evidence"] = (rec.get("dataflow_evidence") or "").rstrip() + (
                f" RACE SOURCE ATTESTED: the fix adds {prims}, so the use-after-free this KASAN "
                "report witnesses is enabled by a data race. The race itself is not directly "
                "witnessed - syzbot cannot reproduce a bare KCSAN report - but its consequence "
                "is, and the added synchronisation is the author's own statement of the cause."
            )
            st["EXTENDED to CWE-362 -> CWE-416 -> sink"] += 1
        else:
            ev = chain[0].setdefault("evidence", {})
            prev = ev.get("patch_hunk_ref") or ""
            if "adds synchronisation" in prev:
                continue
            ev["patch_hunk_ref"] = (
                f"CWE-{src} source NOT attested, and the fix adds synchronisation ({prims}): "
                f"the cause is likely a race, but CWE-362 -> CWE-{chain[-1]['cwe_id']} is not an "
                "admissible edge, so the label is flagged rather than changed"
            )[:250]
            st[f"FLAGGED (CWE-{src} source, cannot extend)"] += 1

    if not args.dry_run:
        with open(args.out, "w") as fh:
            for rec in rows:
                fh.write(json.dumps(rec) + "\n")
    for k, v in st.most_common():
        print(f"  {v:4d}  {k}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
