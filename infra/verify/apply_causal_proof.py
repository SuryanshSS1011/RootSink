#!/usr/bin/env python3
"""Attach guard-ablation proofs to the records whose source link they establish.

Attestation says the fix adds a guard near the bug. This says the guard's ABSENCE caused the
sink: applying that hunk alone to the vulnerable revision, rebuilding and replaying the same
PoV silences the sanitizer. It is the only evidence kind in the corpus that demonstrates
causality rather than correlation, and it exists precisely for the records that most needed it
- CWE-20 sources written in because the sink was an out-of-bounds access, with nothing
supporting the claim.

A proof is accepted only if the unmodified rebuild CRASHED. Without that control a clean run
is indistinguishable from a build that cannot reproduce at all.

Usage: apply_causal_proof.py <dataset.jsonl> <results.json> --out <out.jsonl>
"""

from __future__ import annotations

import argparse
import collections
import json
import os
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))
from chainforge.evidence import hunk_test_narrative, hunk_test_note  # noqa: E402


def main(argv):
    ap = argparse.ArgumentParser()
    ap.add_argument("dataset")
    ap.add_argument("results", help="json: {arvo_id: ablate result.json}")
    ap.add_argument("--hunks", help="dir of <arvo_id>/<hunk>.patch files, to carry the guard")
    ap.add_argument("--out", required=True)
    args = ap.parse_args(argv)

    with open(args.results) as fh:
        res = json.load(fh)
    with open(args.dataset) as fh:
        rows = [json.loads(x) for x in fh if x.strip()]

    st = collections.Counter()
    for rec in rows:
        blob = json.dumps(rec.get("aliases") or []) + json.dumps(rec.get("docker_image_ref") or {})
        m = re.search(r"OSS-Fuzz-(\d+)", blob) or re.search(r"arvo:(\d+)-", blob)
        v = res.get(m.group(1)) if m else None
        if not v:
            continue
        guard = v.get("guard_hunk")
        if not guard or v.get("control") != "crashed":
            st["no proof (or control did not crash)"] += 1
            continue
        chain = [c for c in (rec.get("chain") or []) if isinstance(c, dict)]
        if not chain:
            continue
        ev = chain[0].setdefault("evidence", {})
        ev["causal_proof"] = {
            "method": "guard-ablation",
            "hunk": guard.get("hunk"),
            "file": guard.get("file"),
            "added_lines": guard.get("added"),
            "control": "crashed",
            "with_guard_only": "clean",
            "arvo_id": v.get("arvo_id"),
        }
        # Carry the guard itself where we have it: the minimal counterfactual is
        # vulnerable versus vulnerable-plus-guard, not versus the whole developer fix.
        if args.hunks:
            hp = os.path.join(args.hunks, str(v.get("arvo_id")), guard.get("hunk") or "")
            if os.path.exists(hp):
                with open(hp) as fh:
                    ev["minimal_guard_patch"] = fh.read()[:40_000]
                st["minimal guard patch carried"] += 1
        ev["patch_hunk_ref"] = hunk_test_note(guard.get("file"), guard.get("added"), None)
        rec["dataflow_evidence"] = (rec.get("dataflow_evidence") or "").rstrip() + (
            hunk_test_narrative(guard.get("file"))
        )
        st["hunk-tested source attached"] += 1

    with open(args.out, "w") as fh:
        for rec in rows:
            fh.write(json.dumps(rec) + "\n")
    for k, v in st.most_common():
        print(f"  {v:4d}  {k}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
