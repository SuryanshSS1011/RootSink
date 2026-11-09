#!/usr/bin/env python3
"""Mark the alternative held-out evaluation strata.

The project-disjoint `split` answers "does this generalize to unseen code?". It cannot answer
two questions a causality-chain dataset should be able to pose:

  unseen_arm  does the model generalize to a chain TYPE it never trained on? Every arm appears
              in the project-disjoint training fold, so that split cannot test it.
  length3     does the model follow causal propagation past a single hop? Length-3 records are
              1 in 37, so a random or project split leaves too few in test to measure.

These are marked rather than folded into `split` because the protocols are mutually exclusive:
withholding an entire arm puts that arm's projects on both sides of any project-disjoint line.
A consumer picks one protocol, excludes the marked records from training, and evaluates on them.

Arm choice is deliberate. CWE-129->CWE-119 and CWE-252->CWE-476 are withheld because each has
enough GOLD to measure, neither is structurally load-bearing, and withholding them does not
remove a sink CWE from training entirely: CWE-119 survives via CWE-190->CWE-119 and
CWE-843->CWE-119, CWE-476 via CWE-362->CWE-476. Withholding an arm whose sink appears nowhere
else would test vocabulary, not generalization.

Usage: assign_eval_strata.py <dataset.jsonl> --out <out.jsonl>
"""

from __future__ import annotations

import argparse
import collections
import json
import sys

UNSEEN_ARMS = {"CWE-129->CWE-119", "CWE-252->CWE-476"}


def main(argv):
    ap = argparse.ArgumentParser()
    ap.add_argument("dataset")
    ap.add_argument("--out", required=True)
    args = ap.parse_args(argv)

    with open(args.dataset) as fh:
        rows = [json.loads(x) for x in fh if x.strip()]

    st = collections.Counter()
    for rec in rows:
        chain = [c for c in (rec.get("chain") or []) if isinstance(c, dict)]
        stratum = None
        if rec.get("chain_string") in UNSEEN_ARMS:
            stratum = "unseen_arm"
        elif len(chain) >= 3:
            stratum = "length3"
        rec["eval_stratum"] = stratum
        if stratum:
            st[stratum] += 1
            if rec.get("label_confidence_tier") == "gold":
                st[f"{stratum} (GOLD)"] += 1

    with open(args.out, "w") as fh:
        for rec in rows:
            fh.write(json.dumps(rec) + "\n")

    for k, v in sorted(st.items()):
        print(f"  {v:5d}  {k}")
    held = sum(v for k, v in st.items() if "GOLD" not in k)
    print(f"  {len(rows) - held:5d}  unmarked (usable under either protocol)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
