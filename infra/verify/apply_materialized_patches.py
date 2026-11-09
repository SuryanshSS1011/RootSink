#!/usr/bin/env python3
"""Replace bare patch URLs with the actual diff, and re-derive the guard signal from it.

1277 records stored a link in patch_diff. That satisfies the GOLD invariant's letter and
defeats its purpose: the vise pair - vulnerable and patched differing only by an added guard -
is what makes a counterfactual well defined, and a URL carries no guard. It also rots, because
forges move.

Materialising the diff has a second effect worth more than the first. The guard-absence source
of a chain can only be attested from the patch, and with the patch absent 679 CWE-20 records
asserted a missing input-validation check that nothing demonstrated. With the diff present the
same test used for CWE-456 and CWE-190 can run, and each record either earns its source or is
marked as unevidenced rather than silently assumed.

Usage: apply_materialized_patches.py <dataset.jsonl> <materialized.json> --out <out.jsonl>
"""

from __future__ import annotations

import argparse
import collections
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))
from chainforge.evidence import clip_patch  # noqa: E402

SIZEISH = r"(size|len|length|count|width|height|depth|num|idx|index|off|offset|cap|max|bound|limit)"
# Added lines that introduce a check. Deliberately not counting removals: a deleted guard is
# the opposite of the claim.
GUARD_SIGNALS = [
    (
        re.compile(r"^\+.*\bif\s*\(.*\b\w*" + SIZEISH + r"\w*\s*(<=|>=|<|>|==|!=)", re.I),
        "bound-guard",
    ),
    (
        re.compile(r"^\+.*\b(SIZE_MAX|INT_MAX|UINT_MAX|LONG_MAX|SSIZE_MAX|[A-Z_]{2,}_MAX\w*)\b"),
        "limit-const",
    ),
    (re.compile(r"^\+.*\b__builtin_(add|mul|sub)_overflow\s*\("), "builtin-overflow"),
    (re.compile(r"^\+.*\b(check|validate|verify|sanitiz|safe)\w*\s*\(", re.I), "guard-call"),
    (re.compile(r"^\+.*\b(memset|bzero|calloc)\s*\("), "init-guard"),
    (re.compile(r"^\+.*\b(BUG_ON|WARN_ON|assert|ASSERT)\s*\("), "assert-guard"),
    (re.compile(r"^\+.*\breturn\s*\(?\s*(-\w+|NULL|false|0)\s*\)?\s*;"), "early-reject"),
    (re.compile(r"^\+.*\((size_t|uint64_t|int64_t|unsigned long long|uintmax_t)\)"), "width-cast"),
]
# Sources whose weakness IS an absent check; only these can be attested this way.
GUARD_SOURCE = {20, 129, 190, 252, 456}
STRONG = {"bound-guard", "limit-const", "builtin-overflow", "init-guard"}


def guard_hits(diff: str) -> list[str]:
    hits = []
    for pat, name in GUARD_SIGNALS:
        if any(pat.match(line) for line in diff.splitlines()):
            hits.append(name)
    return hits


def main(argv):
    ap = argparse.ArgumentParser()
    ap.add_argument("dataset")
    ap.add_argument("materialized")
    ap.add_argument("--out", required=True)
    args = ap.parse_args(argv)

    with open(args.materialized) as fh:
        mat = json.load(fh)
    with open(args.dataset) as fh:
        rows = [json.loads(x) for x in fh if x.strip()]

    st = collections.Counter()
    for rec in rows:
        diff = mat.get(rec["id"])
        if not diff:
            continue
        rec["patch_diff"] = clip_patch(diff, 200_000)
        st["patch materialised"] += 1

        chain = [c for c in (rec.get("chain") or []) if isinstance(c, dict)]
        if not chain or chain[0].get("cwe_id") not in GUARD_SOURCE:
            continue
        src = chain[0]["cwe_id"]
        hits = guard_hits(diff)
        ev = chain[0].setdefault("evidence", {})
        if any(h in STRONG for h in hits):
            ev["patch_hunk_ref"] = (
                f"fix adds a guard ({', '.join(hits[:3])}); CWE-{src} source attested "
                "by the patch, not assumed"
            )[:160]
            st["  source ATTESTED from the new diff"] += 1
        else:
            # State the absence rather than leaving an assumption standing.
            ev["patch_hunk_ref"] = (
                f"CWE-{src} source NOT attested: the fix carries no added guard "
                f"({', '.join(hits) if hits else 'no signal'})"
            )[:160]
            st["  source marked UNATTESTED"] += 1

    with open(args.out, "w") as fh:
        for rec in rows:
            fh.write(json.dumps(rec) + "\n")
    for k, v in st.most_common():
        print(f"  {v:5d}  {k}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
