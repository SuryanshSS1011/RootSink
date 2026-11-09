#!/usr/bin/env python3
"""P0 metadata repair: normalise language, give ecosystem real meaning, infer locality
from witnessed locations, and assign project-disjoint evaluation splits.

Each of these is a correctness problem rather than a balance one:

  language   held both "C++" and "c++", so every group-by on language was silently wrong.
  ecosystem  was echoing PROVENANCE ("nvd-race", "osv-git" are not ecosystems), and was
             null for all 731 ARVO records. Set to OSV-convention values instead, and left
             NULL where genuinely unknown - a null is honest, a wrong value is not.
  locality   was null for 65% of records. Inferred ONLY where two links carry witnessed
             file:line evidence; never guessed.
  split      did not exist. Must be project-disjoint: linux-kernel is ~49% of GOLD, so a
             random split trains and tests on the same project and inflates every number.
             linux-kernel is further divided by SUBSYSTEM (drivers/, fs/, net/, mm/, ...)
             because assigning one 49% project to a single fold would leave the other folds
             with no kernel data at all.

Usage: fix_p0_metadata.py <dataset.jsonl> --out <out.jsonl>
"""

import argparse
import collections
import hashlib
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))
from chainforge.field_policy import canonical_project  # noqa: E402

# OSV-style ecosystem values. Anything we cannot honestly determine stays None.
ECOSYSTEM = {
    "arvo": "OSS-Fuzz",
    "arvo-len3": "OSS-Fuzz",
    "arvo-newarm": "OSS-Fuzz",
    "arvo-msan": "OSS-Fuzz",
    "syzbot": "Linux",
    "osv-git": "GIT",
    "osv-git-len3": "GIT",
    "nvd-race": None,  # NVD CVEs across unrelated projects; no single ecosystem applies
}

LANGUAGE = {"c++": "C++", "c": "C", "C++": "C++", "C": "C"}


def links(rec):
    return [c for c in (rec.get("chain") or []) if isinstance(c, dict)]


def locations(rec):
    out = []
    for c in links(rec):
        loc = (c.get("evidence") or {}).get("location")
        if loc and loc.get("file"):
            out.append(loc["file"])
    return out


def infer_locality(rec):
    """Only from witnessed locations. Returns None when we cannot tell."""
    files = locations(rec)
    if len(files) < 2:
        return None
    return "cross-file" if len(set(files)) > 1 else "same-file"  # superseded: evidence.locality


def split_unit(rec):
    """The unit assigned wholesale to a fold.

    Normally the project (canonical name: aliases and forks share a fold). For linux-kernel -
    49% of GOLD - the subsystem, taken from the witnessed file path, so folds each get kernel
    data without sharing a subsystem.
    """
    proj = rec.get("project") or "unknown"
    if proj != "linux-kernel":
        return canonical_project(proj)
    for f in locations(rec):
        parts = f.strip("/").split("/")
        if parts:
            top = parts[0]
            return (
                f"linux-kernel/{top}/{parts[1]}"
                if top in ("drivers", "fs", "net", "arch") and len(parts) > 1
                else f"linux-kernel/{top}"
            )
    return "linux-kernel/unknown"


def main(argv):
    ap = argparse.ArgumentParser()
    ap.add_argument("dataset")
    ap.add_argument("--out", required=True)
    ap.add_argument("--test-frac", type=float, default=0.15)
    ap.add_argument("--val-frac", type=float, default=0.15)
    args = ap.parse_args(argv)

    with open(args.dataset) as fh:
        rows = [json.loads(x) for x in fh if x.strip()]

    st = collections.Counter()
    for rec in rows:
        lang = rec.get("language")
        if lang and LANGUAGE.get(lang, lang) != lang:
            rec["language"] = LANGUAGE[lang]
            st["language_normalised"] += 1
        prov = rec.get("provenance")
        if prov in ECOSYSTEM:
            want = ECOSYSTEM[prov]
            if rec.get("ecosystem") != want:
                rec["ecosystem"] = want
                st["ecosystem_set" if want else "ecosystem_nulled"] += 1
        # Locality from witnessed file:line, which OVERRIDES a stored value. The kernel
        # records were all stamped "cross-scope" before any localization existed; now that
        # the KASAN stages give real files, 418 of them are demonstrably cross-FILE. Direct
        # evidence beats a blanket assumption, the same way the witnessed crash direction
        # overrode the inferred sink CWE.
        loc = infer_locality(rec)
        if loc:
            if not rec.get("locality"):
                st["locality_inferred"] += 1
            elif rec["locality"] != loc:
                st["locality_corrected"] += 1
            rec["locality"] = loc

    # Project-disjoint split. Assign whole units, largest first, to whichever fold is
    # furthest below its quota - this keeps folds near their target sizes even though unit
    # sizes are wildly uneven.
    units = collections.Counter(split_unit(r) for r in rows)
    total = sum(units.values())
    quota = {
        "test": args.test_frac * total,
        "validation": args.val_frac * total,
        "train": (1 - args.test_frac - args.val_frac) * total,
    }
    filled = {k: 0.0 for k in quota}
    assign = {}
    for unit, n in sorted(units.items(), key=lambda kv: (-kv[1], kv[0])):
        # deterministic tiebreak so re-runs are stable
        fold = max(
            quota,
            key=lambda k: (quota[k] - filled[k], hashlib.md5(f"{unit}{k}".encode()).hexdigest()),
        )
        assign[unit] = fold
        filled[fold] += n
    for rec in rows:
        rec["split"] = assign[split_unit(rec)]
        st[f"split_{rec['split']}"] += 1

    with open(args.out, "w") as fh:
        for rec in rows:
            fh.write(json.dumps(rec) + "\n")
    for k, v in sorted(st.items()):
        print(f"  {k}: {v}")
    print(f"  split units: {len(units)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
