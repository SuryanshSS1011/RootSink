#!/usr/bin/env python3
"""Select the PR-7 mining pilot from ARVO's index, before any case is run.

PREREGISTRATION PR-7: reproduced ARVO cases with a located fix, not already in the release;
admitted sinks are ASan overflow READ (-> CWE-125) or WRITE (-> CWE-787) only; seeded (2027),
diversity-first: at most 10 cases per project, strata (overflow region x access) filled in
inverse proportion to their share of current GOLD sinks, random within a stratum.

Writes data/validation/pr7_<name>.json (the selection, the strata and their quotas) and an id
list for the runner. The selection is fixed by the seed and the inputs; it is written before any
of its cases is replayed.

A later batch excludes every case an earlier batch drew (data/validation/pr7_*.json) and counts
their projects toward the per-project cap, so the cap holds across all batches.

Usage: select_pr7.py --n 100 --name pilot [--db data/cache/arvo.db]
"""

from __future__ import annotations

import argparse
import collections
import json
import random
import re
import sqlite3
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))
from chainforge.field_policy import canonical_project  # noqa: E402

_SHA = re.compile(r"[0-9a-f]{40}")
_ADMIT = re.compile(
    r"^(Heap|Stack|Global|Dynamic-stack|Container)-buffer-overflow (READ|WRITE)", re.I
)


def stratum(crash_type: str) -> tuple[str, str] | None:
    m = _ADMIT.match(crash_type or "")
    return (m.group(1).lower(), m.group(2).upper()) if m else None


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--n", type=int, default=100)
    ap.add_argument("--name", default="pilot")
    ap.add_argument("--db", default="data/cache/arvo.db")
    ap.add_argument("--release", default="data/release/dataset.jsonl")
    ap.add_argument("--seed", type=int, default=2027)
    ap.add_argument("--per-project", type=int, default=10)
    ap.add_argument(
        "--skip-known-fix",
        action="store_true",
        help="skip a case whose fix commit is already in the release or already drawn for its "
        "project (same bug, another input); it does not count toward the cap",
    )
    ap.add_argument(
        "--max-gold-share",
        type=float,
        default=None,
        help="draw nothing from a project (other than linux-kernel) already holding this share "
        "of GOLD",
    )
    args = ap.parse_args(argv)

    with open(args.release) as fh:
        rows = [json.loads(line) for line in fh]
    used = {a[9:] for r in rows for a in r["aliases"] if a.startswith("OSS-Fuzz-")}
    per_project = collections.Counter()
    for prev in sorted(Path("data/validation").glob("pr7_*.json")):
        if prev.stem.endswith("_funnel") or prev.stem == f"pr7_{args.name}":
            continue
        for c in json.loads(prev.read_text())["selected"]:
            used.add(c["localId"])
            per_project[c["project"]] += 1
    gold_sinks = collections.Counter(
        r["chain"][-1]["cwe_id"] for r in rows if r["label_confidence_tier"] == "gold"
    )
    sink_share = {
        "READ": gold_sinks[125] / max(1, sum(gold_sinks.values())),
        "WRITE": gold_sinks[787] / max(1, sum(gold_sinks.values())),
    }

    # Fix commits already in the release, per canonical project (any tier): a case closed by one of
    # them is another input for a bug the release already has.
    known_fix = collections.defaultdict(set)
    for r in rows:
        m = _SHA.search(json.dumps(r.get("commit_range") or {}))
        if m:
            known_fix[canonical_project(r["project"])].add(m.group(0)[:12])
    gold_by_project = collections.Counter(
        canonical_project(r["project"]) for r in rows if r["label_confidence_tier"] == "gold"
    )
    n_gold = max(1, sum(gold_by_project.values()))
    too_big = {
        p
        for p, k in gold_by_project.items()
        if args.max_gold_share is not None
        and p != "linux-kernel"
        and k / n_gold >= args.max_gold_share
    }

    db = sqlite3.connect(f"file:{args.db}?mode=ro", uri=True)
    db.row_factory = sqlite3.Row
    pool = collections.defaultdict(list)
    for r in db.execute("select * from arvo where reproduced=1 and patch_located=1"):
        lid = str(r["localId"])
        st = stratum(r["crash_type"])
        if lid in used or not st or not r["fix_commit"] or not r["patch_url"]:
            continue
        pool[st].append(dict(r) | {"localId": lid, "crash_output": None, "report": None})

    # Inverse to current GOLD share: an access direction GOLD already has a lot of is drawn less.
    weights = {st: 1.0 / max(sink_share[st[1]], 0.01) for st in pool}
    total = sum(weights[st] * len(v) for st, v in pool.items())
    quota = {st: max(1, round(args.n * weights[st] * len(v) / total)) for st, v in pool.items()}

    rng = random.Random(args.seed)
    picked, skipped_dup = [], 0
    for st in sorted(pool, key=lambda s: -weights[s]):
        cands = sorted(pool[st], key=lambda r: r["localId"])
        rng.shuffle(cands)
        taken = 0
        for r in cands:
            if taken >= quota[st] or len(picked) >= args.n:
                break
            if per_project[r["project"]] >= args.per_project:
                continue
            canon = canonical_project(r["project"])
            if canon in too_big:
                continue
            if args.skip_known_fix:
                m = _SHA.search(r["fix_commit"] or "") or _SHA.search(r["patch_url"] or "")
                fix = m.group(0)[:12] if m else None
                if fix and fix in known_fix[canon]:
                    skipped_dup += 1
                    continue
                if fix:
                    known_fix[canon].add(fix)
            per_project[r["project"]] += 1
            picked.append(r)
            taken += 1

    out = Path(f"data/validation/pr7_{args.name}.json")
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(
        json.dumps(
            {
                "rule": "PREREGISTRATION PR-7",
                "seed": args.seed,
                "n": len(picked),
                "excluded_earlier_batches": sum(per_project.values()) - len(picked),
                "per_project_cap": args.per_project,
                "skip_known_fix": args.skip_known_fix,
                "skipped_known_fix": skipped_dup,
                "max_gold_share": args.max_gold_share,
                "projects_over_gold_share": sorted(too_big),
                "pool_by_stratum": {f"{a}-{b}": len(v) for (a, b), v in pool.items()},
                "quota_by_stratum": {f"{a}-{b}": q for (a, b), q in quota.items()},
                "selected": [
                    {
                        k: r[k]
                        for k in (
                            "localId",
                            "project",
                            "crash_type",
                            "fix_commit",
                            "patch_url",
                            "language",
                        )
                    }
                    for r in picked
                ],
            },
            indent=1,
        )
    )
    print(f"{len(picked)} selected from {sum(len(v) for v in pool.values())} -> {out}")
    print(collections.Counter(f"{stratum(r['crash_type'])}" for r in picked).most_common())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
