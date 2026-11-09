#!/usr/bin/env python3
"""Select a PR-11 batch (one crash class) from ARVO's index, before any case is run.

PREREGISTRATION PR-11. Supply: reproduced ARVO cases with a recorded fix, not in the release and
never drawn by a PR-7 or PR-11 batch, whose ARVO crash type is the class's. Selection as PR-7
batch 4: seeded (2027), at most --per-project cases per project counted across every batch of
this class, known-fix cases skipped, nothing from a non-kernel project holding --max-gold-share
of GOLD. Use-after-free READ/WRITE strata are filled inverse to their share of GOLD sinks.

Writes data/validation/pr11_<class>_<name>.json and prints the pool and the draw.

Usage: select_pr11.py --cls msan --name pilot --n 100
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

_SHA = re.compile(r"[0-9a-f]{40}(?![0-9a-f])")

# class -> (sanitizer, crash-type pattern whose group 1 is the stratum, or None for one stratum)
CLASSES = {
    "msan": ("msan", re.compile(r"^Use-of-uninitialized-value()", re.I)),
    "uaf": ("asan", re.compile(r"^Heap-use-after-free (READ|WRITE)", re.I)),
    "index-oob": ("ubsan", re.compile(r"^Index-out-of-bounds()", re.I)),
    # PR-16: SEGV-class ASan crashes; our own report decides whether it is a NULL dereference.
    "nullderef": (
        "asan",
        re.compile(
            r"^(?:Segv on unknown address|UNKNOWN (?:READ|WRITE)|Null-dereference (?:READ|WRITE))()",
            re.I,
        ),
    ),
}


def stratum(cls: str, sanitizer: str | None, crash_type: str | None) -> str | None:
    san, rx = CLASSES[cls]
    if (sanitizer or "").lower() != san:
        return None
    m = rx.match(crash_type or "")
    return (m.group(1).upper() or cls) if m else None


def drawn_before(name: str, cls: str) -> tuple[set[str], collections.Counter]:
    """Every case any PR-7 or PR-11 batch drew; projects counted for this class's cap only."""
    used: set[str] = set()
    per_project: collections.Counter = collections.Counter()
    for prev in sorted(Path("data/validation").glob("pr*.json")):
        stem = prev.stem
        if stem.endswith("_funnel") or not stem.startswith(("pr7_", "pr11_")):
            continue
        if stem == f"pr11_{cls}_{name}":
            continue
        d = json.loads(prev.read_text())
        for c in d.get("selected", []):
            used.add(str(c["localId"]))
            if stem.startswith(f"pr11_{cls}_"):
                per_project[c["project"]] += 1
    return used, per_project


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--cls", required=True, choices=sorted(CLASSES))
    ap.add_argument("--name", default="pilot")
    ap.add_argument("--n", type=int, default=100)
    ap.add_argument("--db", default="data/cache/arvo.db")
    ap.add_argument("--release", default="data/release/dataset.jsonl")
    ap.add_argument("--seed", type=int, default=2027)
    ap.add_argument("--per-project", type=int, default=30)
    ap.add_argument("--max-gold-share", type=float, default=0.04)
    args = ap.parse_args(argv)

    with open(args.release) as fh:
        rows = [json.loads(line) for line in fh]
    used, per_project = drawn_before(args.name, args.cls)
    used |= {a[9:] for r in rows for a in r["aliases"] if a.startswith("OSS-Fuzz-")}

    known_fix = collections.defaultdict(set)
    for r in rows:
        m = _SHA.search(json.dumps(r.get("commit_range") or {}))
        if m:
            known_fix[canonical_project(r["project"])].add(m.group(0)[:12])
    gold = [r for r in rows if r["label_confidence_tier"] == "gold"]
    by_project = collections.Counter(canonical_project(r["project"]) for r in gold)
    too_big = {
        p
        for p, k in by_project.items()
        if p != "linux-kernel" and k / max(1, len(gold)) >= args.max_gold_share
    }
    sinks = collections.Counter(r["chain"][-1]["cwe_id"] for r in gold)
    share = {
        "READ": sinks[125] / max(1, len(gold)),
        "WRITE": sinks[787] / max(1, len(gold)),
    }

    db = sqlite3.connect(f"file:{args.db}?mode=ro", uri=True)
    db.row_factory = sqlite3.Row
    pool = collections.defaultdict(list)
    for r in db.execute("select * from arvo where reproduced=1 and patch_located=1"):
        lid = str(r["localId"])
        st = stratum(args.cls, r["sanitizer"], r["crash_type"])
        if lid in used or not st or not r["fix_commit"] or not r["patch_url"]:
            continue
        pool[st].append(dict(r) | {"localId": lid, "crash_output": None, "report": None})

    weights = {st: 1.0 / max(share.get(st, 1.0), 0.01) for st in pool}
    total = sum(weights[st] * len(v) for st, v in pool.items()) or 1
    quota = {st: max(1, round(args.n * weights[st] * len(v) / total)) for st, v in pool.items()}

    rng = random.Random(args.seed)
    picked, skipped_dup = [], 0
    for st in sorted(pool, key=lambda s: (-weights[s], s)):
        cands = sorted(pool[st], key=lambda r: r["localId"])
        rng.shuffle(cands)
        taken = 0
        for r in cands:
            if taken >= quota[st] or len(picked) >= args.n:
                break
            canon = canonical_project(r["project"])
            if per_project[r["project"]] >= args.per_project or canon in too_big:
                continue
            m = _SHA.search(r["fix_commit"] or "") or _SHA.search(r["patch_url"] or "")
            fix = m.group(0)[:12] if m else None
            if fix and fix in known_fix[canon]:
                skipped_dup += 1
                continue
            if fix:
                known_fix[canon].add(fix)
            per_project[r["project"]] += 1
            picked.append(r | {"stratum": st})
            taken += 1

    out = Path(f"data/validation/pr11_{args.cls}_{args.name}.json")
    keys = ("localId", "project", "crash_type", "sanitizer", "fix_commit", "patch_url", "language")
    out.write_text(
        json.dumps(
            {
                "rule": "PREREGISTRATION PR-11",
                "class": args.cls,
                "seed": args.seed,
                "n": len(picked),
                "per_project_cap": args.per_project,
                "skipped_known_fix": skipped_dup,
                "max_gold_share": args.max_gold_share,
                "projects_over_gold_share": sorted(too_big),
                "pool_by_stratum": {k: len(v) for k, v in pool.items()},
                "quota_by_stratum": quota,
                "selected": [{k: r[k] for k in keys} | {"stratum": r["stratum"]} for r in picked],
            },
            indent=1,
        )
    )
    print(f"{args.cls}: {len(picked)} selected from {sum(map(len, pool.values()))} -> {out}")
    print(dict(collections.Counter(r["stratum"] for r in picked)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
