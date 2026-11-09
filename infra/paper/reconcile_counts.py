#!/usr/bin/env python3
"""Print the release summary and the count reconciliation the paper's numbers rest on.

Every quantity is printed with its population (which records), its unit (records, distinct
crashes, bug clusters, events, cases) and how it relates to the others, so two numbers taken
from differently scoped populations are never read as if they must agree. Read-only and
deterministic: it writes nothing and reads only the release, its changelog and
data/validation/.

With --rev it reads those files as they were at a git revision (`git show <rev>:<path>`), so
the counts behind an earlier draft can be regenerated from the same frozen snapshot. The
definitions are this script's, applied to that snapshot; derived artifacts that were never
committed (the duplicate audit) are recomputed here with infra/verify/duplicate_audit.py.

Usage: reconcile_counts.py [--release data/release] [--rev <git rev>] [--json]
"""

from __future__ import annotations

import argparse
import collections
import json
import statistics
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "infra" / "verify"))
from duplicate_audit import UnionFind, keys, near_pairs  # noqa: E402

from chainforge.evidence import locality  # noqa: E402
from chainforge.field_policy import (  # noqa: E402
    LEAKAGE_FIELDS,
    codebase,
    held_out_accuracy,
)

ROOT_KINDS = ("causally-proven", "execution", "attested", "dataflow", "inferred", "none")


def reader(rev: str | None):
    """A function path -> text (or None if absent) at the working tree or at `rev`."""

    def read(path: str) -> str | None:
        if rev is None:
            p = ROOT / path
            return p.read_text() if p.is_file() else None
        got = subprocess.run(
            ["git", "-C", str(ROOT), "show", f"{rev}:{path}"], capture_output=True, text=True
        )
        return got.stdout if got.returncode == 0 else None

    def ls(prefix: str) -> list[str]:
        if rev is None:
            return sorted(str(p.relative_to(ROOT)) for p in (ROOT / prefix).glob("*"))
        got = subprocess.run(
            ["git", "-C", str(ROOT), "ls-tree", "--name-only", f"{rev}:{prefix}"],
            capture_output=True,
            text=True,
        )
        return sorted(f"{prefix}/{n}" for n in got.stdout.split())

    return read, ls


def jsonl(text: str | None) -> list[dict]:
    return [json.loads(line) for line in (text or "").splitlines() if line.strip()]


def pct(a: int, b: int) -> str:
    return f"{100 * a / b:.1f}%" if b else "n/a"


def clusters(rows: list[dict]) -> list[int]:
    """Bug cluster per row, as infra/verify/duplicate_audit.py defines it."""
    uf = UnionFind(len(rows))
    for kind in ("crash", "cve", "fix", "diff"):
        groups = collections.defaultdict(list)
        for i, r in enumerate(rows):
            for k in keys(r)[kind]:
                groups[k].append(i)
        for members in groups.values():
            for m in members[1:]:
                uf.union(members[0], m)
    for a, b, _ in near_pairs(rows):
        uf.union(a, b)
    return [uf.find(i) for i in range(len(rows))]


def summarize(rows: list[dict], log: list[dict], read, ls) -> dict:
    out: dict = {}
    tier = lambda r: r["label_confidence_tier"]  # noqa: E731
    gold = [r for r in rows if tier(r) == "gold"]
    mw_gold = [r for r in gold if r.get("chain_kind") == "multi-weakness"]

    # 1. Populations (review item 2).
    out["records by tier x chain_kind"] = {
        f"{t} / {k}": n
        for (t, k), n in sorted(
            collections.Counter((tier(r), r.get("chain_kind")) for r in rows).items()
        )
    }
    out["records"] = len(rows)
    out["GOLD records"] = len(gold)
    out["GOLD multi-weakness chains (PR-5)"] = len(mw_gold)
    out["GOLD stage decompositions (416->125/787)"] = len(gold) - len(mw_gold)
    bronze = [r for r in rows if tier(r) == "bronze"]
    out["bronze by provenance"] = dict(collections.Counter(r["provenance"] for r in bronze))
    out[
        "bronze resting on advisory co-occurrence (dataflow_evidence 'NVD multi-CWE co-occurrence')"
    ] = sum(
        (r.get("dataflow_evidence") or "").startswith("NVD multi-CWE co-occurrence") for r in bronze
    )
    types = lambda rs: len({r["chain_string"] for r in rs})  # noqa: E731
    mw_all = [r for r in rows if r.get("chain_kind") == "multi-weakness"]
    out["chain types: all records / multi-weakness only"] = f"{types(rows)} / {types(mw_all)}"
    out["chain types: GOLD / GOLD multi-weakness only"] = f"{types(gold)} / {types(mw_gold)}"
    out["length-3 records: all / GOLD"] = (
        f"{sum(len(r['chain']) == 3 for r in rows)} / {sum(len(r['chain']) == 3 for r in gold)}"
    )

    # 2. Root-cause evidence (items 1, 11, 13 rows 1-2).
    root = collections.Counter((tier(r), r["chain"][0].get("evidence_kind")) for r in rows)
    out["root-cause evidence kind, GOLD"] = {k: root[("gold", k)] for k in ROOT_KINDS}
    proven = [r for r in rows if r["chain"][0].get("evidence_kind") == "causally-proven"]
    out["causally-proven roots: records by tier"] = dict(
        collections.Counter(tier(r) for r in proven)
    )
    cl = clusters(rows)
    idx = {r["id"]: i for i, r in enumerate(rows)}
    out["causally-proven roots: records / bug clusters (all tiers)"] = (
        f"{len(proven)} / {len({cl[idx[r['id']]] for r in proven})}"
    )
    sites = [r for r in rows if (r["chain"][0].get("evidence") or {}).get("guard_site_proof")]
    out[
        "site-only proofs (chain[0].evidence.guard_site_proof, source_cwe null): records by tier"
    ] = dict(collections.Counter(tier(r) for r in sites))
    out["site-only proofs: root link keeps its earlier CWE with evidence kind"] = dict(
        collections.Counter(r["chain"][0].get("evidence_kind") for r in sites)
    )
    out["links with a missing CWE id"] = sum(
        1 for r in rows for c in r["chain"] if c.get("cwe_id") in (None, "", 0)
    )

    # 3. PR-7 funnel (item 13 row 3): unit is a selected ARVO case; an admitted case is one record.
    funnels = {}
    for p in ls("data/validation"):
        if p.endswith("_funnel.json") and Path(p).name.startswith("pr7_"):
            f = json.loads(read(p))
            funnels[Path(p).stem] = f["funnel"]
    if funnels:
        steps = list(next(iter(funnels.values())))
        out["PR-7 funnel per batch (cases)"] = {
            k: [f[s] for s in steps] for k, f in funnels.items()
        }
        out["PR-7 funnel steps"] = steps
        tot = {s: sum(f[s] for f in funnels.values()) for s in steps}
        out["PR-7 proof -> CWE derived -> admitted (cases)"] = (
            f"{tot['proof']} -> {tot['CWE derived']} -> {tot['admitted']}; "
            f"{tot['proof'] - tot['CWE derived']} stopped at PR-4 (guard class undetermined or "
            "not admissible) and are not in the release"
        )
    mined = [r for r in rows if (r.get("dataflow_evidence") or "").startswith("Mined under")]
    out["PR-7 records in release: by tier"] = dict(collections.Counter(tier(r) for r in mined))

    # 4. Demotions (item 13 row 4): changelog EVENTS vs CURRENT gaps of a cohort.
    pr3 = [e for e in log if e.get("op") == "PR3-retier"]
    rule_events = collections.Counter(k.split("-")[0] for e in pr3 for k in (e.get("rules") or {}))
    only = collections.Counter(
        tuple(sorted({k.split("-")[0] for k in (e.get("rules") or {})})) for e in pr3
    )
    out["PR3-retier events (historical, from GOLD)"] = {
        "events": len(pr3),
        "distinct records": len({e["id"] for e in pr3}),
        "events citing I2 / of which I2 alone": f"{rule_events['I2']} / {only[('I2',)]}",
        "events citing I3 / of which I3 alone": f"{rule_events['I3']} / {only[('I3',)]}",
        "to": dict(collections.Counter(e.get("to") for e in pr3)),
    }
    last = {e["id"]: e.get("status") for e in log if e.get("op") == "arvo-rerun-attempt"}
    two = {i for i, s in last.items() if (s or "").startswith("differential")}
    miss = [r for r in rows if r["id"] in two and tier(r) != "gold"]
    gaps = [set(r.get("gold_contract_gaps") or {}) for r in miss]
    out["current: two-sided ARVO re-runs not GOLD (records, current gaps)"] = {
        "records": len(miss),
        "I3 (patch)": sum("I3" in g for g in gaps),
        "I2 (root contradicted)": sum("I2" in g for g in gaps),
        "I2-sink": sum("I2-sink" in g for g in gaps),
        "I4 (middle link)": sum("I4" in g for g in gaps),
    }

    # 5. Records, crashes, bugs, duplicates (item 13 row 5).
    n_cl = len(set(cl))
    multi = collections.Counter(cl)
    out["all records / bug clusters / extra rows (1 - clusters/records)"] = (
        f"{len(rows)} / {n_cl} / {pct(len(rows) - n_cl, len(rows))}"
    )
    in_multi = sum(1 for c in cl if multi[c] > 1)
    out["records in a multi-record cluster"] = f"{in_multi} ({pct(in_multi, len(rows))})"
    gcl = {cl[idx[r["id"]]] for r in gold}
    out["GOLD records / GOLD bug clusters"] = f"{len(gold)} / {len(gcl)}"
    out["records with duplicate_group (fix-commit groups, >=2 crashes)"] = sum(
        bool(r.get("duplicate_group")) for r in rows
    )
    span = collections.defaultdict(set)
    for r in rows:
        span[cl[idx[r["id"]]]].add(r.get("split"))
    out["bug clusters spanning splits"] = sum(len(v) > 1 for v in span.values())

    # 6. Projects (item 13 row 6).
    def src(r):
        p = r["provenance"]
        return (
            "ARVO/OSS-Fuzz"
            if p.startswith("arvo")
            else ("syzbot (linux-kernel)" if p == "syzbot" else f"{p}")
        )

    def nproj(rs):
        raw = len({r["project"] for r in rs})
        return f"{raw} / {len({codebase(r['project']) for r in rs})}"

    out["projects: raw names / canonical"] = nproj(rows)
    out["projects (raw) by source"] = {
        s: len({r["project"] for r in rows if src(r) == s}) for s in sorted({src(r) for r in rows})
    }
    out["GOLD projects: raw / canonical"] = nproj(gold)

    # 7. Localization (item 13 row 7, item 18).
    def has(c, k="file"):
        return bool(((c.get("evidence") or {}).get("location") or {}).get(k))

    out["GOLD: every link has a file (all GOLD, incl. stage decompositions)"] = sum(
        all(has(c) for c in r["chain"]) for r in gold
    )
    out["GOLD multi-weakness: both ends have a file (locality not None)"] = sum(
        locality(r) is not None for r in mw_gold
    )
    out["GOLD multi-weakness: both ends located but a middle link not (length 3)"] = sum(
        locality(r) is not None and not all(has(c) for c in r["chain"]) for r in mw_gold
    )
    out["GOLD stage decompositions with every link located"] = sum(
        all(has(c) for c in r["chain"]) for r in gold if r.get("chain_kind") != "multi-weakness"
    )

    def place(rs):
        c = collections.Counter(locality(r) for r in rs)
        known = c["in-function"] + c["cross-function"] + c["cross-file"]
        span = c["cross-function"] + c["cross-file"]
        return (
            f"n={len(rs)}, located={sum(v for k, v in c.items() if k)}, "
            f"placement known={known}, cross-function or cross-file={pct(span, known)}, "
            f"same-file fn unknown={c['same-file']}, unlocated={c[None]}"
        )

    out["locality, GOLD multi-weakness"] = place(mw_gold)
    out["locality, GOLD multi-weakness, root causally proven"] = place(
        [r for r in mw_gold if r["chain"][0].get("evidence_kind") == "causally-proven"]
    )
    out["locality, GOLD multi-weakness, evidence_floor execution or stronger"] = place(
        [r for r in mw_gold if r.get("evidence_floor") in ("execution", "causally-proven")]
    )
    added = [
        r["chain"][0]["evidence"]["causal_proof"].get("added_lines") or 0
        for r in mw_gold
        if r["chain"][0].get("evidence_kind") == "causally-proven"
    ]
    if added:
        out["proven guards: n / median added lines"] = f"{len(added)} / {statistics.median(added)}"

    # 8. Splits (item 17).
    out["split sizes by tier"] = {
        t: dict(collections.Counter(r.get("split") for r in rows if tier(r) == t))
        for t in ("gold", "gold-upstream", "silver", "bronze")
    }
    four = LEAKAGE_FIELDS["project+provenance+ecosystem+language"]
    out["leakage, leave-one-out over all records: 4 fields / majority baseline"] = (
        f"{100 * held_out_accuracy(rows, four):.1f}% / "
        f"{100 * held_out_accuracy(rows, LEAKAGE_FIELDS['baseline']):.1f}%"
    )
    train = [r for r in rows if r.get("split") == "train"]
    test = [r for r in rows if r.get("split") == "test"]
    seen = {four(r) for r in train}
    out["leakage, train->test: test records whose 4-field key occurs in train"] = (
        f"{sum(four(r) in seen for r in test)} of {len(test)}; every other test record is "
        "predicted as the train majority by construction (its project is never in train)"
    )
    return out


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--release", default="data/release")
    ap.add_argument("--rev", default=None)
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args(argv)
    read, ls = reader(args.rev)
    rel = args.release.rstrip("/")
    rows = jsonl(read(f"{rel}/dataset.jsonl"))
    log = jsonl(read(f"{rel}/corrections_changelog.jsonl"))
    if not rows:
        raise SystemExit(f"no dataset at {rel} (rev {args.rev or 'working tree'})")
    out = summarize(rows, log, read, ls)
    if args.json:
        print(json.dumps(out, indent=1))
        return 0
    print(f"# Release reconciliation ({args.rev or 'working tree'}, {rel})")
    for k, v in out.items():
        print(f"- {k}: {json.dumps(v) if isinstance(v, (dict, list)) else v}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
