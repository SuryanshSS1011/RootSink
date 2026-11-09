#!/usr/bin/env python3
"""Apply PREREGISTRATION PR-3 (I1-I6) to the release. Idempotent; never promotes.

Order matters and is fixed: drop byte-identical rows (I1), withdraw harness proofs (I6) and
re-stamp evidence kinds, collapse each crash to one claim (I1), then re-tier every GOLD record
with chainforge.integrity (I2-I5). Each change lands in corrections_changelog.jsonl with its
rule id; each removed record lands in dropped.jsonl with the record it lost to.

Promotion is NOT done here. A record re-earns GOLD only when new evidence is attached (kernel
differential, ARVO re-run, ablation) by the step that attaches it, which then calls the same
integrity rules.

Usage: apply_pr3.py [--release data/release] [--root .]
"""

from __future__ import annotations

import argparse
import collections
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))
from chainforge.evidence import (  # noqa: E402
    chain_kind,
    classify_link,
    floor,
    is_non_guard_path,
    locality,
)
from chainforge.integrity import (  # noqa: E402
    crash_facts,
    gold_violations,
    sink_contradiction,
    source_contradiction,
    tier_for,
    vul_log,
)

SOURCE_PRIORITY = {416: 0, 476: 1, 190: 2, 20: 3}


def withdraw_harness_proofs(rec: dict, log: list) -> None:
    for link in rec.get("chain") or []:
        ev = link.get("evidence") or {}
        cp = ev.get("causal_proof")
        if not cp or not is_non_guard_path(cp.get("file") or ""):
            continue
        ev["withdrawn_causal_proof"] = {
            **cp,
            "minimal_guard_patch": ev.pop("minimal_guard_patch", None),
            "reason": "PR-3 I6: the silencing hunk is in a fuzz harness/test file, so it shows "
            "the harness stopped feeding the input, not that the source guard was missing",
        }
        del ev["causal_proof"]
        ev["patch_hunk_ref"] = (
            f"guard ablation silenced the crash with a harness hunk ({cp.get('file')}); "
            "withdrawn, not evidence for the source"
        )
        log.append({"id": rec["id"], "op": "PR3-I6-withdraw-proof", "file": cp.get("file")})


def restamp(rec: dict) -> None:
    for link in rec.get("chain") or []:
        link["evidence_kind"] = str(classify_link(link.get("evidence")))
    rec["evidence_floor"] = str(floor(rec))
    rec["chain_kind"] = chain_kind([c["cwe_id"] for c in rec.get("chain") or []])
    rec["locality"] = locality(rec)


def crash_key(rec: dict) -> str:
    return next(
        (a for a in rec.get("aliases") or [] if a.startswith(("OSS-Fuzz-", "syzbot-"))), rec["id"]
    )


def claim(rec: dict) -> tuple[int, int]:
    return rec["chain"][0]["cwe_id"], rec["chain"][-1]["cwe_id"]


def main(argv) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--release", default="data/release")
    ap.add_argument("--root", default=".")
    args = ap.parse_args(argv)
    rel, root = Path(args.release), Path(args.root)
    with open(rel / "dataset.jsonl") as fh:
        rows = [json.loads(line) for line in fh]
    log, dropped, stats = [], [], collections.Counter()

    # I1a: byte-identical rows.
    seen, uniq = set(), []
    for r in rows:
        k = json.dumps(r, sort_keys=True)
        if k in seen:
            stats["I1 identical row removed"] += 1
            log.append({"id": r["id"], "op": "PR3-I1-identical-row-removed"})
            continue
        seen.add(k)
        uniq.append(r)

    # I6, then evidence kinds from what remains.
    for r in uniq:
        withdraw_harness_proofs(r, log)
        restamp(r)
    stats["I6 harness proofs withdrawn"] = sum(1 for e in log if e["op"] == "PR3-I6-withdraw-proof")

    # I1b: one claim per crash.
    facts = {}
    for r in uniq:
        p = vul_log(r, root)
        facts[r["id"]] = crash_facts(p.read_text(errors="replace")) if p else None
    groups = collections.defaultdict(list)
    for r in uniq:
        groups[crash_key(r)].append(r)
    keep_ids = {r["id"] for r in uniq}
    for views in groups.values():
        claims = {claim(r) for r in views}
        if len(claims) < 2:
            continue

        def rank(c, views=views):
            consistent = all(
                not source_contradiction(r, facts[r["id"]])
                and not sink_contradiction(r, facts[r["id"]])
                for r in views
                if claim(r) == c
            )
            return (not consistent, SOURCE_PRIORITY.get(c[0], 9), c)

        kept = min(claims, key=rank)
        kept_ids = [r["id"] for r in views if claim(r) == kept]
        for r in views:
            if claim(r) == kept:
                continue
            keep_ids.discard(r["id"])
            stats["I1 conflicting claim on one crash dropped"] += 1
            dropped.append(
                {
                    "id": r["id"],
                    "reason": "PR3-I1-conflicting-claim-on-one-crash",
                    "was": r["chain_string"],
                    "tier_was": r["label_confidence_tier"],
                    "kept": kept_ids,
                }
            )
            log.append({"id": r["id"], "op": "PR3-I1-dropped", "kept": kept_ids})
    out = [r for r in uniq if r["id"] in keep_ids]
    for r in out:
        if r.get("related_records"):
            r["related_records"] = [x for x in r["related_records"] if x in keep_ids]

    # I2-I5: re-tier GOLD. Never promotes.
    for r in out:
        if r["label_confidence_tier"] not in ("gold", "gold-upstream"):
            continue
        v = gold_violations(r, root, facts[r["id"]])
        new = tier_for(r, v)
        if new != r["label_confidence_tier"]:
            log.append(
                {
                    "id": r["id"],
                    "op": "PR3-retier",
                    "from": r["label_confidence_tier"],
                    "to": new,
                    "rules": v,
                }
            )
            stats[f"retier {r['label_confidence_tier']} -> {new}"] += 1
            for rule in v:
                stats[f"  failing {rule}"] += 1
            r["label_confidence_tier"] = new
        if v:
            r["gold_contract_gaps"] = v
        else:
            r.pop("gold_contract_gaps", None)

    with open(rel / "dataset.jsonl", "w") as fh:
        fh.writelines(json.dumps(r) + "\n" for r in out)
    with open(rel / "dropped.jsonl", "a") as fh:
        fh.writelines(json.dumps(d) + "\n" for d in dropped)
    with open(rel / "corrections_changelog.jsonl", "a") as fh:
        fh.writelines(json.dumps(e) + "\n" for e in log)
    for k, n in sorted(stats.items()):
        print(f"{n:6d}  {k}")
    print(f"{len(out):6d}  records; GOLD {sum(r['label_confidence_tier'] == 'gold' for r in out)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
