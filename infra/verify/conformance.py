#!/usr/bin/env python3
"""Check the release against docs/SPECIFICATION.md.

No prior dataset labels ordered multi-CWE causal chains with per-link execution evidence, so
the conventions in SPECIFICATION.md are ours to hold. A specification nobody executes decays
into a description of whatever the data happens to be, which is the failure mode this guards
against: every rule that can be checked mechanically is checked here, and the release is not
shippable while any hard rule fails.

Exit status is non-zero if any HARD rule is violated, so this can gate a release.

Usage: conformance.py [data/release/dataset.jsonl] [--fix-observed-by]
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
from chainforge.evidence import (  # noqa: E402
    causal_proof_defect,
    guard_evidence_defect,
    patch_is_content,
)
from chainforge.field_policy import canonical_project  # noqa: E402
from chainforge.integrity import gold_violations, tier_for  # noqa: E402

# Provenances we executed ourselves; everything kernel-side cites syzbot's own run.
SELF_RUN = {"arvo", "arvo-len3", "arvo-newarm", "arvo-msan", "osv-git", "nvd-mined"}


def audit(rows, root=Path(".")):
    hard, soft = collections.Counter(), collections.Counter()
    ids = collections.Counter(r.get("id") for r in rows)
    hard["I1  record id is not unique"] = sum(n - 1 for n in ids.values() if n > 1)
    claims = collections.defaultdict(set)
    for r in rows:
        crash = next(
            (a for a in r.get("aliases") or [] if a.startswith(("OSS-Fuzz-", "syzbot-"))), None
        )
        if crash and r.get("chain"):
            claims[crash].add((r["chain"][0]["cwe_id"], r["chain"][-1]["cwe_id"]))
    hard["I1  one crash carries conflicting claims"] = sum(len(c) > 1 for c in claims.values())
    group_splits = collections.defaultdict(set)
    for r in rows:
        if r.get("duplicate_group"):
            group_splits[r["duplicate_group"]].add(r.get("split"))
    hard["R9  a duplicate group (one bug) spans splits"] = sum(
        len(v) > 1 for v in group_splits.values()
    )
    project_splits = collections.defaultdict(set)
    for r in rows:
        proj = canonical_project(r.get("project") or "")
        if proj not in ("linux-kernel", "linux"):  # subsystem-split; nvd-race catch-all
            project_splits[proj].add(r.get("split"))
    hard["R9  a project (canonical name) spans splits"] = sum(
        len(v) > 1 for v in project_splits.values()
    )
    from fix_p0_metadata import split_unit  # the kernel's split unit is its subsystem

    subsystem_splits = collections.defaultdict(set)
    for r in rows:
        if canonical_project(r.get("project") or "") == "linux-kernel":
            subsystem_splits[split_unit(r)].add(r.get("split"))
    hard["R9  a linux-kernel subsystem spans splits"] = sum(
        len(v) > 1 for v in subsystem_splits.values()
    )
    for r in rows:
        # PR-3: the GOLD contract, checked by the same code that assigns the tier.
        if r.get("label_confidence_tier") in ("gold", "gold-upstream"):
            v = gold_violations(r, root)
            if tier_for(r, v) != r["label_confidence_tier"]:
                for rule in v or {"tier": ""}:
                    hard[f"{rule:<4}{r['label_confidence_tier']} record breaks PR-3 {rule}"] += 1
        chain = [c for c in (r.get("chain") or []) if isinstance(c, dict)]

        # R1: ordered, admissible pairs
        if not chain or not validate_chain([c["cwe_id"] for c in chain]).admissible:
            hard["R1  chain is not an admissible ordered pair sequence"] += 1

        # R2: nothing composed
        if r.get("synthetic"):
            hard["R2  synthetic or composed record shipped"] += 1

        # R3: evidence is per link
        for c in chain:
            ev = c.get("evidence") or {}
            if not any(
                ev.get(k)
                for k in ("sanitizer_report_ref", "patch_hunk_ref", "dataflow_path", "location")
            ):
                soft["R3  link declares no evidence of any kind"] += 1

        # R5: tiers are a reproduction contract
        if r.get("label_confidence_tier") == "gold":
            d = r.get("patch_diff") or ""
            if not d:
                hard["R5  GOLD without a patch"] += 1
            elif not patch_is_content(d):
                hard["R5  GOLD whose patch is a reference, not content"] += 1
            else:
                # Content is necessary, not sufficient: the diff must be able to CARRY the
                # guard. curl's resolved fix for a use-after-free touches only Makefile.am;
                # skia's touches only its fuzz harness; 22 diffs are cut mid-hunk. Each is a
                # well-formed patch that cannot support the counterfactual GOLD asserts.
                sha = re.search(r"[0-9a-f]{40}", (r.get("commit_range") or {}).get("fixed") or "")
                why = guard_evidence_defect(d, sha.group(0) if sha else "")
                if why:
                    soft["R5  GOLD patch cannot carry a guard: " + why.split(" (")[0]] += 1
            if not any(s.get("triggered") for s in r.get("sanitizer_reports") or []):
                hard["R5  GOLD without a triggered sanitizer report"] += 1
            if r.get("synthetic"):
                hard["R5  GOLD marked synthetic"] += 1

        # R3: a causally-proven source is the dataset's strongest evidence kind, so the
        # hunk it rests on has to be able to bear it. A harness clamp silences the crash
        # without fixing anything, which the ablation cannot distinguish on its own.
        for c in r.get("chain") or []:
            why = causal_proof_defect(c.get("evidence"))
            if why:
                hard["R3  causal proof rests on a non-source hunk"] += 1

        # R5: differential_complete means a CLEAN patched run exists
        if r.get("differential_complete") and not any(
            s.get("revision") == "patched" and not s.get("triggered")
            for s in r.get("sanitizer_reports") or []
        ):
            hard["R5  differential_complete without a clean patched run"] += 1

        # R6: observation provenance declared
        for s in r.get("sanitizer_reports") or []:
            if not s.get("observed_by"):
                soft["R6  sanitizer report without observed_by"] += 1
    return +hard, +soft


def fix_observed_by(rows):
    """Backfill R6 from provenance: kernel records cite syzbot's run, the rest are ours."""
    n = 0
    for r in rows:
        prov = r.get("provenance")
        for s in r.get("sanitizer_reports") or []:
            if s.get("observed_by"):
                continue
            s["observed_by"] = "self" if prov in SELF_RUN else "upstream"
            n += 1
    return n


def main(argv):
    ap = argparse.ArgumentParser()
    ap.add_argument("dataset", nargs="?", default="data/release/dataset.jsonl")
    ap.add_argument(
        "--fix-observed-by",
        action="store_true",
        help="backfill R6 from provenance and rewrite the dataset in place",
    )
    args = ap.parse_args(argv)

    with open(args.dataset) as fh:
        rows = [json.loads(x) for x in fh if x.strip()]

    if args.fix_observed_by:
        n = fix_observed_by(rows)
        with open(args.dataset, "w") as fh:
            for r in rows:
                fh.write(json.dumps(r) + "\n")
        print(f"R6: stamped observed_by on {n} reports")

    hard, soft = audit(rows)
    print(f"\nconformance against docs/SPECIFICATION.md — {len(rows)} records")
    print("\nHARD (release-blocking):")
    for k, v in hard.most_common() or [("none", 0)]:
        print(f"  {v:6d}  {k}" if v else "  none")
    print("\nSOFT (must be disclosed, not blocking):")
    for k, v in soft.most_common() or [("none", 0)]:
        print(f"  {v:6d}  {k}" if v else "  none")
    return 1 if hard else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
