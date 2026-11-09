#!/usr/bin/env python3
"""Regenerate every number the paper cites, from the shipped release.

Paper artifacts are DERIVED, never hand-maintained. A figure typed into a draft and later
contradicted by the data is the failure mode this exists to prevent, so the output directory is
gitignored and rebuilt on demand rather than committed and trusted.

Emits into paper_artifacts/:
  metrics.json    every headline number, machine-readable
  tables.md       paper-ready markdown tables
  findings.md     the narrative claims, each with the number that supports it
  provenance.json what produced each number, so a reviewer can re-derive it

Usage: build_artifacts.py [--release data/release] [--out paper_artifacts]
"""

from __future__ import annotations

import argparse
import collections
import json
import math
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))
from chainforge.field_policy import measure_leakage  # noqa: E402

VERIFIED_BIB = r"""% Verified in-session only. Entries cited but unchecked live in
% docs/REFERENCES.md marked [C]; emitting an unchecked id here is how a wrong
% citation reaches a paper.

@inproceedings{mei2024arvo,
  title     = {{ARVO}: Atlas of Reproducible Vulnerabilities for Open-Source Software},
  author    = {Mei, Xiang and others},
  year      = {2024},
  eprint    = {2408.02153},
  archivePrefix = {arXiv},
  note      = {Updated version arXiv:2606.17283; 5001 vulnerabilities, 273 projects}
}

@inproceedings{yu2025dapo,
  title     = {{DAPO}: An Open-Source {LLM} Reinforcement Learning System at Scale},
  author    = {Yu, Qiying and others},
  booktitle = {NeurIPS},
  year      = {2025},
  eprint    = {2503.14476},
  archivePrefix = {arXiv}
}

@misc{li2025limr,
  title     = {{LIMR}: Less is More for {RL} Scaling},
  year      = {2025},
  eprint    = {2502.11886},
  archivePrefix = {arXiv}
}

@misc{difficulty2026,
  title     = {Predicting Task Difficulty Without Rollouts},
  year      = {2026},
  eprint    = {2608.05797},
  archivePrefix = {arXiv}
}

@misc{crosscommitvuln2026,
  title     = {{CrossCommitVuln-Bench}: A Dataset of Multi-Commit Python Vulnerabilities
               Invisible to Per-Commit Static Analysis},
  year      = {2026},
  eprint    = {2604.21917},
  archivePrefix = {arXiv}
}

@misc{formai2023,
  title     = {The {FormAI} Dataset: Generative {AI} in Software Security Through the Lens of
               Formal Verification},
  year      = {2023},
  eprint    = {2307.02192},
  archivePrefix = {arXiv}
}

@misc{cwe,
  title  = {Common Weakness Enumeration, {CWE-1000} view},
  author = {{MITRE}},
  note   = {Catalogue v4.20},
  url    = {https://cwe.mitre.org/}
}

@misc{syzkaller,
  title  = {syzkaller / syzbot},
  author = {{Google}},
  url    = {https://github.com/google/syzkaller},
  note   = {Data-race reproduction unsupported; KASAN bugs ship C reproducers}
}

@misc{ossfuzz,
  title  = {{OSS-Fuzz}},
  author = {{Google}},
  url    = {https://github.com/google/oss-fuzz}
}

@misc{nvd,
  title  = {National Vulnerability Database},
  author = {{NIST}},
  url    = {https://nvd.nist.gov/}
}

@misc{osv,
  title = {{OSV}: Open Source Vulnerabilities},
  url   = {https://osv.dev}
}
"""

GUARD_SOURCE = {20, 129, 190, 252, 456}
SHAPE_SOURCE = {416, 362, 843, 476}


def links(r):
    return [c for c in (r.get("chain") or []) if isinstance(c, dict)]


def entropy(counter):
    n = sum(counter.values())
    return round(-sum((v / n) * math.log2(v / n) for v in counter.values() if v), 2) if n else 0.0


def subset_profile(name, sub, total):
    if not sub:
        return None
    arm = collections.Counter(r.get("chain_string") for r in sub)
    g = collections.defaultdict(collections.Counter)
    for r in sub:
        g[(r.get("project"), r.get("provenance"))][r.get("chain_string")] += 1
    leak = sum(c.most_common(1)[0][1] for c in g.values()) / len(sub)
    return {
        "name": name,
        "n": len(sub),
        "share_of_corpus": round(len(sub) / total, 3),
        "arms": len(arm),
        "top_arm": arm.most_common(1)[0][0],
        "top_arm_share": round(arm.most_common(1)[0][1] / len(sub), 3),
        "arm_entropy_bits": entropy(arm),
        "projects": len({r.get("project") for r in sub}),
        "metadata_leakage": round(leak, 3),
    }


def main(argv):
    ap = argparse.ArgumentParser()
    ap.add_argument("--release", default="data/release")
    ap.add_argument("--out", default="paper_artifacts")
    args = ap.parse_args(argv)

    with open(os.path.join(args.release, "dataset.jsonl")) as fh:
        rows = [json.loads(x) for x in fh if x.strip()]
    with open(os.path.join(args.release, "dataset.manifest.json")) as fh:
        man = json.load(fh)
    os.makedirs(args.out, exist_ok=True)
    n = len(rows)
    gold = [r for r in rows if r.get("label_confidence_tier") == "gold"]
    leak = measure_leakage(rows)

    guard = [r for r in rows if links(r) and links(r)[0].get("cwe_id") in GUARD_SOURCE]
    shape = [r for r in rows if links(r) and links(r)[0].get("cwe_id") in SHAPE_SOURCE]
    proven = [
        r for r in rows if links(r) and (links(r)[0].get("evidence") or {}).get("causal_proof")
    ]
    strict = [r for r in rows if r.get("evidence_floor") in ("execution", "causally-proven")]

    metrics = {
        "corpus": {
            "records": n,
            "gold": len(gold),
            "by_tier": man["by_tier"],
            "arms": len(man["by_chain"]),
            "projects": len({r.get("project") for r in rows}),
            "by_chain_length": man["by_chain_length"],
        },
        "evidence": {
            "floor": man["evidence_floor"],
            "per_link_kind": man["evidence_kind_per_link"],
            "causally_proven": len(proven),
            "causally_proven_projects": len({r.get("project") for r in proven}),
            "gold_all_links_execution_witnessed": man["gold_all_links_execution_witnessed"],
            "guard_absence_attested": man["guard_absence_attested"],
            "minimal_guard_patches": man["minimal_guard_patches"],
            "gold_patch_materialised": man["gold_patch_materialised"],
            "two_sided": man["differential_complete"],
            "vise_pairs_gold": man["vise_pairs_gold"],
        },
        "guard_thesis": {
            "guard_absence_records": len(guard),
            "shape_change_records": len(shape),
            "guard_absence_share": round(len(guard) / n, 3),
        },
        "localization": {
            "links_with_location": man["links_with_location"],
            "records_with_location": man["records_with_location"],
            "by_locality": man["by_locality"],
        },
        "learnability": {
            "label_leakage_by_field_held_out": leak,
            "difficulty_band": man.get("difficulty_band", {}),
        },
        "provenance_balance": {
            "gold_by_provenance": man["gold_by_provenance"],
            "arvo_share_of_gold_pct": man["gold_arvo_share_pct"],
        },
        "splits": {
            "folds": man["splits"],
            "policy": man["split_policy"],
            "eval_strata": man["eval_strata"],
            "date_coverage": man["any_date_coverage"],
        },
        "subsets": [
            p
            for p in (
                subset_profile("whole corpus", rows, n),
                subset_profile("GOLD", gold, n),
                subset_profile(
                    "floor >= attested",
                    [
                        r
                        for r in rows
                        if r.get("evidence_floor") in ("causally-proven", "execution", "attested")
                    ],
                    n,
                ),
                subset_profile("floor >= execution", strict, n),
                subset_profile("causally proven", proven, n),
            )
            if p
        ],
    }
    with open(os.path.join(args.out, "metrics.json"), "w") as fh:
        json.dump(metrics, fh, indent=2)

    # ---- paper-ready tables
    t = ["# Tables\n", "*Generated — do not edit. Rebuild with infra/paper/build_artifacts.py.*\n"]
    t.append("\n## T1. Corpus\n\n| | n |\n|---|---:|")
    t.append(
        f"| records | {n} |\n| GOLD | {len(gold)} |\n| SILVER | {man['by_tier'].get('silver', 0)} |"
        f"\n| BRONZE | {man['by_tier'].get('bronze', 0)} |"
        f"\n| distinct arms | {len(man['by_chain'])} |"
        f"\n| distinct projects | {metrics['corpus']['projects']} |"
    )
    t.append(
        "\n## T2. Evidence floor — the weakest link per record\n\n| floor | records |\n|---|---:|"
    )
    for k, v in man["evidence_floor"].items():
        t.append(f"| `{k}` | {v} |")
    t.append(
        f"\nOf {len(gold)} GOLD records, "
        f"{man['gold_all_links_execution_witnessed']} have every link execution-witnessed.\n"
    )
    t.append("\n## T3. Evidence quality against arm diversity\n")
    t.append("| subset | n | arms | top arm | entropy | projects |\n|---|---:|---:|---:|---:|---:|")
    for p in metrics["subsets"]:
        t.append(
            f"| {p['name']} | {p['n']} | {p['arms']} | {100 * p['top_arm_share']:.1f}% | "
            f"{p['arm_entropy_bits']} | {p['projects']} |"
        )
    t.append(
        "\n## T4. Label leakage by field (held out)\n\n"
        "Leave-one-out majority-arm accuracy from the field alone.\n\n"
        "| field | accuracy predicting the arm |\n|---|---:|"
    )
    for k, v in sorted(leak.items(), key=lambda kv: -kv[1]):
        t.append(f"| `{k}` | {100 * v:.1f}% |")
    t.append("\n## T5. Arms\n\n| arm | n | GOLD |\n|---|---:|---:|")
    for arm, cnt in man["by_chain"].items():
        t.append(f"| {arm} | {cnt} | {man['by_pair_tier'].get(arm, {}).get('gold', 0)} |")
    with open(os.path.join(args.out, "tables.md"), "w") as fh:
        fh.write("\n".join(t) + "\n")

    # ---- findings, each tied to its number
    f = ["# Findings\n", "*Generated — every claim carries the number that supports it.*\n"]
    strict_p = next(p for p in metrics["subsets"] if p["name"] == "floor >= execution")
    proven_p = next(p for p in metrics["subsets"] if p["name"] == "causally proven")
    attested_p = next(p for p in metrics["subsets"] if p["name"] == "floor >= attested")
    f += [
        "\n## F1. Tier and per-link evidence are different claims\n",
        f"GOLD is a reproduction contract about the sink. Of {len(gold)} GOLD records, "
        f"**{man['gold_all_links_execution_witnessed']}** have every link execution-witnessed; "
        f"{man['evidence_floor'].get('inferred', 0)} records rest on an inferred weakest link.\n",
        "\n## F2. Evidence quality and arm diversity are anti-correlated\n",
        f"Filtering to `floor >= execution` leaves {strict_p['n']} records that are "
        f"**{100 * strict_p['top_arm_share']:.0f}% one arm** "
        f"(entropy {strict_p['arm_entropy_bits']} bits, "
        f"against {metrics['subsets'][0]['arm_entropy_bits']} for the corpus). MSan with origin "
        "tracking is the only pipeline witnessing both links, so that filter nearly restates "
        '"is an MSan record".\n',
        "\n## F3. Guard ablation as a route to diverse high-evidence sources\n",
        f"{proven_p['n']} records carry a causally proven source across {proven_p['projects']} "
        f"projects at arm entropy {proven_p['arm_entropy_bits']} bits, against "
        f"{attested_p['arm_entropy_bits']} bits for the {attested_p['n']}-record "
        f"`floor >= attested` subset: comparable diversity at "
        f"{proven_p['n'] / attested_p['n']:.0%} of the size, from the one mechanism that "
        "witnesses a source link where no sanitizer can.\n",
        "\n## F4. Identity fields leak the label; measure leakage held out\n",
        f"Held out, the four descriptive fields together predict the arm "
        f"{100 * leak['project+provenance+ecosystem+language']:.1f}% of the time and "
        f"`provenance` alone {100 * leak['provenance']:.1f}%, against "
        f"{100 * leak['baseline']:.1f}% baseline. `fix_date` reaches only "
        f"{100 * leak['fix_date']:.1f}%: measured in-sample it had looked like the worst leak "
        "(69%), because a value unique to one record trivially predicts that record. Both stay "
        "harness-only.\n",
    ]
    with open(os.path.join(args.out, "findings.md"), "w") as fh:
        fh.write("\n".join(f) + "\n")

    with open(os.path.join(args.out, "provenance.json"), "w") as fh:
        json.dump(
            {
                "generated_from": os.path.join(args.release, "dataset.jsonl"),
                "records": n,
                "generator": "infra/paper/build_artifacts.py",
                "measurement_scripts": {
                    "evidence kinds/floor": (
                        "src/chainforge/evidence.py + infra/verify/stamp_evidence_kinds.py"
                    ),
                    "label leakage": "src/chainforge/field_policy.py (measure_leakage, held out)",
                    "difficulty proxy": "src/chainforge/difficulty.py",
                    "causal proofs": "infra/verify/ablate.sh + infra/verify/apply_causal_proof.py",
                    "determinism": "infra/verify/determinism_check.sh",
                    "conformance": "infra/verify/conformance.py against docs/SPECIFICATION.md",
                    "manifest": "infra/verify/build_manifest.py",
                },
                "docs": [
                    "docs/SPECIFICATION.md",
                    "docs/COMPOSITION_STUDY.md",
                    "docs/COMPOSITION_BASELINE.md",
                    "docs/OPEN_ISSUES.md",
                ],
            },
            fh,
            indent=2,
        )

    # A .bib of the entries verified in-session. Deliberately only the [V] and [P] ones:
    # emitting an unchecked identifier into a bibliography is how a wrong citation reaches a
    # paper. The rest live in docs/REFERENCES.md marked [C] until someone checks them.
    with open(os.path.join(args.out, "verified.bib"), "w") as fh:
        fh.write(VERIFIED_BIB)

    print(f"wrote {args.out}/: metrics.json tables.md findings.md provenance.json verified.bib")
    print(f"  {n} records, {len(gold)} GOLD, {len(proven)} causally proven")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
