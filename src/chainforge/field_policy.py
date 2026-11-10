"""Who is allowed to see which field.

A dataset for RL has two audiences that must not be confused: the harness that builds splits
and computes rewards, and the POLICY being trained. Fields useful to the first are often
catastrophic to the second, and nothing in the record itself says which is which.

How much a field leaks the label is measured by `measure_leakage`: predict `chain_string` as
the majority arm among the OTHER records sharing the field's value (leave-one-out). An earlier
version measured it in-sample, which scores a value unique to one record as a perfect predictor
of that record; that made `fix_date` (64% of values unique) look like the worst leak at 69%,
when held out it is 33%. The real leaks are the descriptive identity fields - provenance and
project, and above all their combination.

The remedy is not to delete these fields - split construction and contamination control need
them - but to say plainly that they are harness inputs, and to give consumers a projection
that omits them.
"""

from __future__ import annotations

import collections
import re

# Safe to show the policy: describes the code and the weakness, not the record's identity.
MODEL_VISIBLE = frozenset(
    {
        "chain",
        "chain_string",
        "language",
        "locality",
        "sanitizer_reports",
        "patch_diff",
        "pov_input",
        "docker_image_ref",
    }
)

# Harness only. Each either identifies the record or encodes the label through provenance.
HARNESS_ONLY = frozenset(
    {
        "id",
        "aliases",
        "project",
        "provenance",
        "ecosystem",
        "split",
        "eval_stratum",
        "fix_date",
        "disclosure_date",
        "label_confidence_tier",
        "evidence_floor",
        "differential_complete",
        "commit_range",
        "datasheet_ref",
        "license",
        "related_records",
        "mitre_chain",
        "link_validation",
        "synthetic",
        "dataflow_evidence",
        "gold_contract_gaps",
        "kernel_attempt",  # 1.0.10: outcome of our last kernel attempt (correlates with tier)
        # Derived from runs and the root site: they place the root against the crash.
        "fix_attribution",
        "root_site_relation",
        "chain_kind",
        "duplicate_group",
        "sampling_weight",
        "rl_ready",
        "rl_scoring",
    }
)


def canonical_project(name: str) -> str:
    """One identity per codebase, for split construction. The same project arrives under several
    names - `imagemagick` (OSS-Fuzz) and `imagemagick/imagemagick` (a GitHub fix URL), or a fork
    such as `vadz/libtiff` - and a project-disjoint split keyed on the raw name puts one codebase
    in train and test. Case-folded, owner prefix and `.git` dropped, an OSS-Fuzz branch project
    (`libjpeg-turbo.2.0.x`, `.dev`, `.main`) folded into its codebase, and the names in
    `_PROJECT_ALIASES` mapped (release 1.0.5 corrections, item 4)."""
    n = name.lower().removesuffix(".git").rsplit("/", 1)[-1]
    n = _BRANCH_SUFFIX.sub("", n)
    return _PROJECT_ALIASES.get(n, n)


# One codebase under another name: an OSS-Fuzz project name, or a fix URL cut short.
_PROJECT_ALIASES = {"freetype2": "freetype", "cpython3": "cpython", "llama": "llama.cpp"}
# The Linux kernel arrives as `linux-kernel` (syzbot) and `linux` (NVD race advisories, and
# `torvalds/linux` from fix URLs). Splits keep the two apart on purpose (the kernel splits by
# subsystem, the advisory races are a catch-all), so they are merged only for counting codebases
# (release 1.0.9).
_COUNT_ALIASES = {"linux": "linux-kernel"}


def codebase(name: str) -> str:
    """The codebase a project name belongs to, for counting projects. Splits use
    `canonical_project`, which keeps the kernel's two pipelines apart."""
    n = canonical_project(name)
    return _COUNT_ALIASES.get(n, n)


_BRANCH_SUFFIX = re.compile(r"\.(dev|main|master|\d+(\.\d+)*\.x)$")


# Fields whose leakage the manifest and the paper report, as (name, key function).
LEAKAGE_FIELDS = {
    "baseline": lambda r: None,
    "fix_date": lambda r: r.get("fix_date"),
    "fix_date coarsened to year": lambda r: (r.get("fix_date") or "")[:4] or None,
    "project": lambda r: r.get("project"),
    "provenance": lambda r: r.get("provenance"),
    "ecosystem": lambda r: r.get("ecosystem"),
    "language": lambda r: r.get("language"),
    "locality": lambda r: r.get("locality"),
    "project+provenance+ecosystem+language": lambda r: (
        r.get("project"),
        r.get("provenance"),
        r.get("ecosystem"),
        r.get("language"),
    ),
}


def held_out_accuracy(rows: list[dict], key) -> float:
    """Leave-one-out majority-arm accuracy of predicting chain_string from key(record).

    A record is predicted from the others sharing its key; with no other record sharing it,
    from the corpus majority excluding itself. Ties break by Counter order, deterministically.
    """
    by_key: dict = collections.defaultdict(collections.Counter)
    total = collections.Counter(r["chain_string"] for r in rows)
    for r in rows:
        by_key[key(r)][r["chain_string"]] += 1
    hits = 0
    for r in rows:
        y = r["chain_string"]
        rest = by_key[key(r)].copy()
        rest[y] -= 1
        rest = +rest
        if not rest:
            rest = total.copy()
            rest[y] -= 1
        hits += rest.most_common(1)[0][0] == y
    return hits / len(rows) if rows else 0.0


def measure_leakage(rows: list[dict]) -> dict[str, float]:
    """Held-out label leakage per field, rounded to 3 places."""
    return {k: round(held_out_accuracy(rows, f), 3) for k, f in LEAKAGE_FIELDS.items()}


def annotation_view(record: dict) -> dict:
    """Every non-identity field, LABELS INCLUDED: the chain, each link's site, the fix.

    This is the view for reading or auditing annotations, and the source a harness scores
    against. It is never a model input for localization or labeling, because the chain, the
    sites and the fix are those tasks' targets. Task inputs come from `policy_view`,
    `localization_view` and `labeling_view`; targets from `task_target`."""
    return {k: v for k, v in record.items() if k in MODEL_VISIBLE}


# Kept for callers of the old name. It returns labels and sites, so it is NOT a task input.
model_view = annotation_view


def _site(link: dict) -> dict:
    loc = (link.get("evidence") or {}).get("location") or {}
    return {k: loc.get(k) for k in ("file", "line", "function")}


def policy_view(record: dict) -> dict:
    """Repair task input: the vulnerable program and its crash, nothing more.

    The fix, the chain and the patched image are the answer, so they stay on the reward side:
    the policy gets the vulnerable image, the crashing input and the vulnerable-side sink
    report(s). Intermediate witnesses (a UBSan overflow report) and patched runs are withheld:
    the first names a chain link, the second shows the fixed program's behaviour."""
    images = record.get("docker_image_ref") or {}
    return {
        "id": record.get("id"),
        "language": record.get("language"),
        "vulnerable_image": images.get("vulnerable"),
        "pov_input": record.get("pov_input"),
        "sanitizer_reports": [
            s
            for s in record.get("sanitizer_reports") or []
            if s.get("revision") == "vulnerable" and s.get("witnesses") != "intermediate"
        ],
    }


def localization_view(record: dict, with_fix: bool = False) -> dict:
    """Root-cause localization input: the repair input plus the sink's class and crash site.

    Target (`task_target(record, "localize")`): the source link's file, line and function.
    Withheld: every other link's site and CWE, the evidence text, `locality`, the patched image
    and runs, and the fix. `with_fix=True` is a separate, explicitly named condition in which the
    developer's diff is given; results under it must be reported as such."""
    v = policy_view(record)
    sink = (record.get("chain") or [{}])[-1]
    v["sink"] = {"cwe_id": sink.get("cwe_id"), **_site(sink)}
    if with_fix:
        v["patch_diff"] = record.get("patch_diff")
    return v


def labeling_view(record: dict, with_fix: bool = False) -> dict:
    """CWE labeling input: the repair input plus the chain's sites in order, with no CWE ids.

    Target (`task_target(record, "label")`): the ordered CWE ids. Withheld: `chain_string`,
    `mitre_chain`, `chain_kind`, every link's evidence text and the fix (unless `with_fix`)."""
    v = policy_view(record)
    v["sites"] = [_site(link) for link in record.get("chain") or []]
    if with_fix:
        v["patch_diff"] = record.get("patch_diff")
    return v


TASKS = ("repair", "localize", "label")


def task_target(record: dict, task: str):
    """The answer a harness scores against. Repair has none here: it is scored by replay."""
    chain = record.get("chain") or []
    if task == "repair":
        return None
    if task == "localize":
        return (_site(chain[0]) | {"site_kind": chain[0].get("site_kind")}) if chain else None
    if task == "label":
        return [link.get("cwe_id") for link in chain]
    raise ValueError(f"unknown task {task!r}; one of {TASKS}")


# Root sites a localization score uses by default: sites a hunk test placed. An origin site is
# printed in the sanitizer report the input already contains (MSan's origin block, the free
# stack), so scoring it rewards reading the input back; an annotated site is a rule's answer.
# Both are separate subsets, reported as such.
LOCALIZATION_ELIGIBLE = ("tested-repair-site",)


def localization_eligible(record: dict, kinds=LOCALIZATION_ELIGIBLE) -> bool:
    chain = record.get("chain") or []
    return bool(chain) and chain[0].get("site_kind") in kinds


def fixed_after(record: dict, cutoff: str) -> bool | None:
    """True if the record's fix commit is dated after `cutoff` (ISO date), None when undated.

    A cutoff-based holdout: evaluate a model only on fixes it cannot have seen in pretraining.
    Undated records are neither in nor out; report how many were excluded."""
    d = record.get("fix_date")
    return None if not d else d > cutoff


def leaky_fields(rows: list[dict], margin: float = 0.10) -> list[str]:
    """Single fields that beat the baseline by more than `margin`, worst first."""
    m = measure_leakage(rows)
    items = [
        (k, v)
        for k, v in m.items()
        if "+" not in k and k != "baseline" and v - m["baseline"] > margin
    ]
    return [k for k, _ in sorted(items, key=lambda kv: -kv[1])]
