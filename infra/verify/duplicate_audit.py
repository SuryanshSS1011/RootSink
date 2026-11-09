#!/usr/bin/env python3
"""Measure duplicates in the release: how many distinct bugs the rows are, and which leak.

A row is one (crash, chain) view; several rows can be one bug. Rows are joined into bug clusters
(union-find) when they share any of:
  crash    an OSS-Fuzz-/syzbot- id
  cve      a CVE alias
  fix      the 40-hex fix commit
  diff     the same changed lines (normalised patch body, exact)
  neardiff changed-line sets with Jaccard >= NEAR (backports, re-applied fixes)
Project names are also normalised (case, owner prefix, .git) to find one project filed under
several names, which a project-disjoint split cannot see.

Measurement only: nothing in the dataset is modified. Writes paper_artifacts/duplicate_audit.json.

Usage: duplicate_audit.py [--release data/release] [--out paper_artifacts/duplicate_audit.json]
"""

from __future__ import annotations

import argparse
import collections
import hashlib
import json
import re
from pathlib import Path

NEAR = 0.8
_SHA = re.compile(r"[0-9a-f]{40}(?![0-9a-f])")  # last 40 of a hex run (glued pointers)
# Changed lines this short or this generic say nothing about which bug a patch fixes.
_GENERIC = re.compile(r"^[{}();]*$|^(return\s*[\w-]*;|break;|else|goto \w+;)$")


class UnionFind:
    def __init__(self, n: int) -> None:
        self.parent = list(range(n))

    def find(self, i: int) -> int:
        while self.parent[i] != i:
            self.parent[i] = self.parent[self.parent[i]]
            i = self.parent[i]
        return i

    def union(self, a: int, b: int) -> None:
        self.parent[self.find(a)] = self.find(b)


def changed_lines(diff: str | None) -> list[str]:
    out = []
    for line in (diff or "").splitlines():
        if line == "-- ":
            break  # git format-patch signature separator: what follows is not a change
        if line.startswith(("+++", "---")) or not line.startswith(("+", "-")):
            continue
        body = re.sub(r"\s+", "", line[1:])
        if body and not _GENERIC.match(body):
            out.append(line[0] + body)
    return out


def norm_project(name: str) -> str:
    name = name.lower().removesuffix(".git")
    return name.rsplit("/", 1)[-1]


def keys(r: dict) -> dict[str, list[str]]:
    aliases = r.get("aliases") or []
    fixed = (r.get("commit_range") or {}).get("fixed") or ""
    lines = changed_lines(r.get("patch_diff"))
    return {
        "crash": [a for a in aliases if a.startswith(("OSS-Fuzz-", "syzbot-"))],
        "cve": [a for a in aliases if a.startswith("CVE-")],
        "fix": _SHA.findall(fixed)[:1],
        "diff": [hashlib.sha1("\n".join(lines).encode()).hexdigest()] if lines else [],
    }


def near_pairs(rows: list[dict]) -> list[tuple[int, int, float]]:
    sets = [frozenset(changed_lines(r.get("patch_diff"))) for r in rows]
    index = collections.defaultdict(list)
    for i, s in enumerate(sets):
        for line in s:
            index[line].append(i)
    candidates = set()
    for members in index.values():
        if 1 < len(members) <= 50:  # a line shared by >50 patches is boilerplate, not identity
            candidates.update((a, b) for k, a in enumerate(members) for b in members[k + 1 :])
    out = []
    for a, b in candidates:
        inter = len(sets[a] & sets[b])
        jac = inter / len(sets[a] | sets[b])
        if jac >= NEAR and sets[a] != sets[b]:
            out.append((a, b, round(jac, 3)))
    return out


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--release", default="data/release")
    ap.add_argument("--out", default="paper_artifacts/duplicate_audit.json")
    args = ap.parse_args(argv)
    with open(Path(args.release) / "dataset.jsonl") as fh:
        rows = [json.loads(line) for line in fh]

    uf = UnionFind(len(rows))
    by_kind: dict[str, dict] = {}
    for kind in ("crash", "cve", "fix", "diff"):
        groups = collections.defaultdict(list)
        for i, r in enumerate(rows):
            for k in keys(r)[kind]:
                groups[k].append(i)
        multi = {k: v for k, v in groups.items() if len(v) > 1}
        for members in multi.values():
            for m in members[1:]:
                uf.union(members[0], m)
        by_kind[kind] = {
            "groups": len(multi),
            "rows": sum(len(v) for v in multi.values()),
            "groups_spanning_splits": sum(
                len({rows[i].get("split") for i in v}) > 1 for v in multi.values()
            ),
        }

    near = near_pairs(rows)
    for a, b, _ in near:
        uf.union(a, b)
    by_kind["neardiff"] = {
        "pairs": len(near),
        "pairs_spanning_splits": sum(
            rows[a].get("split") != rows[b].get("split") for a, b, _ in near
        ),
        "pairs_with_different_fix": sum(
            keys(rows[a])["fix"] != keys(rows[b])["fix"] for a, b, _ in near
        ),
    }

    clusters = collections.defaultdict(list)
    for i in range(len(rows)):
        clusters[uf.find(i)].append(i)
    multi = [v for v in clusters.values() if len(v) > 1]
    leaking = [v for v in multi if len({rows[i].get("split") for i in v}) > 1]
    gold = [i for i, r in enumerate(rows) if r.get("label_confidence_tier") == "gold"]
    gold_clusters = {uf.find(i) for i in gold}
    gold_up = [
        i for i, r in enumerate(rows) if r.get("label_confidence_tier") in ("gold", "gold-upstream")
    ]

    projects = collections.defaultdict(set)
    proj_splits = collections.defaultdict(set)
    for r in rows:
        projects[norm_project(r["project"])].add(r["project"])
        proj_splits[norm_project(r["project"])].add(r.get("split"))
    aliased = {k: sorted(v) for k, v in projects.items() if len(v) > 1}

    report = {
        "rows": len(rows),
        "bug_clusters": len(clusters),
        "duplicate_rate": round(1 - len(clusters) / len(rows), 4),
        "rows_in_multi_row_clusters": sum(len(v) for v in multi),
        "clusters_spanning_splits": len(leaking),
        "rows_in_clusters_spanning_splits": sum(len(v) for v in leaking),
        "gold_rows": len(gold),
        "gold_bug_clusters": len(gold_clusters),
        "gold_or_upstream_rows": len(gold_up),
        "gold_or_upstream_bug_clusters": len({uf.find(i) for i in gold_up}),
        "by_key": by_kind,
        "near_threshold_jaccard": NEAR,
        "project_aliases": aliased,
        "aliased_projects_spanning_splits": sorted(k for k in aliased if len(proj_splits[k]) > 1),
        "leaking_clusters": [
            [
                {"id": rows[i]["id"], "split": rows[i].get("split"), "project": rows[i]["project"]}
                for i in sorted(v, key=lambda i: rows[i]["id"])
            ]
            for v in sorted(leaking, key=len, reverse=True)
        ],
    }
    Path(args.out).write_text(json.dumps(report, indent=1) + "\n")
    summary = {k: v for k, v in report.items() if k not in ("leaking_clusters", "project_aliases")}
    print(json.dumps(summary, indent=1))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
