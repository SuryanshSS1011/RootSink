#!/usr/bin/env python3
"""Materialise fix patches that could not be fetched from their own forge, via GitHub mirrors.

PR-3 I3 demotes a record whose `patch_diff` cannot carry a guard. For most of the silver records
that fail I3 with "not a patch", our two-sided run passed and the only gap is that the fix commit
lives on a forge we never fetched from (gitweb, googlesource, freedesktop/gnome GitLab, cgit).
Most of those projects keep official GitHub mirrors, and a git commit id names the same content
on every mirror, so the patch is fetched from the mirror by that id and accepted only if

  * `git format-patch` reproduces a `From <sha>` header naming exactly the recorded fix commit, and
  * `chainforge.evidence.guard_evidence_defect` finds no defect in it.

Nothing else about the record is taken from the mirror. A harness-only or doc-only fix still
fails I3 after a correct fetch, and stays demoted (OPEN_ISSUES #18). Hosts whose ids are not git
ids (Mercurial on heptapod and hg.nginx.org, Subversion revisions) are skipped, not guessed.

With `--apply`, each accepted patch replaces `patch_diff` (clipped on hunk boundaries), the
source link is re-attested from it exactly as apply_materialized_patches.py does, and the record
is re-tiered by chainforge.integrity in either direction. Every attempt is logged.

Usage: fetch_mirror_patches.py [--release data/release] [--cache DIR] [--apply]
"""

from __future__ import annotations

import argparse
import collections
import json
import re
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent))
from apply_materialized_patches import GUARD_SOURCE, STRONG, guard_hits  # noqa: E402
from fetch_fix_diffs import MIRROR  # noqa: E402

from chainforge.evidence import (  # noqa: E402
    classify_link,
    clip_patch,
    floor,
    guard_evidence_defect,
)
from chainforge.integrity import gold_violations, tier_for  # noqa: E402

RULE = "patch-materialized-mirror"
SHA = re.compile(r"(?<![0-9a-f])([0-9a-f]{40})(?![0-9a-f])")
FROM = re.compile(r"^From ([0-9a-f]{40}) ", re.M)

# The forge -> GitHub mirror map is shared with the ablation fetcher (fetch_fix_diffs.MIRROR).


def candidates(rows: list[dict]) -> list[tuple[dict, str, str]]:
    """(record, sha, mirror) for silver records whose only I3 defect a correct fetch can cure."""
    out = []
    for r in rows:
        gaps = r.get("gold_contract_gaps") or {}
        why = gaps.get("I3") or ""
        if r["label_confidence_tier"] != "silver" or not why:
            continue
        if not (why == "not a patch" or why.startswith(("truncated", "sha mismatch"))):
            continue
        fixed = (r.get("commit_range") or {}).get("fixed") or ""
        ptr = r.get("patch_diff") or ""
        m = SHA.search(fixed) or (SHA.search(ptr) if "diff --git" not in ptr else None)
        if not m:
            continue
        where = fixed if "://" in fixed or fixed.startswith("git:") else ptr
        host = re.sub(r"^\w+://", "", where).split("/")[0]
        proj = (r.get("project") or "").split("/")[-1].lower()
        if host == "github.com":
            parts = re.sub(r"^\w+://", "", where).split("/")
            mirror = f"{parts[1]}/{parts[2]}" if len(parts) > 2 else None
        else:
            mirror = MIRROR.get(f"{host}:{proj}") or MIRROR.get(host)
        if mirror:
            out.append((r, m.group(1), mirror))
    return out


def fetch(mirror: str, sha: str, cache: Path) -> str | None:
    repo = cache / mirror.replace("/", "__")
    if not (repo / ".git").is_dir():
        subprocess.run(["git", "init", "-q", str(repo)], check=True)
    git = ["git", "-C", str(repo)]
    url = f"https://github.com/{mirror}"
    got = subprocess.run(
        [*git, "fetch", "-q", "--depth", "2", "--filter=blob:none", url, sha],
        capture_output=True,
        text=True,
        timeout=900,
    )
    if got.returncode != 0:
        return None
    pat = subprocess.run(
        [*git, "format-patch", "-1", "--stdout", sha],
        capture_output=True,
        text=True,
        errors="replace",
        timeout=900,
    )
    return pat.stdout if pat.returncode == 0 else None


def attest_source(rec: dict, diff: str) -> str | None:
    chain = rec.get("chain") or []
    if not chain or chain[0].get("cwe_id") not in GUARD_SOURCE:
        return None
    src, hits = chain[0]["cwe_id"], guard_hits(diff)
    ev = chain[0].setdefault("evidence", {})
    if ev.get("causal_proof"):
        return None  # a proof outranks a patch signal; never overwrite it
    if any(h in STRONG for h in hits):
        ev["patch_hunk_ref"] = (
            f"fix adds a guard ({', '.join(hits[:3])}); CWE-{src} source attested "
            "by the patch, not assumed"
        )[:160]
        return "source attested"
    ev["patch_hunk_ref"] = (
        f"CWE-{src} source NOT attested: the fix carries no added guard "
        f"({', '.join(hits) if hits else 'no signal'})"
    )[:160]
    return "source marked unattested"


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--release", default="data/release")
    ap.add_argument("--cache", default="/tmp/cf_mirrors")
    ap.add_argument("--apply", action="store_true")
    args = ap.parse_args(argv)
    rel, cache = Path(args.release), Path(args.cache)
    cache.mkdir(parents=True, exist_ok=True)
    with open(rel / "dataset.jsonl") as fh:
        rows = [json.loads(line) for line in fh]

    log, stats = [], collections.Counter()
    for r, sha, mirror in candidates(rows):
        patch = fetch(mirror, sha, cache)
        m = FROM.search(patch or "")
        if not patch or not m:
            status = "mirror fetch failed"
        elif m.group(1) != sha:
            status = f"sha mismatch from mirror ({m.group(1)[:12]})"
        else:
            patch = clip_patch(patch, 200_000)
            defect = guard_evidence_defect(patch, sha)
            status = f"fetched, still defective: {defect}" if defect else "fetched, carries guard"
        stats[status.split(":")[0]] += 1
        entry = {"id": r["id"], "op": RULE, "mirror": mirror, "sha": sha, "status": status}
        if args.apply and status == "fetched, carries guard":
            r["patch_diff"] = patch
            if note := attest_source(r, patch):
                entry["source"] = note
                stats[note] += 1
            for link in r["chain"]:
                link["evidence_kind"] = str(classify_link(link.get("evidence")))
            r["evidence_floor"] = str(floor(r))
            v = gold_violations(r, Path("."))
            new = tier_for(r, v)
            if new != r["label_confidence_tier"]:
                entry.update({"from": r["label_confidence_tier"], "to": new})
                stats[f"retier {r['label_confidence_tier']} -> {new}"] += 1
                r["label_confidence_tier"] = new
            if v:
                r["gold_contract_gaps"] = v
            else:
                r.pop("gold_contract_gaps", None)
        log.append(entry)
        print(json.dumps(entry), flush=True)

    for k, n in sorted(stats.items()):
        print(f"{n:6d}  {k}")
    if args.apply:
        with open(rel / "dataset.jsonl", "w") as fh:
            fh.writelines(json.dumps(r) + "\n" for r in rows)
        with open(rel / "corrections_changelog.jsonl", "a") as fh:
            fh.writelines(json.dumps(e) + "\n" for e in log)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
