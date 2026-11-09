#!/usr/bin/env python3
"""Place every root cause whose hunk test succeeded at the tested hunk's site.

A successful single-hunk test (`causal_proof` or `guard_site_proof`) names the proving hunk by
its split index and file, but for a few records the stored site is another one (a KASAN
allocation or free stack, an MSan origin) and the hunk text was never archived. The hunk is
recomputed from the record's own `patch_diff` with the same splitter and order the test used
(split_hunks.py: code files only, smallest first) and accepted only if its name, file and
added-line count all match the test's record. Then:

  - a root whose site is not a witnessed origin takes the tested site (`guard_site`), and the
    site it had moves to `evidence.reported_site`;
  - a witnessed origin (MSan CWE-456, the free of a CWE-416) keeps its origin as the instance's
    site, which defines that CWE, and records the tested site as `evidence.tested_site`;
  - a `tested_site` whose test has since been withdrawn moves to `withdrawn_tested_site`.

Logged as `tested-site-located` with the record's previous site. Idempotent.

Usage: locate_tested_sites.py [--release data/release]
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent))
from split_hunks import split  # noqa: E402

from chainforge.evidence import guard_site, site_kind  # noqa: E402


def tested_hunk(patch_diff: str, proof: dict) -> str | None:
    hunks = sorted(split(patch_diff or ""), key=lambda h: h["added"] + h["removed"])
    name = proof.get("hunk") or ""
    if not (name.startswith("hunk") and name[4:6].isdigit()):
        return None
    i = int(name[4:6])
    h = hunks[i] if i < len(hunks) else None
    if h and h["file"] == proof.get("file") and h["added"] == proof.get("added_lines"):
        return h["patch"]
    # The runner's split can order hunks differently; accept the one hunk in the proof's file
    # with the proof's added-line count, and nothing if that is ambiguous.
    same = [
        x
        for x in hunks
        if x["file"] == proof.get("file") and x["added"] == proof.get("added_lines")
    ]
    return same[0]["patch"] if len(same) == 1 else None


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--release", default="data/release")
    args = ap.parse_args(argv)
    rel = Path(args.release)
    with open(rel / "dataset.jsonl") as fh:
        rows = [json.loads(line) for line in fh]
    log, stats = [], {"located": 0, "origin kept": 0, "hunk not reproduced": 0}
    for r in rows:
        root = (r.get("chain") or [{}])[0]
        ev = root.get("evidence") or {}
        proof = ev.get("causal_proof") or ev.get("guard_site_proof")
        if not proof and ev.get("tested_site"):
            # The test was withdrawn (e.g. its hunk applied only with fuzz): its site goes with it.
            ev["withdrawn_tested_site"] = ev.pop("tested_site")
            stats["withdrawn"] = stats.get("withdrawn", 0) + 1
            log.append({"id": r["id"], "op": "tested-site-withdrawn", "why": "no current test"})
            continue
        if not proof or ev.get("tested_site"):
            continue
        prov = r.get("provenance") or ""
        if site_kind(root, prov) == "tested-repair-site":
            continue
        hunk = tested_hunk(r.get("patch_diff"), proof)
        site = guard_site(hunk, proof.get("file") or "") if hunk else None
        if not site:
            stats["hunk not reproduced"] += 1
            continue
        old = ev.get("location")
        if site_kind(root, prov) == "origin-site":
            ev["tested_site"] = site
            stats["origin kept"] += 1
        else:
            if old:
                ev["reported_site"] = old
            ev["location"] = site
            stats["located"] += 1
        root["site_kind"] = site_kind(root, prov)
        log.append(
            {
                "id": r["id"],
                "op": "tested-site-located",
                "site": f"{site['file']}:{site['line']}",
                "previous": old and f"{old.get('file')}:{old.get('line')} ({old.get('stage')})",
                "kept_origin": "tested_site" in ev,
            }
        )
    with open(rel / "dataset.jsonl", "w") as fh:
        fh.writelines(json.dumps(r) + "\n" for r in rows)
    with open(rel / "corrections_changelog.jsonl", "a") as fh:
        fh.writelines(json.dumps(e) + "\n" for e in log)
    print(stats)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
