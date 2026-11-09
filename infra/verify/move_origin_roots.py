#!/usr/bin/env python3
"""Make the tested site the root's site when a witnessed origin also has a tested hunk (1.0.7).

PR-4 kept a witnessed origin (MSan's creation site for CWE-456, the free of a CWE-416) as the
root's site even when a single-hunk test of the fix succeeded, and `locate_tested_sites.py`
stores that tested site as `evidence.tested_site`. The rule-log entry of 2026-11-09 (release
1.0.7) moves the root to the tested site instead:

  - `evidence.location` becomes the tested site, so `site_kind` is `tested-repair-site`;
  - the origin moves to `evidence.origin_site`;
  - the root keeps its CWE and its evidence, because the report still names the CWE;
  - if the test is later withdrawn (no `causal_proof` or `guard_site_proof`), the origin comes
    back as the site and the tested site moves to `withdrawn_tested_site`;
  - a tested site outside C/C++ source (a build file such as configure.ac) never becomes the
    root; such a root keeps, or gets back, its origin (verification of 2026-11-09).

Runs after locate_tested_sites.py in rebuild_derived.sh. Every move is logged with its rule.
Idempotent.

Usage: move_origin_roots.py [--release data/release] [--dry-run]
"""

from __future__ import annotations

import argparse
import collections
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))
from chainforge.evidence import site_kind  # noqa: E402

RULE = "PR-4 amendment 2026-11-09 (release 1.0.7)"
_CODE = re.compile(r"\.(c|cc|cpp|cxx|c\+\+|h|hh|hpp|hxx|inc|inl|ipp|tcc)$", re.I)


def _code(loc: dict | None) -> bool:
    return bool(_CODE.search((loc or {}).get("file") or ""))


def _site(loc: dict | None) -> str | None:
    return loc and f"{loc.get('file')}:{loc.get('line')} ({loc.get('stage')})"


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--release", default="data/release")
    ap.add_argument("--dry-run", action="store_true", help="count only, write nothing")
    args = ap.parse_args(argv)
    rel = Path(args.release)
    with open(rel / "dataset.jsonl") as fh:
        rows = [json.loads(line) for line in fh]
    log, stats = [], collections.Counter()
    for r in rows:
        root = (r.get("chain") or [{}])[0]
        ev = root.get("evidence") or {}
        prov = r.get("provenance") or ""
        tier = r.get("label_confidence_tier")
        proof = ev.get("causal_proof") or ev.get("guard_site_proof")
        if ev.get("origin_site") and not (proof and _code(ev.get("location"))):
            # The test behind the move was withdrawn, or its site is not source code: the
            # origin is the site again.
            why = "test withdrawn" if not proof else "tested site is not C/C++ source"
            if proof:
                ev["tested_site"] = ev.get("location")
            else:
                ev["withdrawn_tested_site"] = ev.get("location")
            ev["location"] = ev.pop("origin_site")
            root["site_kind"] = site_kind(root, prov)
            stats[f"restored {tier}"] += 1
            log.append({"id": r["id"], "op": "origin-root-restored", "rule": RULE, "why": why})
            continue
        ts = ev.get("tested_site")
        if not (proof and ts) or site_kind(root, prov) != "origin-site":
            continue
        if not _code(ts):
            stats[f"kept, tested site not source {tier}"] += 1
            continue
        old = ev.get("location")
        ev["origin_site"] = old
        ev["location"] = ts
        del ev["tested_site"]
        root["site_kind"] = site_kind(root, prov)
        if root["site_kind"] != "tested-repair-site":
            raise SystemExit(f"{r['id']}: moved root is {root['site_kind']}, not a tested site")
        stats[f"moved {tier}"] += 1
        log.append(
            {
                "id": r["id"],
                "op": "origin-root-moved",
                "rule": RULE,
                "site": _site(ts),
                "previous": _site(old),
            }
        )
    if not args.dry_run:
        with open(rel / "dataset.jsonl", "w") as fh:
            fh.writelines(json.dumps(r) + "\n" for r in rows)
        with open(rel / "corrections_changelog.jsonl", "a") as fh:
            fh.writelines(json.dumps(e) + "\n" for e in log)
    print(dict(stats))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
