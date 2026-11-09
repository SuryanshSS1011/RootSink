#!/usr/bin/env python3
"""Supply for the fuzz check of single-hunk and hunk-pair tests (PR-4 and PR-13 amendment).

The hunk tests applied each hunk with GNU patch's default fuzz, which lets a hunk land where up
to two context lines do not match. This lists every ARVO-backed record whose root carries a
`causal_proof`, `guard_site_proof` or `tested_pair`, with the hunk(s) the test applied (by the
splitter's name, file and added-line count, as the test recorded them) and the fix URL the test
fetched. The runner re-fetches the diff, re-splits it, and dry-runs each test's hunks on the
vulnerable image at fuzz 0, then at the default fuzz (`scripts/fuzz_check.sh`).

Writes data/validation/fuzzcheck_supply.json and, for the runner, a TSV of
`arvo \\t project \\t url \\t key \\t name|file|added[;...]` (hunk names are labels, so the TSV
leaves this machine only encrypted). Keys are opaque, derived from record id and test kind.

Usage: fuzz_check_supply.py --urls <runner cases dir> --tsv <out.tsv> [--unchecked --out ...]
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path

KINDS = ("causal_proof", "guard_site_proof")


def urls_from(cases_dir: Path) -> dict[str, tuple[str, str]]:
    """arvo id -> (project, fix URL) from every runner case list that carries a URL."""
    out = {}
    for f in sorted(cases_dir.glob("*.tsv")):
        for line in f.read_text(errors="replace").splitlines():
            parts = line.split("\t")
            url = parts[2] if len(parts) >= 3 else ""
            # Ghostscript's git:// remote is not served over HTTP; Artifex mirrors it on GitHub.
            m = re.fullmatch(r"git://git\.ghostscript\.com/([\w-]+)\.git([0-9a-f]{40})", url)
            if m:
                url = f"https://github.com/ArtifexSoftware/{m.group(1)}/commit/{m.group(2)}"
            if url.startswith("http"):
                out[parts[0]] = (parts[1], url)
    return out


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--release", default="data/release/dataset.jsonl")
    ap.add_argument("--urls", required=True)
    ap.add_argument("--tsv", required=True)
    ap.add_argument("--out", default="data/validation/fuzzcheck_supply.json")
    ap.add_argument(
        "--unchecked",
        action="store_true",
        help="only tests not yet marked strict (added after a check, or left undetermined)",
    )
    args = ap.parse_args(argv)
    urls = urls_from(Path(args.urls))
    cases, missing = [], 0
    with open(args.release) as fh:
        for r in map(json.loads, fh):
            img = ((r.get("docker_image_ref") or {}).get("vulnerable") or "").split("@")[0]
            if not img.startswith("n132/arvo:") or not r.get("chain"):
                continue
            aid = img.split(":")[1].removesuffix("-vul")
            ev = r["chain"][0].get("evidence") or {}
            tests = [(k, [ev[k]]) for k in KINDS if ev.get(k)]
            if args.unchecked:
                tests = [(k, h) for k, h in tests if h[0].get("application") != "strict"]
            if ev.get("tested_pair") and not (
                args.unchecked and ev["tested_pair"].get("application") == "strict"
            ):
                pair = json.loads((Path(ev["tested_pair"]["evidence"]) / "result.json").read_text())
                tests.append(("tested_pair", pair["proving_pair"]))
            for kind, hunks in tests:
                if aid not in urls:
                    missing += 1
                    continue
                spec = ";".join(
                    f"{h.get('hunk') or h.get('name')}|{h['file']}|"
                    f"{h.get('added_lines', h.get('added'))}"
                    for h in hunks
                )
                key = hashlib.sha256(f"{r['id']}:{kind}".encode()).hexdigest()[:12]
                cases.append(
                    {
                        "id": r["id"],
                        "arvo_id": aid,
                        "kind": kind,
                        "key": key,
                        "tier": r["label_confidence_tier"],
                        "project": urls[aid][0],
                        "url": urls[aid][1],
                        "spec": spec,
                    }
                )
    Path(args.tsv).write_text(
        "".join(
            f"{c['arvo_id']}\t{c['project']}\t{c['url']}\t{c['key']}\t{c['spec']}\n"
            for c in sorted(cases, key=lambda c: c["arvo_id"])
        )
    )
    public = [{k: c[k] for k in ("id", "arvo_id", "kind", "key", "tier")} for c in cases]
    Path(args.out).write_text(
        json.dumps(
            {
                "rule": "PR-4/PR-13 fuzz check",
                "n": len(cases),
                "no_fix_url": missing,
                "cases": public,
            },
            indent=1,
        )
        + "\n"
    )
    print(
        f"{len(cases)} tests over {len({c['arvo_id'] for c in cases})} images; "
        f"{missing} without a fix URL"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
