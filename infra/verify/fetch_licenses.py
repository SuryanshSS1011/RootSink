#!/usr/bin/env python3
"""Resolve each record's upstream license (SPDX) so the release can say what it redistributes.

Records ship upstream code - fix diffs, PoV inputs, sanitizer excerpts - so each must name its
project's license. Resolution, never guessed:
  OSS-Fuzz projects  -> google/oss-fuzz projects/<p>/project.yaml `main_repo`
  GIT records        -> the repository in the fix commit URL
  GitHub repos       -> GitHub's license API (SPDX id)
  anything else      -> "NOASSERTION", with the repository URL kept for manual follow-up
Kernel records keep their existing GPL-2.0-only. nvd-race records, all filed under the catch-all
project "linux", are resolved from NVD's affected products (`nvd_products.py`). Uses the
authenticated `gh` CLI.

Usage: fetch_licenses.py [--release data/release] [--cache data/cache/licenses.json]
"""

from __future__ import annotations

import argparse
import base64
import collections
import json
import re
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))
from chainforge.field_policy import canonical_project  # noqa: E402

KERNEL = "GPL-2.0-only"  # SPDX: bare "GPL-2.0" is deprecated; the kernel COPYING is v2 only
_GH = re.compile(r"github\.com[/:]([\w.-]+)/([\w.-]+?)(?:\.git)?(?:/|$)")


def gh(path: str) -> dict | None:
    p = subprocess.run(["gh", "api", path], capture_output=True, text=True)
    return json.loads(p.stdout) if p.returncode == 0 and p.stdout else None


def main_repo(project: str) -> str | None:
    d = gh(f"repos/google/oss-fuzz/contents/projects/{project}/project.yaml")
    if not d:
        return None
    text = base64.b64decode(d.get("content", "")).decode(errors="replace")
    m = re.search(r"^main_repo:\s*['\"]?([^'\"\s]+)", text, re.M)
    return m.group(1) if m else None


# GitHub's detector answers NOASSERTION ("other") for any license file that is not a verbatim
# template (gdal, assimp, perl5). Fall back to the file's own text; a file matching more than one
# license, or none, stays NOASSERTION rather than being guessed.
_TEXTS = [
    ("Apache-2.0", r"Apache License,?\s+Version 2\.0"),
    ("LGPL-2.1", r"GNU LESSER GENERAL PUBLIC LICENSE\s+Version 2\.1"),
    ("LGPL-3.0", r"GNU LESSER GENERAL PUBLIC LICENSE\s+Version 3"),
    ("GPL-2.0", r"GNU GENERAL PUBLIC LICENSE\s+Version 2,"),
    ("GPL-3.0", r"GNU GENERAL PUBLIC LICENSE\s+Version 3"),
    ("MPL-2.0", r"Mozilla Public License,?\s+(?:v\.|version)\s*2\.0"),
    ("BSD-3-Clause", r"Neither the name of .{0,120}? nor the names of"),
    ("MIT", r"Permission is hereby granted, free of charge"),
    ("ISC", r"Permission to use, copy, modify, and(?:/or)? distribute this software"),
    ("Zlib", r"This software is provided 'as-is', without any express or implied"),
    ("Artistic-1.0-Perl", r"Artistic License"),
]


def spdx(repo_url: str | None) -> tuple[str, str]:
    """(SPDX id, how it was determined)."""
    m = _GH.search(repo_url or "")
    if not m:
        return "NOASSERTION", "repository not on GitHub"
    d = gh(f"repos/{m.group(1)}/{m.group(2)}/license") or {}
    sid = (d.get("license") or {}).get("spdx_id") or "NOASSERTION"
    if sid != "NOASSERTION":
        return sid, "github-detector"
    text = base64.b64decode(d.get("content") or "").decode(errors="replace")
    hits = [k for k, rx in _TEXTS if re.search(rx, text, re.I | re.S)]
    if "BSD-3-Clause" not in hits and re.search(
        r"Redistribution and use in source and binary", text
    ):
        hits.append("BSD-2-Clause")
    if len(hits) == 1:
        return hits[0], "license-file text"
    return "NOASSERTION", ("several licenses: " + ", ".join(hits)) if hits else "unrecognised text"


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--release", default="data/release")
    ap.add_argument("--cache", default="data/cache/licenses.json")
    ap.add_argument("--nvd-products", default="data/cache/nvd_products.json")
    args = ap.parse_args(argv)
    cache_p = Path(args.cache)
    cache = json.loads(cache_p.read_text()) if cache_p.is_file() else {}
    path = Path(args.release) / "dataset.jsonl"
    with open(path) as fh:
        rows = [json.loads(line) for line in fh]

    # Licenses resolved by reading each project's own files (source URL per entry): consulted
    # first, so a hand-checked license is never overwritten by the automatic resolver.
    nvd_p = Path(args.nvd_products)
    nvd_products = json.loads(nvd_p.read_text()) if nvd_p.is_file() else {}
    ov_p = Path(__file__).with_name("license_overrides.json")
    overrides = json.loads(ov_p.read_text()) if ov_p.is_file() else {}
    by_canonical = {canonical_project(k): v for k, v in overrides.items()}
    stats = collections.Counter()
    for r in rows:
        ov = overrides.get(r["project"]) or by_canonical.get(canonical_project(r["project"]))
        if ov:
            r["license"] = ov["spdx"]
            stats[r["license"]] += 1
            continue
        if r.get("ecosystem") == "Linux":
            r["license"] = KERNEL
            stats["kernel"] += 1
            continue
        if r["project"] == "linux":
            # The nvd-race catch-all: only NVD's affected-product list says what the CVE is in.
            # Kernel CVEs take the kernel records' license; anything else is left unasserted.
            products = {
                p for a in r["aliases"] for p in nvd_products.get(a, {}).get("products", [])
            }
            r["license"] = KERNEL if "linux:linux_kernel" in products else "NOASSERTION"
            stats["nvd-race kernel" if r["license"] == KERNEL else "NOASSERTION"] += 1
            continue
        key = r["project"]
        if key not in cache:
            repo = None
            if r.get("ecosystem") == "OSS-Fuzz":
                repo = main_repo(key) or main_repo(key.lower())
            if not repo:
                fixed = (r.get("commit_range") or {}).get("fixed") or ""
                repo = fixed if _GH.search(fixed) else None
            if not repo and re.fullmatch(r"[\w.-]+/[\w.-]+", key):
                repo = f"https://github.com/{key}"  # GIT records name the repo owner/name
            sid, how = spdx(repo)
            cache[key] = {"repo": repo, "spdx": sid, "how": how}
            cache_p.parent.mkdir(parents=True, exist_ok=True)
            cache_p.write_text(json.dumps(cache, indent=0, sort_keys=True))
        if cache[key].get("how") is None:  # entry from before the text fallback existed
            cache[key]["spdx"], cache[key]["how"] = spdx(cache[key]["repo"])
        r["license"] = cache[key]["spdx"]
        stats[r["license"]] += 1

    # One codebase under several names: an alias the resolver could not settle takes the license
    # another alias of the same canonical project resolved to, when exactly one was found.
    resolved = collections.defaultdict(set)
    for r in rows:
        if r["license"] != "NOASSERTION":
            resolved[canonical_project(r["project"])].add(r["license"])
    for r in rows:
        found = resolved.get(canonical_project(r["project"]), set())
        if r["license"] == "NOASSERTION" and len(found) == 1 and r["project"] != "linux":
            r["license"] = next(iter(found))
            stats["NOASSERTION"] -= 1
            stats[r["license"]] += 1
            stats["via alias"] += 1

    with open(path, "w") as fh:
        fh.writelines(json.dumps(r) + "\n" for r in rows)
    for k, n in stats.most_common():
        print(f"{n:6d}  {k}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
