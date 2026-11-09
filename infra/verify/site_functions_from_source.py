#!/usr/bin/env python3
"""Name the function of each tested site from the source, not from git's hunk header.

A tested site (a single-hunk or hunk-pair test's site, and `tested_site` on origin roots) took
its function from the hunk header's context, which git fills with the nearest preceding line
that looks like a definition: the previous function when a hunk opens a function body, a macro
(`FUNC`, `Elf_`), or a statement. PR-14's debug information disagreed with that name for 35 of
183 root lines. This fetches each fix's parent revision (shallow, blobs on demand), parses the
site's file with tree-sitter, and takes the innermost function definition that contains the
site's line. Where it finds one whose bare name differs, the site's function is replaced and the
old name kept as `function_hunk_header`; where it finds none (file scope, a parse it cannot
place, or a file it cannot fetch) nothing changes. Logged as `site-function-from-source`.
Writes data/validation/site_functions.json. Idempotent.

Run with: uv run --with tree-sitter --with tree-sitter-c --with tree-sitter-cpp python
  infra/verify/site_functions_from_source.py --urls <runner cases dir> [--cache DIR]
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
from chainforge.evidence import C_KEYWORDS, bare_function  # noqa: E402

HUNK_STAGES = ("missing guard", "tested guard site", "proven guard site")  # last: before 1.0.9
_COMMIT = re.compile(r"^(https?://.+?)/(?:-/)?commit/([0-9a-f]{7,40})")


def parsers():
    import tree_sitter_c
    import tree_sitter_cpp
    from tree_sitter import Language, Parser

    return Parser(Language(tree_sitter_c.language())), Parser(Language(tree_sitter_cpp.language()))


def urls_from(cases_dir: Path) -> dict[str, str]:
    out = {}
    for f in sorted(cases_dir.glob("*.tsv")):
        for line in f.read_text(errors="replace").splitlines():
            p = line.split("\t")
            if len(p) >= 3 and p[2].startswith("http"):
                out[p[0]] = p[2]
    return out


def targets(rows: list[dict], urls: dict[str, str]):
    """(record, site dict, where) for every site a hunk header named."""
    for r in rows:
        img = ((r.get("docker_image_ref") or {}).get("vulnerable") or "").split("@")[0]
        aid = img.split(":")[1].removesuffix("-vul") if img.startswith("n132/arvo:") else None
        url = urls.get(aid or "")
        for i, link in enumerate(r.get("chain") or []):
            ev = link.get("evidence") or {}
            loc = ev.get("location") or {}
            if (loc.get("stage") or "").startswith(HUNK_STAGES):
                yield r, url, loc, f"link{i}"
            if isinstance(ev.get("tested_site"), dict):
                yield r, url, ev["tested_site"], f"link{i}.tested_site"
            for j, h in enumerate((ev.get("tested_pair") or {}).get("hunks") or []):
                if isinstance(h.get("site"), dict):
                    yield r, url, h["site"], f"link{i}.pair{j}"


def fetch(cache: Path, repo: str, sha: str, path: str) -> bytes | None:
    d = cache / re.sub(r"[^A-Za-z0-9]+", "_", repo)
    if not (d / ".git").is_dir():
        d.mkdir(parents=True, exist_ok=True)
        subprocess.run(["git", "init", "-q"], cwd=d, check=False)
        subprocess.run(["git", "remote", "add", "origin", repo], cwd=d, check=False)
    run = lambda *a: subprocess.run(["git", *a], cwd=d, capture_output=True, timeout=300)  # noqa: E731
    if run("cat-file", "-e", f"{sha}^{{commit}}").returncode != 0:
        run("fetch", "-q", "--depth=2", "--filter=blob:none", "origin", sha)
    out = run("show", f"{sha}^:{path}")
    return out.stdout if out.returncode == 0 else None


def _name(fn) -> str | None:
    d = fn.child_by_field_name("declarator")
    while d is not None and d.type != "function_declarator":
        d = d.child_by_field_name("declarator")
    if d is None:
        return None
    n = d.child_by_field_name("declarator")
    return n.text.decode(errors="replace") if n is not None else None


def enclosing(parser, src: bytes, line: int) -> str | None:
    tree = parser.parse(src)
    best, stack = None, [tree.root_node]
    while stack:
        n = stack.pop()
        if not (n.start_point[0] + 1 <= line <= n.end_point[0] + 1):
            continue
        if n.type == "function_definition":
            best = n  # deeper definitions (lambdas aside) come later
        stack.extend(n.children)
    name = _name(best) if best is not None else None
    # A name built by a macro (`PRIV(check_escape)`) or a statement the parser took for a
    # declarator (`if`) is not the function's name; such a site keeps the one it has.
    if name and ("(" in name or bare_function(name) in C_KEYWORDS):
        return None
    return name


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--release", default="data/release")
    ap.add_argument("--urls", required=True)
    ap.add_argument("--cache", default="data/cache/gitcache")
    ap.add_argument("--out", default="data/validation/site_functions.json")
    args = ap.parse_args(argv)
    pc, pcpp = parsers()
    rel = Path(args.release)
    with open(rel / "dataset.jsonl") as fh:
        rows = [json.loads(line) for line in fh]
    urls = urls_from(Path(args.urls))
    stats, log, results = collections.Counter(), [], []
    files: dict = {}
    for r, url, loc, where in targets(rows, urls):
        m = _COMMIT.match(url or "")
        if not m or not loc.get("file") or not loc.get("line"):
            stats["no fix URL or site"] += 1
            continue
        repo, sha = m.group(1) + ".git", m.group(2)
        key = (repo, sha, loc["file"])
        if key not in files:
            files[key] = fetch(Path(args.cache), repo, sha, loc["file"])
        src = files[key]
        if src is None:
            stats["file not fetched"] += 1
            continue
        parser = pc if loc["file"].endswith(".c") else pcpp
        name = enclosing(parser, src, int(loc["line"]))
        prev = loc.get("function_hunk_header", loc.get("function"))
        results.append({"id": r["id"], "where": where, "parsed": name, "hunk_header": prev})
        if name is None:
            stats["no enclosing function found"] += 1
            continue
        if bare_function(name) == bare_function(prev):
            stats["agrees"] += 1
            continue
        stats["replaced"] += 1
        if loc.get("function") != name:
            loc.setdefault("function_hunk_header", prev)
            loc["function"] = name
            log.append(
                {
                    "id": r["id"],
                    "op": "site-function-from-source",
                    "where": where,
                    "from": prev,
                    "to": name,
                }
            )
    with open(rel / "dataset.jsonl", "w") as fh:
        fh.writelines(json.dumps(r) + "\n" for r in rows)
    with open(rel / "corrections_changelog.jsonl", "a") as fh:
        fh.writelines(json.dumps(e) + "\n" for e in log)
    Path(args.out).write_text(json.dumps({"stats": dict(stats), "sites": results}, indent=1) + "\n")
    print(dict(stats))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
