#!/usr/bin/env python3
"""Materialise GOLD patch evidence that is a reference rather than a patch.

R5 says patch evidence must carry the guard the fix added, so a record whose `patch_diff` is a
pointer - an https URL, a `git://` remote, a bare `fix:<sha>` - cannot support the
counterfactual GOLD asserts. `rescue_patches.py` handled the https case; these are the ones it
could not see, because the release only ever tested for an "http" prefix:

    fix:ef5749ef8b307bf8717945701b1b79d036af0a15          162 syzbot records
    git://git.ghostscript.com/jbig2dec.git<sha>            concatenated, no separator
    git://thekelleys.org.uk/dnsmasq.git -> <sha>           arrow separator

Each names a repository and a commit, which is enough to fetch the real diff from that host's
web interface. Whatever cannot be fetched stays a reference and must be demoted, not shipped:
the rule working is a record leaving GOLD, never the check being loosened to admit it.

Writes a JSONL of {id, patch_diff, source_url}; applying it is a separate step.

Usage: rescue_reference_patches.py [--release data/release/dataset.jsonl]
                                   [--out data/interim/rescued_reference_patches.jsonl]
                                   [--limit N]
"""

from __future__ import annotations

import argparse
import collections
import json
import re
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))
from chainforge.evidence import patch_is_content  # noqa: E402

SHA = re.compile(r"[0-9a-f]{40}")
MAX_PATCH_BYTES = 2_000_000
KERNEL = "https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/patch/?id={sha}"
# host -> cgit/gitweb plain-diff template. Keyed on the host in the `git://` remote, because
# that is all these strings carry; the repo name is recovered from the path.
GITWEB = {
    "git.ghostscript.com": "https://git.ghostscript.com/?p={repo};a=commitdiff_plain;h={sha}",
    "thekelleys.org.uk": "http://thekelleys.org.uk/gitweb/?p={repo};a=commitdiff_plain;h={sha}",
    "code.qt.io": "https://code.qt.io/cgit/{repo}/patch/?id={sha}",
}


def candidates(rec: dict) -> list[str]:
    """URLs that might return the real diff for this record, best first."""
    diff = (rec.get("patch_diff") or "").strip()
    fixed = (rec.get("commit_range") or {}).get("fixed") or ""
    sha_m = SHA.search(fixed) or SHA.search(diff)
    if not sha_m:
        return []
    sha = sha_m.group(0)

    # syzbot records are Linux; the fix is a mainline commit.
    if rec.get("provenance") == "syzbot" or rec.get("ecosystem") == "Linux":
        return [KERNEL.format(sha=sha)]

    m = re.match(r"git://([^/\s]+)/(\S+?)(?:\.git)", diff)
    if m:
        host, repo = m.group(1), m.group(2) + ".git"
        tmpl = GITWEB.get(host)
        if tmpl:
            return [tmpl.format(repo=repo, sha=sha)]
    return []


CODE = re.compile(r"\.(c|cc|cpp|cxx|h|hpp|inc|S)$", re.I)
NON_GUARD = re.compile(r"(^|/)(test|tests|fuzz|fuzzing|fuzzer|fuzzers|corpus|docs?)/", re.I)


def is_usable_guard_evidence(body: str, want_sha: str) -> str | None:
    """Reason this fetched diff cannot serve as guard evidence, or None if it can.

    Fetching the text is not the same as recovering the evidence. A commit can be the right
    sha and still carry no guard - qtqa's "fix" adds a fuzzing testcase, and one syzbot record
    resolves to a whole-subsystem removal - so the same check that rejected the reference has
    to be applied to what replaces it, or the defect just moves down one level.
    """
    if not patch_is_content(body):
        return "not a patch"
    m = re.search(r"^From ([0-9a-f]{40})", body, re.M)
    if want_sha and m and m.group(1) != want_sha:
        return f"sha mismatch (got {m.group(1)[:12]}, want {want_sha[:12]})"
    files = re.findall(r"^diff --git a/\S+ b/(\S+)", body, re.M)
    if not files:
        return "no file headers"
    if not any(CODE.search(f) and not NON_GUARD.search(f) for f in files):
        return "touches no non-test source file"
    return None


def fetch(url: str, timeout: float = 30.0) -> str | None:
    req = urllib.request.Request(url, headers={"User-Agent": "chainforge/0.1"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            # a truncated diff can end mid-hunk and would be applied as if complete
            body = resp.read(MAX_PATCH_BYTES + 1)
            return None if len(body) > MAX_PATCH_BYTES else body.decode("utf-8", "replace")
    except (urllib.error.URLError, OSError, ValueError):
        return None


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--release", default="data/release/dataset.jsonl")
    ap.add_argument("--out", default="data/interim/rescued_reference_patches.jsonl")
    ap.add_argument("--limit", type=int, default=0)
    ap.add_argument("--sleep", type=float, default=0.3)
    a = ap.parse_args(argv)

    with open(a.release) as fh:
        rows = [json.loads(ln) for ln in fh]
    targets = [
        r
        for r in rows
        if r.get("label_confidence_tier") == "gold"
        and (r.get("patch_diff") or "").strip()
        and not patch_is_content(r.get("patch_diff"))
    ]
    if a.limit:
        targets = targets[: a.limit]

    st = collections.Counter()
    rejected: list[dict] = []
    out_path = Path(a.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    n = 0
    with open(out_path, "w") as fh:
        for i, rec in enumerate(targets, 1):
            urls = candidates(rec)
            if not urls:
                st["no candidate url"] += 1
                continue
            want = SHA.search((rec.get("commit_range") or {}).get("fixed") or "")
            want_sha = want.group(0) if want else ""
            got, why = None, "fetch failed"
            for u in urls:
                body = fetch(u)
                time.sleep(a.sleep)
                if body is None:
                    continue
                why = is_usable_guard_evidence(body, want_sha)
                if why is None:
                    got = (u, body)
                    break
            if got is None:
                st[f"rejected: {why}"] += 1
                rejected.append({"id": rec["id"], "reason": why, "urls": urls})
                continue
            fh.write(
                json.dumps({"id": rec["id"], "source_url": got[0], "patch_diff": got[1]}) + "\n"
            )
            n += 1
            st["recovered"] += 1
            if i % 25 == 0:
                print(f"  {i}/{len(targets)} … recovered {n}", file=sys.stderr)

    print(f"targets: {len(targets)}")
    for k, v in st.most_common():
        print(f"  {k:32s} {v}")
    rej_path = out_path.with_name(out_path.stem + "_rejected.jsonl")
    with open(rej_path, "w") as fh:
        for r in rejected:
            fh.write(json.dumps(r) + "\n")
    print(f"wrote {n} to {out_path}")
    print(f"wrote {len(rejected)} rejections to {rej_path} (these must be DEMOTED, not shipped)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
