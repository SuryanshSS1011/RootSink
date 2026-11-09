"""Fetch fix-commit diffs for the osv-git arm and attest the CWE-190 source from them.

Why this arm: 106 of the 159 osv-git records are CWE-190 chains, the single largest gap
against the NVD baseline (24.2% of real co-occurrence against 3.0% of our links), and the one
arm with ZERO remaining ARVO supply. All 159 currently ship with an EMPTY patch_diff, so they
carry neither patch evidence nor any source attestation.

This does not make them GOLD - that needs a triggered sanitizer report and these have no
reproducer. It supplies the patch half honestly and attests the source link the way
patch_signal_456.py does for the uninitialised-memory arm: if the fix that closes an overflow
ADDS a bounds or width check, the missing check was the cause, and CWE-190 is attested rather
than assumed.

Also records the commit date, which the corpus lacks entirely (4 of 2262 records carry any
date string) and which a temporal split needs as a contamination control.
"""
import collections
import json
import os
import re
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))
from chainforge.evidence import clip_patch  # noqa: E402

# Added-line patterns that introduce an integer-overflow / bounds guard.
SIGNALS = [
    (re.compile(r"^\+.*\b(SIZE_MAX|INT_MAX|UINT_MAX|LONG_MAX|SSIZE_MAX)\b"), "limit-const", 3),
    (re.compile(r"^\+.*\b__builtin_(add|mul|sub)_overflow\s*\("), "builtin-overflow", 3),
    (re.compile(r"^\+.*\b(check|safe)_(add|mul|sub|size)\w*\s*\("), "checked-arith", 3),
    (re.compile(r"^\+.*if\s*\([^)]*\b(>|>=|<|<=)\s*\w*(MAX|LIMIT|SIZE|LEN|COUNT)\b"), "bound-cmp", 2),
    (re.compile(r"^\+.*\((size_t|uint64_t|int64_t|unsigned long long)\)"), "width-cast", 2),
    (re.compile(r"^\+.*\bif\s*\([^)]*\boverflow\b"), "overflow-guard", 3),
    (re.compile(r"^\+.*/\*.*overflow.*\*/|^\+.*//.*overflow"), "overflow-comment", 1),
]


def fetch(url, timeout=40):
    req = urllib.request.Request(url, headers={"User-Agent": "chainforge/0.1"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read().decode("utf-8", "replace")


def score(diff):
    hits, total = [], 0
    for pat, name, w in SIGNALS:
        n = sum(1 for line in diff.splitlines() if pat.match(line))
        if n:
            hits.append({"signal": name, "added_lines": n})
            total += w * min(n, 3)
    return total, hits


def main():
    CF = os.environ.get("CF_HOME") or sys.exit("set CF_HOME to the chainforge working directory")
    recs = json.load(open(f"{CF}/osvgit.json"))
    out, st = {}, collections.Counter()
    for i, r in enumerate(recs, 1):
        proj, fixed = r.get("project"), r.get("fixed")
        if not proj or not fixed:
            st["no project/commit"] += 1
            continue
        entry = {"cve": r.get("cve"), "arm": r.get("arm"), "project": proj, "fixed": fixed}
        diff = None
        for u in (f"https://github.com/{proj}/commit/{fixed}.diff",
                  f"https://github.com/{proj}/commit/{fixed}.patch"):
            try:
                b = fetch(u)
                if "diff --git" in b or b.startswith("From "):
                    diff = b
                    break
            except urllib.error.HTTPError as e:
                st[f"HTTP {e.code}"] += 1
            except Exception:
                st["fetch error"] += 1
            time.sleep(0.6)
        if diff:
            entry["patch_diff"] = clip_patch(diff, 200_000)
            s, hits = score(diff)
            entry["cwe190_score"], entry["cwe190_hits"] = s, hits
            entry["cwe190_attested"] = s >= 3
            m = re.search(r"^Date:\s*(.+)$", diff, re.M)
            if m:
                entry["commit_date"] = m.group(1).strip()
                st["with date"] += 1
            st["patch fetched"] += 1
            st["CWE-190 attested"] += bool(entry.get("cwe190_attested"))
        else:
            st["patch unfetchable"] += 1
        out[r["id"]] = entry
        if i % 20 == 0:
            print(f"  {i}/{len(recs)} {dict(st)}", flush=True)
        time.sleep(0.8)
    json.dump(out, open(f"{CF}/osv_enriched.json", "w"))
    print("\nDONE")
    for k, v in st.most_common():
        print(f"  {v:4d}  {k}")


if __name__ == "__main__":
    sys.exit(main())
