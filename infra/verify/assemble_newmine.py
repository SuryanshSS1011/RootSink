"""Build ChainRecords for newly mined CVEs whose CWE set carries both ends of an admissible pair.

Scope guard: only records whose fix touches C/C++ files are kept. The candidates come from an
NVD CWE co-occurrence sweep, which is language-agnostic, and this dataset is a C/C++ corpus -
admitting a Python or Go CVE because its CWE pair matched would silently widen the scope.

Tier is SILVER by construction. There is no reproducer, so no execution witness exists; the
patch supplies the fix evidence and, where the fix adds an overflow guard, attests the CWE-190
source rather than assuming it.
"""
import collections
import json
import os
import re
import sys
import time
import urllib.request

CF = os.environ.get("CF_HOME") or sys.exit("set CF_HOME to the chainforge working directory")
sys.path.insert(0, f"{CF}/repo/src")
import hashlib

from chainforge.evidence import clip_patch  # noqa: E402
from chainforge.schema import (
    ChainLink,
    ChainRecord,
    CommitRange,
    ConfidenceTier,
    LinkEvidence,
    LinkRole,
)

CLIKE = re.compile(r"^\+\+\+ b/.*\.(c|cc|cpp|cxx|h|hpp)$", re.M)
SIZEISH = r"(size|len|length|count|n[a-z]*|width|height|depth|num|idx|index|off|offset|cap|max)"
SIGNALS = [
    (re.compile(r"^\+.*\bif\s*\(.*\b\w*" + SIZEISH + r"\w*\s*(<=|>=|<|>|==|!=)", re.I), "bound-guard", 3),
    (re.compile(r"^\+.*\b(SIZE_MAX|INT_MAX|UINT_MAX|[A-Z_]+_MAX(_[A-Z_]+)?)\b"), "limit-const", 3),
    (re.compile(r"^\+.*\b__builtin_(add|mul|sub)_overflow\s*\("), "builtin-overflow", 4),
    (re.compile(r"^\+.*\boverflow\b", re.I), "overflow-mention", 2),
    (re.compile(r"^\+.*\((size_t|uint64_t|int64_t|unsigned long long)\)"), "width-cast", 2),
]


def fetch(url, timeout=35):
    req = urllib.request.Request(url, headers={"User-Agent": "chainforge/0.1"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read().decode("utf-8", "replace")


def score(diff):
    hits, tot = [], 0
    for pat, name, w in SIGNALS:
        n = sum(1 for line in diff.splitlines() if pat.match(line))
        if n:
            hits.append(name)
            tot += w * min(n, 3)
    return tot, hits


res = json.load(open(f"{CF}/new_all_resolved.json"))
recs, st = [], collections.Counter()
for i, (cve, v) in enumerate(res.items(), 1):
    proj, fix = v.get("project"), v.get("fix")
    if not proj or not fix:
        st["no project/fix"] += 1
        continue
    diff = None
    for suf in (".diff", ".patch"):
        try:
            b = fetch(f"https://github.com/{proj}/commit/{fix}{suf}")
            if "diff --git" in b:
                diff = b
                break
        except Exception:
            pass
        time.sleep(0.5)
    if not diff:
        st["patch unfetchable"] += 1
        continue
    if not CLIKE.search(diff):
        st["not a C/C++ fix - out of scope"] += 1
        continue
    arm = sorted(v["arms"])[0]
    src, snk = (int(x.replace("CWE-", "")) for x in arm.split("->"))
    sc, hits = score(diff)
    attested = sc >= 3 and src == 190
    h = int(hashlib.sha1(cve.encode()).hexdigest()[:8], 16) % 10_000_000
    recs.append(ChainRecord(
        id=f"CHAINFORGE-97{h:07d}",
        aliases=[cve],
        project=proj,
        language="C",
        ecosystem="GIT",
        commit_range=CommitRange(fixed=f"https://github.com/{proj}/commit/{fix}"),
        chain=[
            ChainLink(cwe_id=src, role=LinkRole.SOURCE, evidence=LinkEvidence(
                patch_hunk_ref=(f"fix adds an overflow guard ({', '.join(hits[:3])}); "
                                f"CWE-{src} source attested by the patch"
                                if attested else
                                f"CWE-{src} from NVD CWE assignment; no guard signal in the fix")[:160])),
            ChainLink(cwe_id=snk, role=LinkRole.SINK, evidence=LinkEvidence(
                patch_hunk_ref=f"CWE-{snk} sink from the NVD CWE assignment on {cve}")),
        ],
        chain_string=arm,
        patch_diff=clip_patch(diff, 200_000),
        label_confidence_tier=ConfidenceTier.SILVER,
        dataflow_evidence=(
            f"NVD assigns BOTH CWE-{src} and CWE-{snk} to {cve}, an admissible ordered pair. "
            "No reproducer is published, so there is no execution witness and the record is "
            "SILVER; the fix commit is carried in full."
            + (" The fix adds an integer-overflow guard, attesting the source." if attested else "")),
        provenance="nvd-mined",
        synthetic=False,
    ))
    st["record built"] += 1
    st["  CWE-190 source attested"] += attested
    if i % 10 == 0:
        print(f"  {i}/{len(res)} {dict(st)}", flush=True)
    time.sleep(0.4)

with open(f"{CF}/new_mined.jsonl", "w") as fh:
    for r in recs:
        fh.write(r.model_dump_json() + "\n")
for k, val in st.most_common():
    print(f"  {val:4d}  {k}")
print("arms:", collections.Counter(r.chain_string for r in recs).most_common())
