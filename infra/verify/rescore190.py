"""Re-score the CWE-190 source attestation on already-fetched patches.

The first pass attested 21 of 158 and was wrong to. Inspecting the diffs, patches it rejected
were adding textbook guards:

    if (img->width <= 0 || img->width > 32767 || ...) return (-1);   # literal bound, missed
    if (length > BT_ATT_MAX_VALUE_LEN) return ...ERROR_INVALID_LEN;  # matched, but weight 2
                                                                     # against a threshold of 3

Two errors: the bound comparison demanded a symbolic constant, so numeric literals were
invisible; and a single guard scored below threshold, when one guard on a size variable IS the
evidence. Re-scored offline against the stored diffs, so nothing is refetched.
"""
import collections
import json
import os
import re
import sys

SIZEISH = r"(size|len|length|count|n[a-z]*|width|height|depth|num|idx|index|off|offset|cap|max)"
SIGNALS = [
    # a guard comparing a size-ish variable against anything - literal or symbolic
    (re.compile(r"^\+.*\bif\s*\(.*\b\w*" + SIZEISH + r"\w*\s*(<=|>=|<|>|==|!=)", re.I), "bound-guard", 3),
    (re.compile(r"^\+.*\b(SIZE_MAX|INT_MAX|UINT_MAX|LONG_MAX|SSIZE_MAX|[A-Z_]+_MAX(_[A-Z_]+)?)\b"), "limit-const", 3),
    (re.compile(r"^\+.*\b__builtin_(add|mul|sub)_overflow\s*\("), "builtin-overflow", 4),
    (re.compile(r"^\+.*\b(check|validate|verify|safe)_\w*\s*\("), "guard-call", 2),
    (re.compile(r"^\+.*\boverflow\b", re.I), "overflow-mention", 2),
    (re.compile(r"^\+.*\((size_t|uint64_t|int64_t|unsigned long long|uintmax_t)\)"), "width-cast", 2),
    (re.compile(r"^\+.*\breturn\s*\(?\s*(-1|NULL|false|0)\s*\)?\s*;"), "early-reject", 1),
]
THRESHOLD = 3


def score(diff):
    hits, total = [], 0
    for pat, name, w in SIGNALS:
        n = sum(1 for line in diff.splitlines() if pat.match(line))
        if n:
            hits.append({"signal": name, "added_lines": n})
            total += w * min(n, 3)
    return total, hits


CF = os.environ.get("CF_HOME") or sys.exit("set CF_HOME to the chainforge working directory")
P = f"{CF}/osv_enriched.json"
d = json.load(open(P))
st = collections.Counter()
agg = collections.Counter()
for rid, v in d.items():
    if not v.get("patch_diff"):
        continue
    s, hits = score(v["patch_diff"])
    v["cwe190_score"], v["cwe190_hits"] = s, hits
    v["cwe190_attested"] = s >= THRESHOLD
    is190 = (v.get("arm") or "").startswith("CWE-190")
    st["patched"] += 1
    if is190:
        st["190-arm"] += 1
        st["190-arm ATTESTED"] += bool(v["cwe190_attested"])
        if v["cwe190_attested"]:
            for h in hits:
                agg[h["signal"]] += 1
    else:
        st["other-arm ATTESTED"] += bool(v["cwe190_attested"])
json.dump(d, open(P, "w"))
for k, v in st.most_common():
    print("  %4d  %s" % (v, k))
print("\n  signals firing on attested 190 records: %s" % dict(agg.most_common()))
print("  190-arm attestation rate: %d%%" % (100 * st["190-arm ATTESTED"] // max(st["190-arm"], 1)))
