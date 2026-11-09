"""Round-3 work-list: exhaust the supply in every arm still below target.

Deliberately excludes the 20->125/787 default-source bucket (1506 cases available) and the
416 arms. Those are frozen by #44 and #38 -- they are the cheapest to mine and the least
valuable to add, so they will grow by default unless a work-list explicitly leaves them out.
"""
import collections
import glob
import os
import re
import sqlite3
import sys

CF = os.environ.get("CF_HOME") or sys.exit("set CF_HOME to the chainforge working directory")
WANT = {"456->457", "129->119", "843->119", "252->476", "362->415"}
NOISE = re.compile(r"(compiler-rt/lib/(msan|sanitizer_common)|msan_interceptors|/usr/include/)")
LOC = re.compile(r"([a-zA-Z0-9_/.\-]+\.(?:c|cc|cpp|h|hpp|cxx)):(\d+)")
ORIGIN = re.compile(r"was created by[^\n]*\n((?:\s+#\d+[^\n]*\n){1,8})")
SUMMARY = re.compile(r"SUMMARY: MemorySanitizer: \S+\s+([a-zA-Z0-9_/.\-]+\.(?:c|cc|cpp|h|hpp|cxx)):(\d+)")

consumed = set()
for pat in ("msan_mine", "msan_rest", "starved_pilot", "starved_rest", "arvo_untapped",
            "arvo_reverify", "len3_repro"):
    for d in glob.glob(f"{CF}/{pat}/*/"):
        consumed.add(d.strip("/").split("/")[-1])

db = sqlite3.connect(f"{CF}/arvo.db")
db.row_factory = sqlite3.Row


def arm_of(ct, co=""):
    """Classify by ARVO's crash_type, falling back to what the stored report actually says.

    ARVO's label misses cases: 83 reports contain a MemorySanitizer trace while their
    crash_type says something else entirely, so a label-only screen leaves them unmined.
    """
    c = (ct or "").lower()
    if "use-of-uninitialized" in c or "uninitialized" in c:
        return "456->457"
    if "index-out-of-bounds" in c:
        return "129->119"
    if "bad-cast" in c:
        return "843->119"
    if "null-dereference" in c or "segv" in c:
        return "252->476"
    if "double-free" in c:
        return "362->415"
    if "MemorySanitizer" in co:
        return "456->457"
    if re.search(r"runtime error:.*out of bounds for type", co):
        return "129->119"
    if re.search(r"member call on address|downcast of address", co):
        return "843->119"
    return None


# Cap CUMULATIVELY against what the arm already holds, not per-round: the 456->457 arm
# already spans 83 projects with its largest at 6%, so a per-round cap of 20 was throwing
# away 181 usable cases to protect a diversity it already has.
import json as _json

held = _json.load(open(f"{CF}/arm_projects.json"))
per = collections.Counter()
for _arm, _d in held.items():
    for _proj, _n in _d.items():
        per[(_arm, _proj)] = _n
rows, st = [], collections.Counter()
for r in db.execute("SELECT localId, project, crash_type, crash_output, patch_url FROM arvo"):
    lid = str(r["localId"])
    if lid in consumed:
        continue
    a = arm_of(r["crash_type"], r["crash_output"] or "")
    if a not in WANT or not r["patch_url"]:
        continue
    co = r["crash_output"] or ""
    if a == "456->457":
        m = ORIGIN.search(co)
        src = None
        if m:
            for line in m.group(1).splitlines():
                x = LOC.search(line)
                if x and not NOISE.search(x.group(1)):
                    src = x.group(1)
                    break
        s = SUMMARY.search(co)
        ok = bool(src and s and not NOISE.search(s.group(1)))
    else:
        ok = any(not NOISE.search(x.group(1)) for x in LOC.finditer(co))
    if not ok:
        st[f"{a}: screened out"] += 1
        continue
    if per[(a, r["project"])] >= 25:
        st[f"{a}: project cap"] += 1
        continue
    per[(a, r["project"])] += 1
    rows.append((lid, r["project"], a))
    st[a] += 1

with open(f"{CF}/round3.tsv", "w") as fh:
    for lid, proj, _a in rows:
        fh.write(f"{lid}\t{proj}\n")
for k, v in sorted(st.items()):
    print(f"  {v:5d}  {k}")
print(f"\nround3.tsv: {len(rows)} cases, {len({p for _, p, _ in rows})} projects")
