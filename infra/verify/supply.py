"""What is actually still minable per arm, so targets are supply-grounded not aspirational.

Counts ARVO cases we have NOT already consumed, bucketed by the arm their crash class implies,
and screens each through crash_output for the causal structure a chain needs. A target above
this ceiling is not a plan, it is a wish.
"""
import collections
import glob
import json
import os
import re
import sqlite3
import sys

CF = os.environ.get("CF_HOME") or sys.exit("set CF_HOME to the chainforge working directory")
db = sqlite3.connect(f"{CF}/arvo.db")
db.row_factory = sqlite3.Row

consumed = set()
for pat in ("msan_mine", "msan_rest", "starved_pilot", "starved_rest", "arvo_untapped",
            "arvo_reverify", "len3_repro"):
    for d in glob.glob(f"{CF}/{pat}/*/"):
        consumed.add(d.strip("/").split("/")[-1])
print(f"already attempted locally: {len(consumed)} ARVO cases")

NOISE = re.compile(r"(compiler-rt/lib/|sanitizer_common|_interceptors|/usr/include/|/usr/lib/"
                   r"|libc-start|libfuzzer|/src/llvm|LLVMFuzzer)", re.I)
LOC = re.compile(r"([a-zA-Z0-9_/.\-]+\.(?:c|cc|cpp|h|hpp|cxx)):(\d+)")


def arm_of(ct, co):
    """Map (ARVO crash_type, stored report) -> the arm it can witness."""
    c = (ct or "").lower()
    if "integer-overflow" in c or "shift" in c or re.search(r"runtime error:.*overflow", co or ""):
        return "190->787/125/119"
    if "index-out-of-bounds" in c:
        return "129->119"
    if "bad-cast" in c:
        return "843->119"
    if "use-of-uninitialized" in c or "uninitialized" in c:
        return "456->457"
    if "null-dereference" in c or "segv" in c:
        return "252->476"
    if "double-free" in c:
        return "362->415"
    if "use-after-free" in c:
        return "416->787/125"
    if "overflow" in c:  # heap/stack/global buffer overflow
        return "20->125/787 (default-source)"
    return "other"


sup = collections.Counter()
structured = collections.Counter()
for r in db.execute("SELECT localId, crash_type, crash_output, patch_url FROM arvo"):
    if str(r["localId"]) in consumed:
        continue
    co = r["crash_output"] or ""
    a = arm_of(r["crash_type"], co)
    sup[a] += 1
    sites = [m for m in LOC.finditer(co) if not NOISE.search(m.group(1))]
    if sites and r["patch_url"]:
        structured[a] += 1

print(f"\n{'arm':<32} {'unmined':>8} {'+ localized & patched':>22}")
print("-" * 66)
for a, n in sup.most_common():
    print(f"{a:<32} {n:>8} {structured[a]:>22}")
json.dump({"unmined": dict(sup), "minable": dict(structured)},
          open(f"{CF}/supply.json", "w"), indent=1)
