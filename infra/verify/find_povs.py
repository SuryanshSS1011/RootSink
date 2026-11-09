"""Do the osv-git fix commits carry a reproducer we could actually run?

Three things a patch can hand us, in descending usefulness:
  test-input   a binary/corpus file added under tests/ or fuzz/ - that IS a PoV
  fuzz-harness a new or changed fuzz target, meaning the project is fuzzable at all
  test-code    a regression test in source form, which encodes the triggering input
"""
import collections
import json
import os
import re
import sys

CF = os.environ.get("CF_HOME") or sys.exit("set CF_HOME to the chainforge working directory")
P = f"{CF}/osv_enriched.json"
d = json.load(open(P))

NEWFILE = re.compile(r"^diff --git a/(\S+) b/(\S+)", re.M)
BINARY = re.compile(r"^GIT binary patch", re.M)
TESTPATH = re.compile(r"(^|/)(tests?|testing|fuzz\w*|corpus|regress\w*|poc|crash\w*)(/|$)", re.I)
INPUTEXT = re.compile(r"\.(bin|dat|raw|jpg|jpeg|png|gif|tif|tiff|pdf|zip|gz|wav|mp3|mp4|"
                      r"svg|xml|json|ttf|otf|ico|bmp|webp|heic|jp2|pcap|fuzz|input|testcase)$", re.I)
HARNESS = re.compile(r"fuzz\w*\.(c|cc|cpp)$|_fuzzer\.(c|cc|cpp)$|LLVMFuzzerTestOneInput", re.I)

st = collections.Counter()
detail = {}
for rid, v in d.items():
    diff = v.get("patch_diff")
    if not diff:
        continue
    st["patched"] += 1
    files = [b for _a, b in NEWFILE.findall(diff)]
    test_inputs = [f for f in files if TESTPATH.search(f) and INPUTEXT.search(f)]
    test_any = [f for f in files if TESTPATH.search(f)]
    harness = [f for f in files if HARNESS.search(f)] or (["<inline>"] if "LLVMFuzzerTestOneInput" in diff else [])
    binary = bool(BINARY.search(diff))
    tag = []
    if test_inputs or (binary and test_any):
        tag.append("test-input")
    if harness:
        tag.append("fuzz-harness")
    if test_any and not test_inputs:
        tag.append("test-code")
    for t in tag:
        st[t] += 1
    is190 = (v.get("arm") or "").startswith("CWE-190")
    if tag:
        st["ANY reproducer signal"] += 1
        if is190:
            st["  of which CWE-190 arm"] += 1
        detail[rid] = {"cve": v.get("cve"), "project": v.get("project"), "arm": v.get("arm"),
                       "tags": tag, "test_inputs": test_inputs[:4], "harness": harness[:2]}
json.dump(detail, open(f"{CF}/pov_candidates.json", "w"), indent=1)
for k, v in st.most_common():
    print(f"  {v:4d}  {k}")
print()
for rid, x in list(detail.items())[:6]:
    print(f"  {x['cve']:<18} {x['project'][:32]:<32} {','.join(x['tags'])}  {x['test_inputs'] or x['harness']}")
