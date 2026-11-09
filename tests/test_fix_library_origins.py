"""fix_library_origins.py (release 1.0.8): an origin on a C++ standard-library frame moves to the
first project frame of the same origin stack."""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "infra" / "verify"))
import fix_library_origins as F  # noqa: E402

ASAN = """==1==ERROR: AddressSanitizer: heap-use-after-free on address 0x1
READ of size 8 at 0x1 thread T0
    #0 0x1 in use(Node*) /src/proj/src/use.cc:9:3
freed by thread T0 here:
    #0 0x2 in operator delete(void*) /src/llvm-project/compiler-rt/lib/asan/new.cpp:1:3
    #1 0x3 in operator() /usr/local/bin/../include/c++/v1/__memory/unique_ptr.h:54:5
    #2 0x3 in geos::Node::add(geos::Edge*) /src/geos/src/geomgraph/Node.cpp:163:1

previously allocated by thread T0 here:
    #0 0x4 in operator new(unsigned long) /src/llvm-project/compiler-rt/lib/asan/x.cpp:1:1
"""
MSAN = """==2==WARNING: MemorySanitizer: use-of-uninitialized-value
    #0 0x5 in f /src/proj/a.c:1:1
  Uninitialized value was created by a heap allocation
    #0 0x6 in operator new(unsigned long) /src/llvm-project/compiler-rt/lib/msan/new.cpp:1:1
    #1 0x7 in std::__1::basic_string<char>::__assign_external(char const*) (/out/fuzz+0x7)
    #2 0x8 in operator() /usr/local/bin/../include/c++/v1/__functional/function.h:499:16
    #3 0x8 in LLVMFuzzerTestOneInput /src/boringssl/fuzz/ssl_ctx_api.cc:534:5
"""


def test_asan_free_stack_skips_library_frames():
    site = F.project_frame(F.origin_stack(ASAN, 416))
    assert site == {
        "file": "src/geomgraph/Node.cpp",
        "line": 163,
        "function": "geos::Node::add(geos::Edge*)",
    }


def test_msan_origin_stack_reaches_the_harness():
    site = F.project_frame(F.origin_stack(MSAN, 456))
    assert site["file"] == "fuzz/ssl_ctx_api.cc" and site["function"] == "LLVMFuzzerTestOneInput"


def test_no_project_frame_gives_none():
    only_lib = "freed by thread T0 here:\n    #0 0x1 in f /usr/include/c++/v1/new:1:1\n"
    assert F.project_frame(F.origin_stack(only_lib, 416)) is None


def test_cwe416_without_a_free_stack_uses_the_msan_origin_block():
    freed = MSAN.replace("a heap allocation", "a heap deallocation")
    assert F.project_frame(F.origin_stack(freed, 416))["function"] == "LLVMFuzzerTestOneInput"


def test_build_tree_hops_are_resolved_and_llvm_code_counts():
    stack = [
        "    #0 0x1 in free /src/llvm-project/compiler-rt/lib/asan/asan_malloc_linux.cpp:1:1",
        "    #1 0x2 in ~vector /usr/local/bin/../include/c++/v1/vector:9:3",
        "    #2 0x3 in P::f() /work/build/../../src/ots/src/glat.cc:327:5",
    ]
    assert F.project_frame(stack)["file"] == "src/glat.cc"
    llvm = ["    #0 0x3 in llvm::f() /src/llvm-project/llvm/lib/Support/MemAlloc.h:7:1"]
    assert F.project_frame(llvm)["file"] == "llvm/lib/Support/MemAlloc.h"


def test_main_moves_the_site_rewrites_the_note_and_is_idempotent(tmp_path):
    log = tmp_path / "vul.txt"
    log.write_text(ASAN)
    old = {"file": "/usr/local/bin/../include/c++/v1/__memory/unique_ptr.h", "line": 54}
    root = {
        "cwe_id": 416,
        "site_kind": "origin-site",
        "evidence": {"location": dict(old, function="operator()", stage="free")},
    }
    rec = {
        "id": "R1",
        "label_confidence_tier": "gold",
        "chain": [root, {"cwe_id": 125}],
        "dataflow_evidence": f"CWE-416 at {old['file']}:54 is the free.",
        "sanitizer_reports": [{"revision": "vulnerable", "log_ref": str(log), "triggered": True}],
    }
    rel = tmp_path / "release"
    rel.mkdir()
    (rel / "dataset.jsonl").write_text(json.dumps(rec) + "\n")
    for _ in range(2):
        F.main(["--release", str(rel), "--root", "/"])
    out = json.loads((rel / "dataset.jsonl").read_text())
    loc = out["chain"][0]["evidence"]["location"]
    assert (loc["file"], loc["line"], loc["stage"]) == ("src/geomgraph/Node.cpp", 163, "free")
    assert out["dataflow_evidence"] == "CWE-416 at src/geomgraph/Node.cpp:163 is the free."
    ops = [
        json.loads(x)["op"]
        for x in (rel / "corrections_changelog.jsonl").read_text().split("\n")
        if x
    ]
    assert ops == ["library-origin-moved"]
