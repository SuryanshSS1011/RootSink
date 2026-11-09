"""PR-11 site rules: free site, index sink, harness stop, and the MSan origin parse."""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "infra" / "verify"))
import admit_pr11 as a  # noqa: E402

UAF = """==1==ERROR: AddressSanitizer: heap-use-after-free on address 0x6020 at pc 0x1 bp 0x2 sp 0x3
READ of size 4 at 0x6020 thread T0
    #0 0x55 in use_it /src/proj/lib/use.c:40:5
    #1 0x56 in LLVMFuzzerTestOneInput /src/proj/fuzz/fuzz_x.c:9:3

0x6020 is located 0 bytes inside of 16-byte region
freed by thread T0 here:
    #0 0x4a in free /src/llvm-project/compiler-rt/lib/asan/asan_malloc_linux.cpp:52:3
    #1 0x57 in release_it /src/proj/lib/pool.c:88:2
    #2 0x58 in use_it /src/proj/lib/use.c:38:5

previously allocated by thread T0 here:
    #0 0x4b in malloc /src/llvm-project/compiler-rt/lib/asan/asan_malloc_linux.cpp:69:3
SUMMARY: AddressSanitizer: heap-use-after-free /src/proj/lib/use.c:40:5 in use_it
"""

MSAN = """==1==WARNING: MemorySanitizer: use-of-uninitialized-value
    #0 0x55 in read_hdr /src/proj/lib/hdr.c:120:7
    #1 0x56 in LLVMFuzzerTestOneInput /src/proj/fuzz/f.c:9:3

  Uninitialized value was created by an allocation of 'buf' in the stack frame of function 'parse'
    #0 0x57 in parse /src/proj/lib/parse.c:30

SUMMARY: MemorySanitizer: use-of-uninitialized-value /src/proj/lib/hdr.c:120:7 in read_hdr
"""


def test_free_site_skips_runtime_and_takes_the_first_project_frame():
    assert a.freed_site(UAF) == {
        "file": "/src/proj/lib/pool.c",
        "line": 88,
        "function": "release_it",
    }


def test_use_site_is_the_access_stack():
    assert a.p7.first_project_frame(UAF)["function"] == "use_it"


def test_index_sink_only_for_index_reports():
    ub = "/src/p/a.c:12:3: runtime error: index 7 out of bounds for type 'int [4]'\n"
    assert a.index_sink(ub) == 119
    assert a.index_sink("runtime error: signed integer overflow: 1 + 2147483647") is None
    assert a.index_site(ub) == {"file": "/src/p/a.c", "line": 12, "function": None}


def test_harness_rule_normalises_build_hops():
    assert a.harness({"file": "/src/proj/fuzz/fuzz_x.c"})
    assert a.harness({"file": "/src/krb5/src/tests/fuzzing/./../../kdc/replay.c"}) is False
    assert not a.harness({"file": "/src/proj/lib/pool.c"})


def _case(tmp: Path, aid: str, log: str) -> tuple[Path, Path]:
    d = tmp / "r" / aid
    d.mkdir(parents=True)
    (d / "vul.sanitizer.txt").write_text(log)
    for i in (1, 2):
        (d / f"fix{i}.sanitizer.txt").write_text("Executed /tmp/poc in 3 ms\n")
    (d / "result.json").write_text(json.dumps({"vul": "crashed", "fix": ["clean", "clean"]}))
    (tmp / "d").mkdir(exist_ok=True)
    (tmp / "d" / f"{aid}.diff").write_text("diff --git a/lib/x.c b/lib/x.c\n")
    return tmp / "r", tmp / "d"


def test_uaf_case_admits_free_then_read(tmp_path):
    rerun, diffs = _case(tmp_path, "1", UAF)
    step, got = a.evaluate_witnessed("1", "uaf", rerun, diffs)
    assert step == "admitted" and got["cwes"] == [416, 125]
    assert got["sites"][0]["function"] == "release_it"


def test_msan_case_admits_origin_then_use(tmp_path):
    rerun, diffs = _case(tmp_path, "2", MSAN)
    step, got = a.evaluate_witnessed("2", "msan", rerun, diffs)
    assert step == "admitted" and got["cwes"] == [456, 457]
    assert got["sites"][0]["line"] == 30 and got["sites"][1]["line"] == 120


def test_wrong_class_stops_at_reproduced(tmp_path):
    rerun, diffs = _case(tmp_path, "3", MSAN)
    step, got = a.evaluate_witnessed("3", "uaf", rerun, diffs)
    assert step == "reproduced" and "not this class" in got["why"]


def test_silent_patched_run_is_not_reproduced(tmp_path):
    rerun, diffs = _case(tmp_path, "4", UAF)
    (rerun / "4" / "fix2.sanitizer.txt").write_text("")
    step, got = a.evaluate_witnessed("4", "uaf", rerun, diffs)
    assert step == "selected" and "demonstrably" in got["why"]
