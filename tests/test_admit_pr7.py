"""PR-7 admits a mined case only through replay -> sink -> logged proof -> derived CWE -> chain."""

import importlib.util
import json
from pathlib import Path

spec = importlib.util.spec_from_file_location(
    "pr7", Path(__file__).resolve().parents[1] / "infra/verify/admit_pr7.py"
)
pr7 = importlib.util.module_from_spec(spec)
spec.loader.exec_module(pr7)

VUL = (
    "==1==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x6\n"
    "WRITE of size 4 at 0x6 thread T0\n"
    "    #0 0x55 in copy_row /src/proj/lib/row.c:88:5\n"
)
CLEAN = "Running: /tmp/poc\nExecuted /tmp/poc in 3 ms\n"
GUARD = (
    "diff --git a/lib/row.c b/lib/row.c\n--- a/lib/row.c\n+++ b/lib/row.c\n"
    "@@ -80,3 +80,5 @@ int copy_row(char *dst, size_t n, size_t cap)\n"
    " {\n+    if (n > cap)\n+        return -1;\n     memcpy(dst, src, n);\n"
)


def _case(tmp: Path, *, fix_log=CLEAN, guard_log=CLEAN, guard_file="lib/row.c"):
    rr = tmp / "rerun" / "1"
    rr.mkdir(parents=True)
    (rr / "result.json").write_text(json.dumps({"vul": "crashed", "fix": ["clean", "clean"]}))
    (rr / "vul.sanitizer.txt").write_text(VUL)
    for i in (1, 2):
        (rr / f"fix{i}.sanitizer.txt").write_text(fix_log)
    ab = tmp / "abl" / "1"
    (ab / "hunks").mkdir(parents=True)
    g = {"hunk": "hunk00.patch", "file": guard_file, "added": 2}
    (ab / "result.json").write_text(json.dumps({"control": "crashed", "guard_hunk": g}))
    (ab / "control.log").write_text(VUL)
    (ab / "hunk00.patch.log").write_text(guard_log)
    (ab / "hunks" / "hunk00.patch").write_text(GUARD)
    (tmp / "diffs").mkdir()
    (tmp / "diffs" / "1.diff").write_text(GUARD)
    return tmp / "rerun", {"1": ab}, tmp / "diffs"


def test_full_pass_is_admitted_with_sink_from_report(tmp_path):
    step, got = pr7.evaluate("1", *_case(tmp_path))
    assert step == "admitted"
    assert got["sink"] == 787
    assert got["sink_site"]["function"] == "copy_row"
    assert got["source"] is not None and got["source"] != 787


def test_patched_run_that_never_executed_is_not_reproduced(tmp_path):
    step, got = pr7.evaluate("1", *_case(tmp_path, fix_log="Shadow memory range interleaves\n"))
    assert step == "selected"
    assert "execute" in got["why"]


def test_unlogged_guard_run_is_no_proof(tmp_path):
    step, _ = pr7.evaluate("1", *_case(tmp_path, guard_log="build ok\n"))
    assert step == "sink"


def test_harness_hunk_is_no_proof(tmp_path):
    step, got = pr7.evaluate("1", *_case(tmp_path, guard_file="fuzz/row_fuzzer.c"))
    assert step == "sink"
    assert "harness" in got["why"]


def test_non_overflow_sink_is_not_admitted():
    assert pr7.sink_cwe(VUL.replace("heap-buffer-overflow", "heap-use-after-free")) is None
    assert pr7.sink_cwe(VUL.replace("WRITE", "READ")) == 125
