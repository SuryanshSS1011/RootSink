"""infra/repro/check.py, the replay checker verify.sh ends with: it sees MemorySanitizer reports,
reads a use-after-free sink as PR-8 states it, and exits 2 when it cannot parse a witness."""

import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CHECK = ROOT / "infra" / "repro" / "check.py"

UAF = """==1==ERROR: AddressSanitizer: heap-use-after-free on address 0x6020 at pc 0x1 bp 0x2 sp 0x3
READ of size 8 at 0x6020 thread T0
    #0 0x1 in f /src/p/a.c:9:3
SUMMARY: AddressSanitizer: heap-use-after-free /src/p/a.c:9:3 in f
"""
MSAN = """==1==WARNING: MemorySanitizer: use-of-uninitialized-value
    #0 0x1 in g /src/p/b.c:4:7
SUMMARY: MemorySanitizer: use-of-uninitialized-value /src/p/b.c:4:7 in g
"""


def run(tmp_path, bundle, vul, check=CHECK):
    (tmp_path / "b.json").write_text(json.dumps(bundle))
    (tmp_path / "vul.txt").write_text(vul)
    (tmp_path / "fix.txt").write_text("INFO: Running with entropic power schedule\n")
    p = subprocess.run(
        [
            sys.executable,
            "-I",
            str(check),
            *(str(tmp_path / f) for f in ("b.json", "vul.txt", "fix.txt")),
        ],
        capture_output=True,
        text=True,
    )
    return p.returncode, json.loads(p.stdout)


def uaf_bundle(before_sink):
    witness = {"bug_class": "heap-use-after-free", "direction": "READ", "implies_sink_cwe": 125}
    return {
        "record_id": "X",
        "expected": {"vulnerable": {"witness": witness}},
        "links": [{"cwe_id": before_sink, "role": "source"}, {"cwe_id": 125, "role": "sink"}],
    }


def test_use_after_free_read_behind_416_is_a_125_sink(tmp_path):
    rc, v = run(tmp_path, uaf_bundle(416), UAF)
    assert rc == 0 and v["verdict"] == "PASS"
    rc, v = run(tmp_path, uaf_bundle(20), UAF)  # PR-8: no CWE-416 link, no 125 sink
    assert rc == 1 and not next(c for c in v["checks"] if c["check"] == "sink_cwe")["ok"]


def test_memory_sanitizer_warning_is_a_crash(tmp_path):
    witness = {"bug_class": "use-of-uninitialized-value", "implies_sink_cwe": 457}
    bundle = {"record_id": "Y", "expected": {"vulnerable": {"witness": witness}}}
    rc, v = run(tmp_path, bundle, MSAN)
    assert rc == 0 and v["verdict"] == "PASS"


def test_missing_parser_is_inconclusive_not_fail(tmp_path):
    lone = tmp_path / "repro"
    lone.mkdir()
    (lone / "check.py").write_text(CHECK.read_text())  # no ../mac/parse_sanitizer.py beside it
    rc, v = run(tmp_path, uaf_bundle(416), UAF, check=lone / "check.py")
    assert rc == 2 and v["verdict"] == "INCONCLUSIVE"


UBSAN_SEGV = """UndefinedBehaviorSanitizer:DEADLYSIGNAL
==1==ERROR: UndefinedBehaviorSanitizer: SEGV on unknown address 0x000000000000
SUMMARY: UndefinedBehaviorSanitizer: SEGV (/out/f+0x1)
"""
UBSAN_ONLY = """/src/p/c.c:12:9: runtime error: index 40 out of bounds for type 'int[8]'
SUMMARY: UndefinedBehaviorSanitizer: undefined-behavior /src/p/c.c:12:9
"""


def test_undefined_behavior_sanitizer_reports_are_read(tmp_path):
    bundle = {"record_id": "Z", "expected": {"vulnerable": {"witness": {}}}}
    rc, v = run(tmp_path, bundle, UBSAN_SEGV)
    assert rc == 0 and v["checks"][0] == {"check": "vulnerable_crashes", "ok": True, "detail": ""}
    witness = {"sanitizer": "undefined", "bug_class": "undefined-behavior"}
    bundle["expected"]["vulnerable"]["witness"] = witness
    rc, v = run(tmp_path, bundle, UBSAN_ONLY)
    assert rc == 0 and v["verdict"] == "PASS"
