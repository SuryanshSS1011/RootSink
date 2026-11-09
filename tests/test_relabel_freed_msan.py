"""relabel_freed_msan.py and PR-3 I2 (release 1.0.7): an MSan origin created by a heap
deallocation is a use after free, CWE-416 -> CWE-125, and the contract accepts it."""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "infra" / "verify"))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
import relabel_freed_msan  # noqa: E402

from chainforge.integrity import crash_facts, source_contradiction  # noqa: E402

FREED = """==1==WARNING: MemorySanitizer: use-of-uninitialized-value
    #0 0x1 in use_it lib/a.c:9:3
  Uninitialized value was created by a heap deallocation
    #0 0x2 in free msan_interceptors.cc:228
    #1 0x3 in drop_it lib/a.c:5:5
"""
CREATED = FREED.replace("a heap deallocation", "a heap allocation")


def record(tmp_path, log_text, rid="R1"):
    log = tmp_path / "logs" / f"{rid}.txt"
    log.parent.mkdir(exist_ok=True)
    log.write_text(log_text)
    root = {
        "cwe_id": 456,
        "role": "source",
        "evidence_kind": "execution",
        "evidence": {
            "sanitizer_report_ref": "vul.sanitizer.txt",
            "patch_hunk_ref": "MSan origin block: uninitialised value created here",
            "location": {"file": "lib/a.c", "line": 5, "function": "drop_it", "stage": None},
        },
    }
    sink = {"cwe_id": 457, "role": "sink", "evidence_kind": "execution", "evidence": {}}
    return {
        "id": rid,
        "label_confidence_tier": "gold",
        "provenance": "arvo-msan",
        "chain": [root, sink],
        "chain_string": "CWE-456->CWE-457",
        "sanitizer_reports": [
            {"revision": "vulnerable", "log_ref": str(log), "triggered": True, "sanitizer": "msan"}
        ],
    }


def run(tmp_path, rows):
    rel = tmp_path / "release"
    rel.mkdir(exist_ok=True)
    (rel / "dataset.jsonl").write_text("".join(json.dumps(r) + "\n" for r in rows))
    relabel_freed_msan.main(["--release", str(rel), "--root", "/"])
    return [json.loads(x) for x in (rel / "dataset.jsonl").read_text().splitlines()]


def test_heap_deallocation_origin_becomes_use_after_free(tmp_path):
    out = run(tmp_path, [record(tmp_path, FREED)])
    root, sink = out[0]["chain"]
    assert (root["cwe_id"], sink["cwe_id"]) == (416, 125)
    assert out[0]["chain_string"] == "CWE-416->CWE-125"
    assert root["evidence"]["location"]["stage"].startswith("freed")
    assert root["site_kind"] == "origin-site"


def test_heap_allocation_origin_is_left_alone(tmp_path):
    out = run(tmp_path, [record(tmp_path, CREATED)])
    assert out[0]["chain_string"] == "CWE-456->CWE-457"


def test_contract_accepts_cwe416_on_a_freed_msan_origin():
    rec = {"chain": [{"cwe_id": 416, "evidence_kind": "execution"}, {"cwe_id": 125}]}
    assert source_contradiction(rec, crash_facts(FREED)) is None
    assert source_contradiction(rec, crash_facts(CREATED)) is not None
