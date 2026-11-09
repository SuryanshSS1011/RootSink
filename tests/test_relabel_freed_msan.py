"""relabel_freed_msan.py and PR-3 I2 (release 1.0.7): an MSan origin created by a heap
deallocation is a use after free, CWE-416 -> CWE-125, and the contract accepts it."""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "infra" / "verify"))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
import relabel_freed_msan  # noqa: E402

from chainforge.integrity import crash_facts, sink_contradiction, source_contradiction  # noqa: E402

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


def test_contract_rejects_a_write_sink_on_a_freed_msan_origin():
    rec = {"chain": [{"cwe_id": 416, "evidence_kind": "execution"}, {"cwe_id": 787}]}
    assert sink_contradiction(rec, crash_facts(FREED)) is not None


def test_only_the_first_report_counts():
    other = "==2==WARNING: MemorySanitizer: use-of-uninitialized-value\nSUMMARY: x\n"
    assert crash_facts(other + FREED.replace("WARNING", "NOTE"))["freed_origin"] is False


def test_hunk_named_root_is_left_to_the_guard_rule(tmp_path):
    r = record(tmp_path, FREED)
    r["chain"][0]["evidence"]["causal_proof"] = {"hunk": "hunk00.patch"}
    out = run(tmp_path, [r])
    assert out[0]["chain_string"] == "CWE-456->CWE-457"


def test_record_relabelled_before_the_note_update_gets_the_new_note(tmp_path):
    old = "CWE-456 at the origin block's creation site, CWE-457 at the SUMMARY use site"
    r = record(tmp_path, FREED)
    r["dataflow_evidence"] = old
    out = run(tmp_path, [r])
    new_note = out[0]["dataflow_evidence"]
    new_ref = out[0]["chain"][0]["evidence"]["patch_hunk_ref"]
    # A 1.0.7-style record: relabelled, but with the old note and hunk reference.
    out[0]["dataflow_evidence"] = old
    out[0]["chain"][0]["evidence"]["patch_hunk_ref"] = "MSan origin block: memory freed here"
    rel = tmp_path / "release"
    (rel / "corrections_changelog.jsonl").unlink()
    again = run(tmp_path, out)
    assert again[0]["dataflow_evidence"] == new_note and "CWE-456" not in new_note
    assert again[0]["chain"][0]["evidence"]["patch_hunk_ref"] == new_ref
    logf = rel / "corrections_changelog.jsonl"
    assert [json.loads(x)["op"] for x in logf.read_text().splitlines()] == [
        "freed-msan-note-rewritten"
    ]
    run(tmp_path, again)  # idempotent: nothing more to log
    assert len(logf.read_text().splitlines()) == 1
