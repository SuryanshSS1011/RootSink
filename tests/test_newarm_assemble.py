from chainforge.mining.newarm_assemble import (
    assemble_newarm_batch,
    assemble_newarm_record,
    source_cwe_for,
)
from chainforge.schema import ConfidenceTier, LinkRole


def _ev(local_id=42470635, sink=119, san="AddressSanitizer", reproduced=True, fix_crashed=False):
    return {
        "local_id": local_id,
        "sink_cwe": sink,
        "project": "aom",
        "language": "C",
        "repro": {
            "reproduced": reproduced,
            "vul_crashed": True,
            "fix_crashed": fix_crashed,
            "vul_sanitizer": san,
        },
        "dataflows": [],
    }


def test_source_from_crash_type():
    assert source_cwe_for(119, "Index-out-of-bounds") == 129
    assert source_cwe_for(119, "Bad-cast") == 843
    assert source_cwe_for(476, "Null-dereference READ") == 252
    assert source_cwe_for(415, "Heap-double-free") == 362
    assert source_cwe_for(787, "Heap-buffer-overflow WRITE") is None  # not a new arm


def test_reproduced_with_patch_is_gold():
    diff = "+    if (idx >= ARRAY_SIZE(t)) return -1;\n"
    r = assemble_newarm_record(_ev(), "Index-out-of-bounds", diff, "http://x/commit/a")
    assert r.label_confidence_tier == ConfidenceTier.GOLD
    assert r.chain_string == "CWE-129->CWE-119"
    assert r.chain[0].role == LinkRole.SOURCE and r.chain[0].cwe_id == 129
    assert r.chain[1].role == LinkRole.SINK and r.chain[1].cwe_id == 119
    assert any(s.triggered for s in r.sanitizer_reports)  # GOLD invariant
    assert r.patch_diff  # GOLD invariant
    assert r.mitre_chain["edges"][0]["kind"] == "mitre-direct"


def test_reproduced_no_patch_is_silver():
    r = assemble_newarm_record(_ev(sink=415), "Heap-double-free", None, "url")
    assert r.label_confidence_tier == ConfidenceTier.SILVER
    assert r.chain_string == "CWE-362->CWE-415"
    assert r.patch_diff is None


def test_bad_cast_gives_843():
    r = assemble_newarm_record(
        _ev(), "Bad-cast", "+ if (o->type != T) return;\n", "http://x/commit/b"
    )
    assert r.chain_string == "CWE-843->CWE-119"


def test_not_reproduced_skipped():
    assert assemble_newarm_record(_ev(reproduced=False), "Index-out-of-bounds", "d", "u") is None
    # a case that also crashes at the fix (not a clean witness) is skipped
    assert assemble_newarm_record(_ev(fix_crashed=True), "Index-out-of-bounds", "d", "u") is None


def test_non_newarm_sink_skipped():
    # sink 787 is not a new arm -> None
    assert assemble_newarm_record(_ev(sink=787), "Heap-buffer-overflow WRITE", "d", "u") is None


def test_batch_dedupes():
    cases = [
        {
            "ev": _ev(local_id=1),
            "crash_type": "Index-out-of-bounds",
            "patch_diff": "d",
            "patch_url": "http://x/commit/a",
        },
        {
            "ev": _ev(local_id=1),
            "crash_type": "Index-out-of-bounds",
            "patch_diff": "d",
            "patch_url": "http://x/commit/a",
        },
        {
            "ev": _ev(local_id=2, sink=476),
            "crash_type": "Null-dereference",
            "patch_diff": None,
            "patch_url": "u",
        },
    ]
    recs = assemble_newarm_batch(cases)
    assert len(recs) == 2
    assert {r.chain_string for r in recs} == {"CWE-129->CWE-119", "CWE-252->CWE-476"}
