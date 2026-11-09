from chainforge.mining.arvo_index import ArvoIndexRow
from chainforge.pilot import (
    CandidateEvidence,
    DataflowOutcome,
    GateMetrics,
    ReproOutcome,
    assemble_batch,
    assign_tier,
    build_chain_record,
    compute_metrics,
    evidence_from_json,
)
from chainforge.schema import ConfidenceTier


def _row(sink_crash="Heap-buffer-overflow WRITE 4", lang="c", patch="url"):
    return ArvoIndexRow(
        local_id=40096184,
        project="skia",
        fix_commit="07afa23bd0fa74d18fb7faee898b2a876536a170",
        patch_url=patch,
        sanitizer="asan",
        crash_type=sink_crash,
        language=lang,
        repo_addr="repo",
        reproduced=True,
    )


def _reproduced():
    return ReproOutcome(reproduced=True, vul_crashed=True, fix_crashed=False, vul_sanitizer="asan")


def _dataflow(src=190, sink=787, has=True, paths=3):
    return DataflowOutcome(src_cwe=src, sink_cwe=sink, has_dataflow=has, path_count=paths)


def test_most_specific_source_wins_over_path_count():
    # UAF case: CWE-20 has 726 paths, CWE-416 has only 5, but 416 is more specific -> it wins.
    ev = CandidateEvidence(
        row=_row(),
        sink_cwe=787,
        dataflows=[
            DataflowOutcome(src_cwe=20, sink_cwe=787, has_dataflow=True, path_count=726),
            DataflowOutcome(src_cwe=416, sink_cwe=787, has_dataflow=True, path_count=5),
        ],
    )
    best = ev.best_source_dataflow()
    assert best.src_cwe == 416  # specificity beats path count


def test_cwe20_fallback_when_only_source():
    ev = CandidateEvidence(
        row=_row(),
        sink_cwe=787,
        dataflows=[DataflowOutcome(src_cwe=20, sink_cwe=787, has_dataflow=True, path_count=100)],
    )
    assert ev.best_source_dataflow().src_cwe == 20


def test_specificity_tie_breaks_on_path_count():
    # Same specificity (both 20) -> higher path count wins.
    ev = CandidateEvidence(
        row=_row(),
        sink_cwe=125,
        dataflows=[
            DataflowOutcome(src_cwe=20, sink_cwe=125, has_dataflow=True, path_count=3),
            DataflowOutcome(src_cwe=20, sink_cwe=125, has_dataflow=True, path_count=9),
        ],
    )
    assert ev.best_source_dataflow().path_count == 9


def test_tier_gold_requires_repro_patch_and_dataflow():
    ev = CandidateEvidence(
        row=_row(), sink_cwe=787, repro=_reproduced(), dataflows=[_dataflow()], has_patch=True
    )
    assert assign_tier(ev) == ConfidenceTier.GOLD


def test_tier_silver_dataflow_without_repro():
    ev = CandidateEvidence(row=_row(), sink_cwe=787, repro=None, dataflows=[_dataflow()])
    assert assign_tier(ev) == ConfidenceTier.SILVER


def test_tier_silver_reproduced_but_no_patch():
    # Reproduced + dataflow but no patch -> not GOLD, still SILVER.
    ev = CandidateEvidence(
        row=_row(patch=None),
        sink_cwe=787,
        repro=_reproduced(),
        dataflows=[_dataflow()],
        has_patch=False,
    )
    assert assign_tier(ev) == ConfidenceTier.SILVER


def test_tier_bronze_no_dataflow():
    ev = CandidateEvidence(
        row=_row(),
        sink_cwe=787,
        repro=_reproduced(),
        dataflows=[_dataflow(has=False, paths=0)],
        has_patch=True,
    )
    assert assign_tier(ev) == ConfidenceTier.BRONZE


def test_build_gold_record_is_valid():
    ev = CandidateEvidence(
        row=_row(), sink_cwe=787, repro=_reproduced(), dataflows=[_dataflow()], has_patch=True
    )
    rec = build_chain_record(ev, "CHAINFORGE-0001")
    assert rec.label_confidence_tier == ConfidenceTier.GOLD
    assert rec.chain_string == "CWE-190->CWE-787"
    assert rec.language == "C"
    assert "OSS-Fuzz-40096184" in rec.aliases
    # GOLD schema invariants: a triggered sanitizer report and a patch_diff.
    assert any(r.triggered for r in rec.sanitizer_reports)
    assert rec.patch_diff


def test_build_bronze_record_uses_first_admissible_source():
    # No dataflow -> BRONZE, source picked from catalog (sink 787 -> min source).
    ev = CandidateEvidence(row=_row(), sink_cwe=787, repro=None, dataflows=[])
    rec = build_chain_record(ev, "CHAINFORGE-0002")
    assert rec.label_confidence_tier == ConfidenceTier.BRONZE
    # admissible sources for 787 are {20,190,416,476}; min is 20
    assert rec.chain[0].cwe_id == 20
    assert rec.chain_string == "CWE-20->CWE-787"


def test_metrics_and_gate1():
    tiers = [ConfidenceTier.GOLD] * 20 + [ConfidenceTier.SILVER] * 10 + [ConfidenceTier.BRONZE] * 10
    m = compute_metrics(tiers)
    assert m.total == 40
    assert m.gold == 20 and m.silver == 10 and m.bronze == 10
    assert m.silver_or_better == 30
    assert m.silver_or_better_frac == 0.75
    assert m.passes_gate1  # >=50% silver+ and >=20 gold


def test_gate1_fails_without_enough_gold():
    tiers = [ConfidenceTier.SILVER] * 40  # 100% silver+ but 0 gold
    m = compute_metrics(tiers)
    assert m.silver_or_better_frac == 1.0
    assert not m.passes_gate1  # needs >=20 gold


def test_gatemetrics_empty():
    m = GateMetrics(total=0, gold=0, silver=0, bronze=0)
    assert m.silver_or_better_frac == 0.0
    assert not m.passes_gate1


def test_evidence_from_json_roundtrip():
    ev_json = {
        "local_id": 40096184,
        "sink_cwe": 787,
        "repro": {
            "reproduced": True,
            "vul_crashed": True,
            "fix_crashed": False,
            "vul_sanitizer": "asan",
        },
        "dataflows": [{"src_cwe": 190, "sink_cwe": 787, "has_dataflow": True, "path_count": 3}],
    }
    ev = evidence_from_json(_row(), ev_json)
    assert ev.sink_cwe == 787
    assert ev.repro.reproduced
    assert ev.has_patch  # row has patch_url/fix_commit
    assert assign_tier(ev) == ConfidenceTier.GOLD


def test_assemble_batch_skips_invalid_sink_and_numbers_ids():
    good = CandidateEvidence(
        row=_row(), sink_cwe=787, repro=_reproduced(), dataflows=[_dataflow()], has_patch=True
    )
    # sink 20 is source-only in the catalog (never a terminal sink) -> build_chain_record
    # raises -> skipped. (476 is no longer source-only: the race arm adds 362->476.)
    invalid = CandidateEvidence(row=_row(sink_crash="Improper Input Validation"), sink_cwe=20)
    records, metrics = assemble_batch([good, invalid, good], id_start=1)
    assert len(records) == 2  # the invalid one is dropped
    assert [r.id for r in records] == ["CHAINFORGE-0001", "CHAINFORGE-0002"]
    assert metrics.total == 2
    assert metrics.gold == 2


def test_patch_overflow_190_is_silver_190_source():
    # No dataflow, but patch proves overflow + reproduced -> SILVER CWE-190->sink.
    ev = CandidateEvidence(
        row=_row(sink_crash="Heap-buffer-overflow READ 2"),
        sink_cwe=125,
        repro=_reproduced(),
        dataflows=[],
        patch_overflow_190=True,
    )
    assert assign_tier(ev) == ConfidenceTier.SILVER
    rec = build_chain_record(ev, "CHAINFORGE-0000000001")
    assert rec.chain_string == "CWE-190->CWE-125"
    assert rec.chain[0].cwe_id == 190
    assert rec.label_confidence_tier == ConfidenceTier.SILVER


def test_patch_overflow_190_not_gold_without_witness():
    # Even reproduced + patch + overflow: no dataflow/ordered-link witness -> never GOLD.
    ev = CandidateEvidence(
        row=_row(), sink_cwe=787, repro=_reproduced(), has_patch=True, patch_overflow_190=True
    )
    assert assign_tier(ev) != ConfidenceTier.GOLD
    assert assign_tier(ev) == ConfidenceTier.SILVER


def test_patch_overflow_190_beats_coincident_cwe20_dataflow():
    # The jq-case bug: patch proves 190, but a CWE-20 dataflow is also positive.
    # 190 must win (source) and it must be SILVER (no 190 witness), NOT CWE-20 GOLD.
    ev = CandidateEvidence(
        row=_row(sink_crash="Heap-buffer-overflow READ 2"),
        sink_cwe=125,
        repro=_reproduced(),
        has_patch=True,
        patch_overflow_190=True,
        dataflows=[DataflowOutcome(src_cwe=20, sink_cwe=125, has_dataflow=True, path_count=44)],
    )
    assert ev.effective_source_cwe() == 190  # 190 beats the CWE-20 dataflow
    assert assign_tier(ev) == ConfidenceTier.SILVER  # not GOLD via the CWE-20 path
    rec = build_chain_record(ev, "CHAINFORGE-0000000042")
    assert rec.chain_string == "CWE-190->CWE-125"
    assert rec.label_confidence_tier == ConfidenceTier.SILVER


def test_patch_overflow_190_not_reproduced_is_bronze():
    # Patch proves overflow but the case did NOT reproduce -> BRONZE (no execution, no witness),
    # NOT a 190 SILVER via a coincident CWE-20 dataflow.
    ev = CandidateEvidence(
        row=_row(sink_crash="Heap-buffer-overflow READ 2"),
        sink_cwe=125,
        repro=ReproOutcome(reproduced=False, vul_crashed=False, fix_crashed=False),
        patch_overflow_190=True,
        dataflows=[DataflowOutcome(src_cwe=20, sink_cwe=125, has_dataflow=True, path_count=4)],
    )
    assert assign_tier(ev) == ConfidenceTier.BRONZE
    rec = build_chain_record(ev, "CHAINFORGE-0000000043")
    assert rec.chain_string == "CWE-190->CWE-125"  # source is still 190 (patch-proven)
    assert rec.label_confidence_tier == ConfidenceTier.BRONZE


def test_copresent_recovers_masked_chains():
    # A reproduced 787 write where 20, 416, AND 476 independently connect (disjoint node sets).
    ev = CandidateEvidence(
        row=_row(), sink_cwe=787, repro=_reproduced(),
        dataflows=[
            DataflowOutcome(src_cwe=20, sink_cwe=787, has_dataflow=True, path_count=500),
            DataflowOutcome(src_cwe=416, sink_cwe=787, has_dataflow=True, path_count=8),
            DataflowOutcome(src_cwe=476, sink_cwe=787, has_dataflow=True, path_count=3),
        ],
    )
    # old picker keeps only the most-specific
    assert ev.effective_source_cwe() == 416
    # co-present recovers both specific roots, drops the broad CWE-20 catch-all
    cp = [d.src_cwe for d in ev.copresent_source_dataflows()]
    assert cp == [416, 476]  # most-specific first


def test_copresent_keeps_solo_cwe20():
    ev = CandidateEvidence(
        row=_row(), sink_cwe=787, repro=_reproduced(),
        dataflows=[DataflowOutcome(src_cwe=20, sink_cwe=787, has_dataflow=True, path_count=100)],
    )
    assert [d.src_cwe for d in ev.copresent_source_dataflows()] == [20]


def test_copresent_dedupes_same_source():
    ev = CandidateEvidence(
        row=_row(), sink_cwe=787, repro=_reproduced(),
        dataflows=[
            DataflowOutcome(src_cwe=416, sink_cwe=787, has_dataflow=True, path_count=8),
            DataflowOutcome(src_cwe=416, sink_cwe=787, has_dataflow=True, path_count=12),
        ],
    )
    cp = ev.copresent_source_dataflows()
    assert len(cp) == 1 and cp[0].path_count == 12  # keeps the higher path_count


def test_copresent_empty_when_no_dataflow():
    ev = CandidateEvidence(row=_row(), sink_cwe=787, repro=_reproduced(), dataflows=[])
    assert ev.copresent_source_dataflows() == []
