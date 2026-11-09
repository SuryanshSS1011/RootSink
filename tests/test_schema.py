import pytest
from pydantic import ValidationError

from chainforge.schema import (
    ChainLink,
    ChainRecord,
    ConfidenceTier,
    LinkRole,
    SanitizerReport,
)


def _bronze_record(**overrides):
    base = dict(
        id="CHAINFORGE-0001",
        project="libfoo",
        chain=[
            ChainLink(cwe_id=20, role=LinkRole.SOURCE),
            ChainLink(cwe_id=190, role=LinkRole.INTERMEDIATE),
            ChainLink(cwe_id=787, role=LinkRole.SINK),
        ],
        chain_string="CWE-20->CWE-190->CWE-787",
        label_confidence_tier=ConfidenceTier.BRONZE,
    )
    base.update(overrides)
    return ChainRecord(**base)


def test_valid_bronze_record():
    r = _bronze_record()
    assert r.chain_string == "CWE-20->CWE-190->CWE-787"
    assert [link.cwe_id for link in r.chain] == [20, 190, 787]


def test_chain_string_must_match_order():
    with pytest.raises(ValidationError, match="does not match chain order"):
        _bronze_record(chain_string="CWE-190->CWE-20->CWE-787")


def test_inadmissible_edge_rejected():
    with pytest.raises(ValidationError, match="not admissible"):
        ChainRecord(
            id="CHAINFORGE-0002",
            project="libfoo",
            chain=[
                ChainLink(cwe_id=787, role=LinkRole.SOURCE),
                ChainLink(cwe_id=20, role=LinkRole.SINK),
            ],
            chain_string="CWE-787->CWE-20",
            label_confidence_tier=ConfidenceTier.BRONZE,
        )


def test_roles_must_be_source_then_sink():
    with pytest.raises(ValidationError, match="first link must have role=source"):
        ChainRecord(
            id="CHAINFORGE-0003",
            project="libfoo",
            chain=[
                ChainLink(cwe_id=20, role=LinkRole.SINK),
                ChainLink(cwe_id=190, role=LinkRole.SINK),
            ],
            chain_string="CWE-20->CWE-190",
            label_confidence_tier=ConfidenceTier.BRONZE,
        )


def test_unknown_cwe_rejected():
    with pytest.raises(ValidationError, match="not in the 8-CWE catalog"):
        ChainLink(cwe_id=999, role=LinkRole.SOURCE)


def test_gold_requires_execution_and_patch():
    # GOLD without sanitizer/patch evidence must fail.
    with pytest.raises(ValidationError, match="GOLD tier requires"):
        _bronze_record(label_confidence_tier=ConfidenceTier.GOLD)


def test_gold_with_evidence_ok():
    r = _bronze_record(
        label_confidence_tier=ConfidenceTier.GOLD,
        patch_diff="--- a/foo.c\n+++ b/foo.c\n@@ ... guard added",
        sanitizer_reports=[
            SanitizerReport(
                revision="vulnerable",
                sanitizer="asan",
                log_ref="reports/0001-asan.log",
                triggered=True,
            )
        ],
    )
    assert r.label_confidence_tier == ConfidenceTier.GOLD


def test_bad_id_pattern_rejected():
    with pytest.raises(ValidationError):
        _bronze_record(id="CF-1")


def test_mitre_chain_computed_on_record():
    # The mitre_chain field is computed in the validator (not user-set) for every record.
    r = _bronze_record()  # 20->190->787
    mc = r.mitre_chain
    assert mc["catalog_version"] == "4.20"
    kinds = [e["kind"] for e in mc["edges"]]
    assert kinds == ["mitre-hierarchy", "mitre-transitive"]
    assert mc["any_catalog_only"] is False


def test_mitre_chain_flags_catalog_only_edge():
    # 476->787 is a CHAINFORGE modeling edge (not in MITRE) -> flagged catalog-only.
    r = _bronze_record(
        chain=[
            ChainLink(cwe_id=476, role=LinkRole.SOURCE),
            ChainLink(cwe_id=787, role=LinkRole.SINK),
        ],
        chain_string="CWE-476->CWE-787",
    )
    assert r.mitre_chain["any_catalog_only"] is True


def test_related_records_roundtrip():
    r = _bronze_record(related_records=["CHAINFORGE-0002", "CHAINFORGE-0003"])
    assert r.related_records == ["CHAINFORGE-0002", "CHAINFORGE-0003"]
    # survives serialization
    r2 = ChainRecord.model_validate_json(r.model_dump_json())
    assert r2.related_records == ["CHAINFORGE-0002", "CHAINFORGE-0003"]
