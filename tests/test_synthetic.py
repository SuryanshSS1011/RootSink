from chainforge.schema import (
    ChainLink,
    ChainRecord,
    ConfidenceTier,
    LinkRole,
    SanitizerReport,
)
from chainforge.synthetic import (
    LENGTH3_SPINES,
    _index_by_pair,
    compose_spine,
    generate_length3,
)


def _real(src, sink, tier, rec_id):
    kwargs = dict(
        id=rec_id,
        project="realproj",
        chain=[
            ChainLink(cwe_id=src, role=LinkRole.SOURCE),
            ChainLink(cwe_id=sink, role=LinkRole.SINK),
        ],
        chain_string=f"CWE-{src}->CWE-{sink}",
        label_confidence_tier=tier,
    )
    if tier == ConfidenceTier.GOLD:
        kwargs["patch_diff"] = "p"
        kwargs["sanitizer_reports"] = [
            SanitizerReport(revision="vulnerable", sanitizer="asan", log_ref="x", triggered=True)
        ]
    return ChainRecord(**kwargs)


def test_spines_are_admissible_length3():
    for src, mid, sink in LENGTH3_SPINES:
        assert mid == 190
        assert src != sink  # a genuine 3-CWE spine
    # the flagship 20->190->787 must be present
    assert (20, 190, 787) in LENGTH3_SPINES


def test_compose_spine_anchored_to_gold_is_silver():
    real = [_real(20, 787, ConfidenceTier.GOLD, "CHAINFORGE-0000000001")]
    by_pair = _index_by_pair(real)
    rec = compose_spine((20, 190, 787), by_pair, "CHAINFORGE-0900000")
    assert rec is not None
    assert rec.synthetic
    assert rec.label_confidence_tier == ConfidenceTier.SILVER  # gold endpoint anchor
    assert rec.chain_string == "CWE-20->CWE-190->CWE-787"
    assert len(rec.chain) == 3
    # one link_validation per hop (2 hops)
    assert len(rec.link_validation) == 2
    assert "CHAINFORGE-0000000001" in rec.link_validation[1]


def test_compose_spine_bronze_when_only_nongold_anchor():
    real = [_real(20, 787, ConfidenceTier.BRONZE, "CHAINFORGE-0000000002")]
    by_pair = _index_by_pair(real)
    rec = compose_spine((20, 190, 787), by_pair, "CHAINFORGE-0900000")
    assert rec.label_confidence_tier == ConfidenceTier.BRONZE


def test_compose_spine_no_anchor_returns_none():
    # No real CWE-20->CWE-787 record -> spine unsupported -> None (do not fabricate).
    by_pair = _index_by_pair([_real(20, 125, ConfidenceTier.GOLD, "CHAINFORGE-0000000003")])
    assert compose_spine((20, 190, 787), by_pair, "CHAINFORGE-0900000") is None


def test_synthetic_record_cannot_be_gold():
    # The schema forbids synthetic+GOLD; compose never emits GOLD, but assert the invariant.
    real = [_real(20, 787, ConfidenceTier.GOLD, "CHAINFORGE-0000000001")]
    rec = compose_spine((20, 190, 787), _index_by_pair(real), "CHAINFORGE-0900000")
    assert rec.label_confidence_tier != ConfidenceTier.GOLD


def test_generate_length3_from_corpus():
    real = [
        _real(20, 787, ConfidenceTier.GOLD, "CHAINFORGE-0000000001"),
        _real(20, 125, ConfidenceTier.GOLD, "CHAINFORGE-0000000002"),
        # no 20->119 -> that spine is skipped
    ]
    synth = generate_length3(real)
    chains = {r.chain_string for r in synth}
    assert "CWE-20->CWE-190->CWE-787" in chains
    assert "CWE-20->CWE-190->CWE-125" in chains
    assert "CWE-20->CWE-190->CWE-119" not in chains  # no anchor
    # all flagged synthetic, none GOLD, distinct ids
    assert all(r.synthetic for r in synth)
    assert all(r.label_confidence_tier != ConfidenceTier.GOLD for r in synth)
    assert len({r.id for r in synth}) == len(synth)


def test_generated_records_revalidate():
    real = [_real(20, 787, ConfidenceTier.GOLD, "CHAINFORGE-0000000001")]
    for rec in generate_length3(real):
        # round-trip through schema validation
        ChainRecord.model_validate_json(rec.model_dump_json())
