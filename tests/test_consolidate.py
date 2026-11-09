from chainforge.consolidate import (
    consolidate,
    record_score,
    stable_id,
)
from chainforge.schema import (
    ChainLink,
    ChainRecord,
    ConfidenceTier,
    LinkRole,
)


def _rec(local_id, src_cwe, sink_cwe, tier, project="proj", rec_id="CHAINFORGE-0001"):
    roles = [LinkRole.SOURCE, LinkRole.SINK]
    return ChainRecord(
        id=rec_id,
        aliases=[f"OSS-Fuzz-{local_id}"],
        project=project,
        chain=[
            ChainLink(cwe_id=src_cwe, role=roles[0]),
            ChainLink(cwe_id=sink_cwe, role=roles[1]),
        ],
        chain_string=f"CWE-{src_cwe}->CWE-{sink_cwe}",
        label_confidence_tier=tier,
        patch_diff="p" if tier == ConfidenceTier.GOLD else None,
        sanitizer_reports=(
            [
                {
                    "revision": "vulnerable",
                    "sanitizer": "asan",
                    "log_ref": "x",
                    "triggered": True,
                }
            ]
            if tier == ConfidenceTier.GOLD
            else []
        ),
    )


def test_stable_id_from_local_id():
    assert stable_id(42480497) == "CHAINFORGE-0042480497"


def test_dedup_keeps_more_specific_source():
    # Same localId: old mislabel CWE-20->787 (gold) vs corrected CWE-416->787 (gold).
    old = _rec(100, 20, 787, ConfidenceTier.GOLD)
    new = _rec(100, 416, 787, ConfidenceTier.GOLD)
    out, manifest = consolidate([old, new])
    assert len(out) == 1
    assert out[0].chain_string == "CWE-416->CWE-787"  # more-specific root wins
    assert manifest.superseded == 1


def test_dedup_keeps_higher_tier():
    gold = _rec(200, 20, 787, ConfidenceTier.GOLD)
    bronze = _rec(200, 416, 787, ConfidenceTier.BRONZE)
    out, _ = consolidate([bronze, gold])
    assert len(out) == 1
    # GOLD outranks BRONZE even though 416 is more specific than 20
    assert out[0].label_confidence_tier == ConfidenceTier.GOLD
    assert out[0].chain_string == "CWE-20->CWE-787"


def test_stable_ids_assigned():
    out, _ = consolidate([_rec(42480497, 416, 787, ConfidenceTier.GOLD)])
    assert out[0].id == "CHAINFORGE-0042480497"


def test_distinct_local_ids_all_kept():
    recs = [
        _rec(1, 20, 787, ConfidenceTier.GOLD),
        _rec(2, 416, 787, ConfidenceTier.GOLD),
        _rec(3, 20, 125, ConfidenceTier.SILVER),
    ]
    out, manifest = consolidate(recs)
    assert len(out) == 3
    assert manifest.superseded == 0


def test_manifest_composition():
    recs = [
        _rec(1, 20, 787, ConfidenceTier.GOLD, project="a"),
        _rec(2, 416, 787, ConfidenceTier.GOLD, project="b"),
        _rec(3, 416, 787, ConfidenceTier.SILVER, project="a"),
        _rec(4, 20, 125, ConfidenceTier.BRONZE, project="c"),
    ]
    out, m = consolidate(recs)
    assert m.total == 4
    assert m.by_tier == {"gold": 2, "silver": 1, "bronze": 1}
    assert m.by_chain["CWE-416->CWE-787"] == 2
    assert m.by_pair_tier["CWE-416->CWE-787"] == {"gold": 1, "silver": 1}
    assert m.distinct_projects == 3


def test_record_score_ordering():
    gold_416 = _rec(1, 416, 787, ConfidenceTier.GOLD)
    gold_20 = _rec(2, 20, 787, ConfidenceTier.GOLD)
    bronze_416 = _rec(3, 416, 787, ConfidenceTier.BRONZE)
    assert record_score(gold_416) > record_score(gold_20)  # specificity breaks tier tie
    assert record_score(gold_20) > record_score(bronze_416)  # tier dominates


def _syzbot_rec(extid, src, sink, tier, rec_id="CHAINFORGE-0800001"):
    from chainforge.schema import Locality

    return ChainRecord(
        id=rec_id,
        aliases=[f"syzbot-{extid}"],
        project="linux-kernel",
        ecosystem="linux-kernel",
        chain=[
            ChainLink(cwe_id=src, role=LinkRole.SOURCE),
            ChainLink(cwe_id=sink, role=LinkRole.SINK),
        ],
        chain_string=f"CWE-{src}->CWE-{sink}",
        label_confidence_tier=tier,
        locality=Locality.CROSS_FUNCTION,
    )


def test_syzbot_records_dedup_by_extid_and_get_stable_id():
    # Same extid twice (different seq ids) -> deduped to one, stable id in the '9' range.
    a = _syzbot_rec("abc123", 416, 125, ConfidenceTier.SILVER, "CHAINFORGE-0800001")
    b = _syzbot_rec("abc123", 416, 125, ConfidenceTier.SILVER, "CHAINFORGE-0800099")
    out, m = consolidate([a, b])
    assert len(out) == 1
    assert m.superseded == 1
    assert out[0].id.startswith("CHAINFORGE-9")  # syzbot id range


def test_arvo_and_syzbot_coexist_no_collision():
    arvo = _rec(42480497, 416, 787, ConfidenceTier.GOLD)
    syz = _syzbot_rec("deadbeef", 416, 125, ConfidenceTier.SILVER)
    out, m = consolidate([arvo, syz])
    assert len(out) == 2
    ids = {r.id for r in out}
    assert "CHAINFORGE-0042480497" in ids  # ARVO localId-based
    assert any(i.startswith("CHAINFORGE-9") for i in ids)  # syzbot hashed
