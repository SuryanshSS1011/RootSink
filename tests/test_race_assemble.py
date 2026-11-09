from chainforge.mining.race_assemble import assemble_race_batch, assemble_race_record
from chainforge.schema import ConfidenceTier, LinkRole


def _seed(cve="CVE-2016-8655", sink=416, tier="SILVER", refs=("url",), pats=("mutex_lock",)):
    return {
        "cve": cve,
        "cwe_sequence": [362, sink],
        "chain_string": f"CWE-362->CWE-{sink}",
        "all_catalog_cwes": [362, sink],
        "fix_refs": list(refs),
        "tier": tier,
        "race_signal": tier == "SILVER",
        "matched_patterns": list(pats),
    }


def test_silver_race_record():
    r = assemble_race_record(_seed(tier="SILVER"))
    assert r.label_confidence_tier == ConfidenceTier.SILVER
    assert r.chain_string == "CWE-362->CWE-416"
    assert r.chain[0].cwe_id == 362 and r.chain[0].role == LinkRole.SOURCE
    assert r.chain[1].cwe_id == 416 and r.chain[1].role == LinkRole.SINK
    assert "sync guard" in r.chain[0].evidence.patch_hunk_ref
    assert r.provenance == "nvd-race"
    assert r.commit_range.fixed == "url"


def test_bronze_race_record():
    r = assemble_race_record(_seed(tier="BRONZE", pats=()))
    assert r.label_confidence_tier == ConfidenceTier.BRONZE
    assert "co-occurrence" in r.dataflow_evidence


def test_race_476_sink():
    r = assemble_race_record(_seed(sink=476))
    assert r.chain_string == "CWE-362->CWE-476"


def test_mitre_provenance_is_direct():
    # 362->416 and 362->476 are MITRE-direct CanPrecede edges; the record's computed
    # mitre_chain field should reflect that.
    for sink in (416, 476):
        r = assemble_race_record(_seed(sink=sink))
        edges = r.mitre_chain["edges"]
        assert edges[0]["kind"] == "mitre-direct"


def test_rejects_non_race_seed():
    assert assemble_race_record({"cve": "x", "cwe_sequence": [20, 190]}) is None
    assert assemble_race_record({"cve": "x", "cwe_sequence": [362, 787]}) is None


def test_batch_dedupes_by_cve_and_sink():
    seeds = [
        _seed(cve="CVE-1", sink=416),
        _seed(cve="CVE-1", sink=416),
        _seed(cve="CVE-1", sink=476),
    ]
    recs = assemble_race_batch(seeds)
    assert len(recs) == 2  # 416 deduped; 476 distinct
    assert {r.chain_string for r in recs} == {"CWE-362->CWE-416", "CWE-362->CWE-476"}
