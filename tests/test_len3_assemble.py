from chainforge.mining.len3_assemble import assemble_len3_batch, assemble_len3_record
from chainforge.schema import ConfidenceTier, LinkRole

CAND = {
    "osv_id": "CVE-2022-23521",
    "repo": "https://github.com/git/git",
    "fixed_commit": "abc123def456",
    "chain": "CWE-20->CWE-190->CWE-787",
    "sink_cwe": 787,
    "input_patterns": ["if (len > MAX)"],
    "overflow_patterns": ["st_mult overflow"],
}


def test_assemble_len3_record():
    r = assemble_len3_record(CAND)
    assert r is not None
    assert r.chain_string == "CWE-20->CWE-190->CWE-787"
    assert len(r.chain) == 3
    assert [lk.cwe_id for lk in r.chain] == [20, 190, 787]
    assert r.chain[0].role == LinkRole.SOURCE
    assert r.chain[1].role == LinkRole.INTERMEDIATE
    assert r.chain[2].role == LinkRole.SINK
    assert r.label_confidence_tier == ConfidenceTier.SILVER
    assert r.ecosystem == "osv-git-len3"
    assert r.aliases == ["CVE-2022-23521"]
    assert r.id.startswith("CHAINFORGE-93")
    # per-link patch evidence recorded
    assert "input guard" in (r.chain[0].evidence.patch_hunk_ref or "")
    assert "overflow guard" in (r.chain[1].evidence.patch_hunk_ref or "")


def test_assemble_len3_rejects_bad_sink():
    bad = dict(CAND, sink_cwe=416)
    assert assemble_len3_record(bad) is None


def test_batch_dedups_by_id():
    recs = assemble_len3_batch([CAND, dict(CAND), {**CAND, "osv_id": "CVE-2022-9999"}])
    assert len(recs) == 2
