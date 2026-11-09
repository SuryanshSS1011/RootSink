from chainforge.mining.git_assemble import (
    GitEvidence,
    assemble_git_batch,
    assemble_git_record,
)
from chainforge.schema import ConfidenceTier, LinkRole


def _ev(dataflows, osv_id="CVE-2022-1785", labeled=(787,)):
    return GitEvidence.from_json(
        {
            "osv_id": osv_id,
            "repo": "https://github.com/vim/vim",
            "fixed_commit": "e2bd8600b873d2cd1f9d667c28cba8b1dba18839",
            "vuln_commit": "b1040dc11fa15818eda724c35a334f460cf98005",
            "labeled_cwes": list(labeled),
            "repro": None,
            "dataflows": dataflows,
        }
    )


def _df(src, sink, paths, hit=True):
    return {"src_cwe": src, "sink_cwe": sink, "path_count": paths, "has_dataflow": hit}


def test_assemble_silver_record_from_dataflow():
    ev = _ev([_df(20, 787, 803)])
    rec = assemble_git_record(ev)
    assert rec is not None
    assert rec.chain_string == "CWE-20->CWE-787"
    assert rec.label_confidence_tier == ConfidenceTier.SILVER  # no oracle -> never GOLD
    assert rec.ecosystem == "osv-git"
    assert rec.provenance == "osv-git"
    assert rec.aliases == ["CVE-2022-1785"]
    assert rec.project == "vim/vim"
    assert rec.sanitizer_reports == []  # SILVER: no execution witness
    assert rec.chain[0].role == LinkRole.SOURCE and rec.chain[-1].role == LinkRole.SINK
    assert rec.commit_range.fixed.startswith("e2bd8600")


def test_most_specific_source_wins_not_path_count():
    # 20 has far more paths, but 416 (UAF) is the more specific root -> it labels the chain.
    ev = _ev([_df(20, 787, 803), _df(416, 787, 6), _df(476, 787, 3)])
    rec = assemble_git_record(ev)
    assert rec.chain_string == "CWE-416->CWE-787"


def test_no_dataflow_yields_no_record():
    ev = _ev([_df(20, 787, 0, hit=False), _df(416, 787, 0, hit=False)])
    assert assemble_git_record(ev) is None


def test_inadmissible_dataflow_dropped():
    # 787->20 is not an admissible edge; even if Joern emitted it, it must be ignored.
    ev = _ev([_df(787, 20, 5)])
    assert assemble_git_record(ev) is None


def test_stable_id_is_deterministic_and_banded():
    r1 = assemble_git_record(_ev([_df(20, 787, 10)], osv_id="CVE-X"))
    r2 = assemble_git_record(_ev([_df(20, 787, 99)], osv_id="CVE-X"))
    assert r1.id == r2.id  # id depends only on osv_id, not dataflow
    assert r1.id.startswith("CHAINFORGE-91")  # git band, distinct from ARVO/syzbot
    r3 = assemble_git_record(_ev([_df(20, 787, 10)], osv_id="CVE-Y"))
    assert r3.id != r1.id


def test_batch_drops_empties():
    evs = [
        _ev([_df(20, 787, 803)], osv_id="CVE-1"),
        _ev([_df(20, 787, 0, hit=False)], osv_id="CVE-2"),
        _ev([_df(476, 787, 3)], osv_id="CVE-3"),
    ]
    recs = assemble_git_batch(evs)
    assert len(recs) == 2
    assert {r.aliases[0] for r in recs} == {"CVE-1", "CVE-3"}
