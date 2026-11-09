import pytest

from chainforge.silver import (
    UnsupportedPairError,
    build_chain_query,
    build_lifecycle_query,
    build_multi_query,
    build_query,
    parse_chain_result,
    parse_lifecycle_result,
    parse_multi_result,
    parse_result,
    supported_pairs,
)


def test_build_query_admissible_pair():
    q = build_query(190, 787, source_dir="jsample")
    assert q.src_cwe == 190
    assert q.sink_cwe == 787
    assert 'importCode.c(inputPath="jsample")' in q.script  # C frontend forced
    assert "reachableBy" in q.script
    assert "CF_REACHABLE=" in q.script


def test_build_query_inadmissible_pair():
    with pytest.raises(UnsupportedPairError, match="not an admissible edge"):
        build_query(787, 20)  # reversed / not in catalog


def test_build_query_supported_pair_ok():
    # 190->787 is a reachability pair with both a source and sink pattern.
    q = build_query(190, 787)
    assert q.src_cwe == 190 and q.sink_cwe == 787


def test_build_query_rejects_lifecycle_source():
    # 416 is lifecycle-only (no reachability source pattern) -> build_query (reachability) fails.
    with pytest.raises(UnsupportedPairError, match="no source pattern for CWE-416"):
        build_query(416, 787)


def test_build_query_missing_sink_pattern():
    # CWE-190 is a source-only weakness (no sink pattern); using it as a sink is unsupported.
    with pytest.raises(UnsupportedPairError, match="no sink pattern for CWE-190"):
        build_query(20, 190)


def test_parse_result_positive():
    out = "some log\nCF_REACHABLE=3\nmore log\n"
    r = parse_result(190, 787, out)
    assert r.path_count == 3
    assert r.has_dataflow is True


def test_parse_result_zero():
    r = parse_result(190, 787, "CF_REACHABLE=0\n")
    assert r.path_count == 0
    assert r.has_dataflow is False


def test_parse_result_missing_marker():
    with pytest.raises(ValueError, match="no CF_REACHABLE"):
        parse_result(190, 787, "joern crashed, no output\n")


def test_supported_pairs_are_admissible():
    from chainforge.cwe import is_admissible_edge

    pairs = supported_pairs()
    assert pairs  # non-empty
    for s, d in pairs:
        assert is_admissible_edge(s, d)
    # reachability pairs (taint-flow sources 20/190); lifecycle pairs (416/476) are separate.
    assert (190, 787) in pairs
    assert (20, 125) in pairs
    assert (416, 787) not in pairs  # lifecycle, not a reachability pair


def test_build_multi_query_one_cpg_many_sources():
    q = build_multi_query([20, 190, 416, 476], 787, source_dir="jsample")
    # Exactly one importCode (CPG built once) and one sink.
    assert q.script.count("importCode.c(") == 1
    assert q.script.count("val sink =") == 1
    # 20 and 190 are reachability sources; 416 and 476 are lifecycle sources.
    assert "CF_REACHABLE_20=" in q.script
    assert "CF_REACHABLE_190=" in q.script
    assert "CF_LIFECYCLE_416=" in q.script
    assert "CF_LIFECYCLE_476=" in q.script


def test_build_multi_query_skips_inadmissible_source():
    # 125 is not an admissible source for 787; it should be dropped, 190 kept.
    q = build_multi_query([125, 190], 787)
    assert "CF_REACHABLE_190=" in q.script
    assert "CF_REACHABLE_125=" not in q.script


def test_build_multi_query_no_usable_source():
    with pytest.raises(UnsupportedPairError):
        build_multi_query([125], 787)  # only an inadmissible source given


def test_parse_multi_result():
    out = "log\nCF_REACHABLE_190=114\nnoise\nCF_REACHABLE_20=3\nCF_REACHABLE_416=0\n"
    results = {r.src_cwe: r for r in parse_multi_result(787, out)}
    assert results[190].path_count == 114 and results[190].has_dataflow
    assert results[20].path_count == 3
    assert results[416].path_count == 0 and not results[416].has_dataflow


def test_parse_multi_result_empty():
    assert parse_multi_result(787, "joern crashed") == []


def test_build_chain_query_flagship():
    q = build_chain_query(20, 190, 787, source_dir="jsample")
    assert q.script.count("importCode.c(") == 1
    # id-set based, tractable (no per-node reachability): h1/h2/h3 by node-id intersection
    assert "val midIds =" in q.script and "val h1ids =" in q.script and "val h2ids =" in q.script
    assert "CF_CHAIN_H1=" in q.script and "CF_CHAIN_H2=" in q.script and "CF_CHAIN_H3=" in q.script
    # H1 = mid reached-by-src; H2 = mid on sink flows; H3 = their id-set intersection.
    assert "reachableBy" in q.script and "reachableByFlows" in q.script
    assert "intersect" in q.script
    assert ".id.l.toSet" in q.script  # id-sets, not per-node reachability


def test_build_chain_query_rejects_inadmissible():
    with pytest.raises(UnsupportedPairError):
        build_chain_query(787, 190, 20)  # not an admissible chain


def test_build_chain_query_only_190_is_intermediate():
    # The only admissible 3-CWE chain with a supported intermediate is 20->190->787.
    # Any other middle CWE fails admissibility first (there is no X->416->Y or X->476->Y
    # chain in the catalog), so build_chain_query rejects it.
    with pytest.raises(UnsupportedPairError):
        build_chain_query(20, 416, 787)
    with pytest.raises(UnsupportedPairError):
        build_chain_query(20, 476, 787)


def test_parse_chain_result_strict_shared_node():
    # H3>0: the SAME arithmetic node is reached-by-src AND reaches-the-sink -> a real chain.
    out = "log\nCF_CHAIN_H1=5\nCF_CHAIN_H2=12\nCF_CHAIN_H3=3\n"
    r = parse_chain_result(20, 190, 787, out)
    assert r.hop1_paths == 5 and r.hop2_paths == 12 and r.shared_mid == 3
    assert r.has_chain


def test_parse_chain_result_both_hops_but_no_shared_node():
    # Both hops fire but on DIFFERENT arithmetic nodes (H3=0) -> NOT a genuine 3-link chain.
    r = parse_chain_result(20, 190, 787, "CF_CHAIN_H1=5\nCF_CHAIN_H2=12\nCF_CHAIN_H3=0\n")
    assert r.hop1_paths == 5 and r.hop2_paths == 12
    assert not r.has_chain  # strict: needs a shared intermediate node


def test_parse_chain_result_broken_chain():
    # source reaches arithmetic, but arithmetic never reaches the sink -> not a chain.
    r = parse_chain_result(20, 190, 787, "CF_CHAIN_H1=5\nCF_CHAIN_H2=0\nCF_CHAIN_H3=0\n")
    assert not r.has_chain


def test_parse_chain_result_missing_marker():
    with pytest.raises(ValueError, match="hop markers"):
        parse_chain_result(20, 190, 787, "CF_CHAIN_H1=5\n")  # H2 missing


def test_build_lifecycle_query_416():
    q = build_lifecycle_query(416, 787, source_dir="jsample")
    assert q.script.count("importCode.c(") == 1
    assert "free" in q.script and "isIdentifier" in q.script
    assert "intersect" in q.script
    assert "CF_LIFECYCLE_416=" in q.script


def test_build_lifecycle_query_476():
    q = build_lifecycle_query(476, 787)
    assert "malloc" in q.script
    assert "CF_LIFECYCLE_476=" in q.script


def test_build_lifecycle_query_rejects_non_lifecycle():
    # CWE-20 is not a lifecycle CWE, even though 20->787 is admissible.
    with pytest.raises(UnsupportedPairError, match="lifecycle"):
        build_lifecycle_query(20, 787)


def test_build_lifecycle_query_rejects_inadmissible():
    with pytest.raises(UnsupportedPairError, match="admissible"):
        build_lifecycle_query(416, 190)  # 416->190 not in catalog


def test_parse_lifecycle_result_positive():
    r = parse_lifecycle_result(416, 787, "log\nCF_LIFECYCLE_416=4\n")
    assert r.shared_count == 4
    assert r.has_evidence


def test_parse_lifecycle_result_zero():
    r = parse_lifecycle_result(416, 787, "CF_LIFECYCLE_416=0\n")
    assert r.shared_count == 0
    assert not r.has_evidence


def test_parse_lifecycle_result_missing_marker():
    with pytest.raises(ValueError, match="CF_LIFECYCLE_416"):
        parse_lifecycle_result(416, 787, "nothing here")


def test_multi_query_includes_lifecycle_sources():
    # sink 787 admits reachability sources 20/190 AND lifecycle sources 416/476.
    q = build_multi_query([20, 190, 416, 476], 787)
    assert q.script.count("importCode.c(") == 1  # single CPG
    assert "CF_REACHABLE_20=" in q.script  # reachability source
    assert "CF_LIFECYCLE_416=" in q.script  # lifecycle source (UAF)
    assert "CF_LIFECYCLE_476=" in q.script  # lifecycle source (null deref)
    assert "intersect" in q.script


def test_parse_multi_result_mixes_reachability_and_lifecycle():
    out = "CF_REACHABLE_20=97\nCF_LIFECYCLE_416=12\nCF_LIFECYCLE_476=0\n"
    results = {r.src_cwe: r for r in parse_multi_result(787, out)}
    assert results[20].path_count == 97 and results[20].has_dataflow
    assert results[416].path_count == 12 and results[416].has_dataflow  # lifecycle -> positive
    assert results[476].path_count == 0 and not results[476].has_dataflow


def test_lifecycle_476_excludes_freed():
    # 476 null-deref query must SUBTRACT freed identifiers (a freed ptr is 416, not 476).
    q = build_lifecycle_query(476, 787)
    assert "freed" in q.script and ".diff(freed)" in q.script
    assert "CF_LIFECYCLE_476=" in q.script


def test_lifecycle_416_does_not_subtract():
    # 416 UAF query keeps all freed identifiers (no diff).
    q = build_lifecycle_query(416, 787)
    assert ".diff(" not in q.script
    assert "CF_LIFECYCLE_416=" in q.script


def test_multi_query_476_disjoint_from_416():
    # In the combined query, the 476 node set is freed-subtracted so 416/476 are disjoint.
    q = build_multi_query([416, 476], 787)
    assert "lc_freed" in q.script
    assert "lc_476" in q.script and ".diff(lc_freed)" in q.script
