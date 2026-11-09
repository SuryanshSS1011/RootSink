from chainforge.cwe import (
    ADMISSIBLE_PAIRS,
    is_admissible_edge,
    parse_cwe_id,
    validate_chain,
)


def test_parse_cwe_id_variants():
    assert parse_cwe_id("CWE-190") == 190
    assert parse_cwe_id("cwe190") == 190
    assert parse_cwe_id("190") == 190
    assert parse_cwe_id(" CWE-787 ") == 787
    assert parse_cwe_id("not-a-cwe") is None


def test_admissible_edges():
    assert is_admissible_edge(20, 190)
    assert is_admissible_edge(190, 787)
    assert not is_admissible_edge(787, 20)  # reversed
    assert not is_admissible_edge(20, 416)  # not in catalog


def test_new_arvo_arms_admissible():
    # ARVO-reproducible arms added for weak/new-stratum growth.
    assert is_admissible_edge(129, 119)  # array-index -> bounds
    assert is_admissible_edge(843, 119)  # type confusion -> bounds
    assert is_admissible_edge(252, 476)  # unchecked return -> null deref
    assert is_admissible_edge(362, 415)  # race -> double free
    assert not is_admissible_edge(415, 787)  # 415 has no outbound chain (terminal-ish)


def test_validate_chain_admissible():
    v = validate_chain([20, 190, 787])
    assert v.admissible
    assert v.edges == ((20, 190), (190, 787))
    assert v.inadmissible_edges == ()
    assert v.out_of_scope == ()


def test_validate_chain_inadmissible_edge():
    v = validate_chain([20, 787, 190])  # 787->190 not admissible
    assert not v.admissible
    assert (787, 190) in v.inadmissible_edges


def test_validate_chain_out_of_scope():
    v = validate_chain([20, 999])  # 999 not in the 8-CWE catalog
    assert not v.admissible
    assert 999 in v.out_of_scope


def test_validate_chain_too_short():
    v = validate_chain([20])
    assert not v.admissible  # a single CWE is not a chain


def test_all_admissible_pairs_are_edges():
    for src, dst in ADMISSIBLE_PAIRS:
        assert is_admissible_edge(src, dst)
