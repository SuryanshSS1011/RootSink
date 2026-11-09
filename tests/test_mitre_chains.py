from chainforge.mitre_chains import (
    CANPRECEDE,
    CWE_CATALOG_VERSION,
    classify_chain,
    classify_edge,
)


def test_catalog_version_pinned():
    assert CWE_CATALOG_VERSION == "4.20"


def test_direct_precede_edges():
    # Literal CanPrecede edges from the catalog.
    for src, dst in [(190, 119), (362, 416), (362, 476), (822, 787), (252, 476), (754, 416)]:
        e = classify_edge(src, dst)
        assert e.kind == "mitre-direct", (src, dst, e.kind)
        assert e.mitre_recognized
        assert (src, dst) in CANPRECEDE


def test_transitive_edges_through_hierarchy():
    # src CanPrecede an ancestor of dst -> transitive MITRE chain.
    for src, dst in [(190, 787), (190, 125), (20, 787), (20, 125)]:
        e = classify_edge(src, dst)
        assert e.kind == "mitre-transitive", (src, dst, e.kind)
        assert e.mitre_recognized


def test_hierarchy_edge_not_a_precede_chain():
    # CWE-190 is-a CWE-20: a specialization, not a causal precede-chain.
    e = classify_edge(20, 190)
    assert e.kind == "mitre-hierarchy"
    assert not e.mitre_recognized


def test_catalog_only_modeling_edges():
    # CHAINFORGE modeling edges not endorsed by MITRE.
    # (416 -> 125/787 is mitre-inherited since PR-17: CWE-416 is-a CWE-825, CanPrecede 125/787.)
    for src, dst in [(476, 787), (362, 415)]:
        e = classify_edge(src, dst)
        assert e.kind == "catalog-only", (src, dst, e.kind)
        assert not e.mitre_recognized


def test_classify_flagship_chain():
    cp = classify_chain([20, 190, 787])
    kinds = [e.kind for e in cp.edges]
    assert kinds == ["mitre-hierarchy", "mitre-transitive"]
    # flagship has no catalog-only edges (fully MITRE-grounded, via two relation types)
    assert not cp.any_catalog_only
    # but not all-recognized, because 20->190 is a hierarchy edge, not a precede-chain
    assert not cp.all_mitre_recognized


def test_classify_new_race_arm_all_recognized():
    cp = classify_chain([362, 416, 787])
    # 362->416 is direct; 416->787 is inherited (CWE-416 is-a CWE-825, which CanPrecede
    # CWE-787 in CWE 4.20), so the chain has no catalog-only edge.
    assert cp.edges[0].kind == "mitre-direct"
    assert cp.edges[1].kind == "mitre-inherited"
    assert not cp.any_catalog_only


def test_fully_recognized_chain():
    # 129 CanPrecede 119; 190 CanPrecede 119 (transitive to 787). Build an all-recognized 2-edge.
    cp = classify_chain([190, 119])
    assert cp.all_mitre_recognized
    assert not cp.any_catalog_only
