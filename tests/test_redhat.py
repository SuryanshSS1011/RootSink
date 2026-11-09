from chainforge.mining.redhat import (
    parse_chain_notation,
    seeds_from_notation,
)


def test_simple_chain():
    p = parse_chain_notation("CWE-20->CWE-190")
    assert p.candidates == [[20, 190]]
    assert p.admissible == [[20, 190]]


def test_alternation_group_expands():
    p = parse_chain_notation("CWE-20->(CWE-125|CWE-787)")
    assert p.candidates == [[20, 125], [20, 787]]
    # both 20->125 and 20->787 are admissible
    assert p.admissible == [[20, 125], [20, 787]]


def test_inadmissible_link_dropped_but_kept_as_candidate():
    # CWE-805 is not in the 8-CWE catalog, so nothing is admissible,
    # but the candidate expansion is still recorded.
    p = parse_chain_notation("CWE-20->CWE-805->(CWE-125|CWE-787)")
    assert [20, 805, 125] in p.candidates
    assert [20, 805, 787] in p.candidates
    assert p.admissible == []


def test_bare_alternation_no_chain():
    p = parse_chain_notation("CWE-125|CWE-787")
    # single position -> sequences of length 1 -> no admissible chain
    assert p.candidates == [[125], [787]]
    assert p.admissible == []


def test_unparsed_token_recorded():
    p = parse_chain_notation("CWE-20->garbage")
    assert "garbage" in p.unparsed
    assert p.candidates == []


def test_seeds_from_notation():
    seeds = seeds_from_notation("CVE-2023-0001", "CWE-190->CWE-787")
    assert len(seeds) == 1
    assert seeds[0].cve == "CVE-2023-0001"
    assert seeds[0].chain_string == "CWE-190->CWE-787"
    assert seeds[0].cwe_sequence == [190, 787]


def test_seeds_multi_from_alternation():
    seeds = seeds_from_notation("CVE-2023-0002", "CWE-20->(CWE-125|CWE-787)")
    chains = {s.chain_string for s in seeds}
    assert chains == {"CWE-20->CWE-125", "CWE-20->CWE-787"}


def test_whitespace_tolerant():
    p = parse_chain_notation(" CWE-190 -> CWE-119 ")
    assert p.admissible == [[190, 119]]
