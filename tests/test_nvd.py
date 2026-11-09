from chainforge.mining.nvd import (
    NvdClient,
    catalog_cwes_of,
    fix_refs_of,
    seeds_from_cwe_set,
)


def _item(cve, cwe_ids, refs=None):
    item = {
        "cve": {
            "id": cve,
            "weaknesses": [{"description": [{"value": f"CWE-{c}"} for c in cwe_ids]}],
        }
    }
    if refs is not None:
        item["cve"]["references"] = [{"url": u} for u in refs]
    return item


def test_catalog_cwes_filters_to_catalog():
    item = _item("CVE-2016-3945", [190, 787, 999])  # 999 not in catalog
    assert catalog_cwes_of(item) == {190, 787}


def test_seeds_from_cwe_set_admissible_ordering():
    seeds = seeds_from_cwe_set("CVE-2016-3945", {190, 787})
    assert len(seeds) == 1
    s = seeds[0]
    assert s.cwe_sequence == [190, 787]  # admissible direction, not 787->190
    assert s.chain_string == "CWE-190->CWE-787"


def test_seeds_from_cwe_set_no_admissible_pair():
    # 125 and 787 are both sinks; no admissible edge between them.
    assert seeds_from_cwe_set("CVE-x", {125, 787}) == []


def test_seeds_from_cwe_set_single_cwe():
    assert seeds_from_cwe_set("CVE-x", {190}) == []


def test_seeds_from_three_cwes_multiple_pairs():
    # 20,190,787: admissible edges 20->190, 20->787, 190->787
    seeds = seeds_from_cwe_set("CVE-2016-6207", {20, 190, 787})
    chains = {s.chain_string for s in seeds}
    assert chains == {"CWE-20->CWE-190", "CWE-20->CWE-787", "CWE-190->CWE-787"}


def test_race_arm_362_co_occurrence():
    # CWE-362 co-listed with a UAF/null-deref sink is the MITRE-endorsed race arm.
    assert catalog_cwes_of(_item("CVE-x", [362, 416])) == {362, 416}
    for sink in (416, 476):
        seeds = seeds_from_cwe_set("CVE-2016-8655", {362, sink})
        assert [s.chain_string for s in seeds] == [f"CWE-362->CWE-{sink}"]
        assert seeds[0].cwe_sequence == [362, sink]


def test_fix_refs_extraction():
    item = _item(
        "CVE-2016-8655",
        [362, 416],
        refs=[
            "http://git.kernel.org/cgit/linux/kernel/git/torvalds/linux.git/commit/?id=84ac726",
            "http://www.securityfocus.com/bid/94655",  # advisory, not a fix commit
            "https://github.com/torvalds/linux/commit/84ac726",
        ],
    )
    refs = fix_refs_of(item)
    assert len(refs) == 2  # the two commit URLs, not the securityfocus advisory
    assert all("commit" in r for r in refs)


def test_seeds_carry_fix_refs():
    seeds = seeds_from_cwe_set(
        "CVE-2016-8655", {362, 416}, fix_refs=["https://github.com/torvalds/linux/commit/abc"]
    )
    assert seeds[0].fix_refs == ["https://github.com/torvalds/linux/commit/abc"]


def test_seeds_for_source_cwe_paginates_and_dedupes(httpx_mock):
    page = {
        "vulnerabilities": [
            _item("CVE-2016-3945", [190, 787]),
            _item("CVE-2015-8870", [20, 190]),
            _item("CVE-0000-0000", [190]),  # single CWE -> no seed
        ]
    }
    empty = {"vulnerabilities": []}
    httpx_mock.add_response(json=page)  # page 0
    httpx_mock.add_response(json=empty)  # page 1 -> stop

    with NvdClient() as client:
        seeds = client.seeds_for_source_cwe(190, max_pages=2, per_page=200)

    chains = {(s.cve, s.chain_string) for s in seeds}
    assert ("CVE-2016-3945", "CWE-190->CWE-787") in chains
    assert ("CVE-2015-8870", "CWE-20->CWE-190") in chains
    assert all(s.cve != "CVE-0000-0000" for s in seeds)
