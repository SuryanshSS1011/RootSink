import io
import json
import zipfile

import pytest

from chainforge.mining.osv import (
    ChainCandidate,
    OsvClient,
    iter_chain_candidates,
    parse_record,
)

SAMPLE_RECORD = {
    "id": "CVE-2021-3156",
    "aliases": ["GHSA-abcd-1234-wxyz"],
    "summary": "Heap buffer overflow in sudo",
    "affected": [
        {
            "ranges": [
                {
                    "type": "GIT",
                    "repo": "https://github.com/sudo-project/sudo",
                    "events": [
                        {"introduced": "aaaa1111"},
                        {"fixed": "bbbb2222"},
                    ],
                },
                {"type": "SEMVER", "events": [{"introduced": "1.8.2"}]},
            ]
        }
    ],
    "database_specific": {"cwe_ids": ["CWE-787"]},
}


def test_parse_record_extracts_git_range_and_cwe():
    rec = parse_record(SAMPLE_RECORD)
    assert rec.id == "CVE-2021-3156"
    assert rec.aliases == ["GHSA-abcd-1234-wxyz"]
    assert rec.cwe_ids == ["CWE-787"]
    assert len(rec.commit_ranges) == 1  # only the GIT range, not SEMVER
    cr = rec.commit_ranges[0]
    assert cr.introduced == "aaaa1111"
    assert cr.fixed == "bbbb2222"
    assert cr.repo == "https://github.com/sudo-project/sudo"


def test_get_vuln(httpx_mock):
    httpx_mock.add_response(
        url="https://api.osv.dev/v1/vulns/CVE-2021-3156",
        json=SAMPLE_RECORD,
    )
    with OsvClient() as client:
        rec = client.get_vuln("CVE-2021-3156")
    assert rec.commit_ranges[0].fixed == "bbbb2222"


def test_query_package(httpx_mock):
    httpx_mock.add_response(
        url="https://api.osv.dev/v1/query",
        json={"vulns": [SAMPLE_RECORD]},
    )
    with OsvClient() as client:
        recs = client.query_package("sudo", "Debian")
    assert len(recs) == 1
    assert recs[0].id == "CVE-2021-3156"


def test_query_batch_returns_ids(httpx_mock):
    httpx_mock.add_response(
        url="https://api.osv.dev/v1/querybatch",
        json={"results": [{"vulns": [{"id": "CVE-1"}, {"id": "CVE-2"}]}, {}]},
    )
    with OsvClient() as client:
        out = client.query_batch(
            [{"package": {"name": "a", "ecosystem": "Debian"}}, {"commit": "deadbeef"}]
        )
    assert out == [["CVE-1", "CVE-2"], []]


def test_query_batch_size_limit():
    with OsvClient() as client, pytest.raises(ValueError, match="at most 1000"):
        client.query_batch([{"commit": "x"}] * 1001)


def _make_dump(records: list[dict]) -> zipfile.ZipFile:
    """Build an in-memory OSV all.zip from raw records (offline test fixture)."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        for i, r in enumerate(records):
            z.writestr(f"{r.get('id', i)}.json", json.dumps(r))
    buf.seek(0)
    return zipfile.ZipFile(buf)


_R_190 = {
    "id": "CVE-2020-1111",
    "summary": "integer overflow",
    "affected": [
        {
            "ranges": [
                {
                    "type": "GIT",
                    "repo": "https://github.com/x/y",
                    "events": [{"introduced": "aaa"}, {"fixed": "bbb"}],
                }
            ]
        }
    ],
    "database_specific": {"cwe_ids": ["CWE-190"]},
}
_R_NO_FIX = {  # has repo but no fixed commit -> not minable
    "id": "CVE-2020-2222",
    "affected": [
        {
            "ranges": [
                {"type": "GIT", "repo": "https://github.com/a/b", "events": [{"introduced": "c"}]}
            ]
        }
    ],
    "database_specific": {"cwe_ids": ["CWE-125"]},
}
_R_OFFCATALOG = {  # fixable but CWE not in catalog (XSS)
    "id": "CVE-2020-3333",
    "affected": [
        {
            "ranges": [
                {
                    "type": "GIT",
                    "repo": "https://github.com/c/d",
                    "events": [{"introduced": "e"}, {"fixed": "f"}],
                }
            ]
        }
    ],
    "database_specific": {"cwe_ids": ["CWE-79"]},
}


def test_iter_chain_candidates_filters_to_fixable_catalog_cwes():
    z = _make_dump([_R_190, _R_NO_FIX, _R_OFFCATALOG])
    cands = list(iter_chain_candidates(zf=z))
    assert [c.osv_id for c in cands] == ["CVE-2020-1111"]  # only the fixable catalog-CWE record
    c = cands[0]
    assert isinstance(c, ChainCandidate)
    assert c.repo == "https://github.com/x/y"
    assert c.fixed_commit == "bbb"
    assert c.introduced_commit == "aaa"
    assert c.chain_cwes == {190}


def test_iter_chain_candidates_can_include_offcatalog_when_not_required():
    z = _make_dump([_R_190, _R_OFFCATALOG, _R_NO_FIX])
    cands = list(iter_chain_candidates(require_chain_cwe=False, zf=z))
    # both fixable records surface; the no-fix one is still excluded (can't clone+diff)
    assert {c.osv_id for c in cands} == {"CVE-2020-1111", "CVE-2020-3333"}
    offcat = next(c for c in cands if c.osv_id == "CVE-2020-3333")
    assert offcat.chain_cwes == set()  # CWE-79 is not a catalog CWE
