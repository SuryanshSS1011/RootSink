"""NVD multi-CWE seed harvester (plan sections 2, 3).

The public Red Hat security-data API flattens each CVE to a single CWE — the machine-
readable `->` chain notation the plan references lives in Red Hat's internal cwe-toolkit,
not this API (verified: 0 of 14k+ 2013-2019 records carried `->`/`|`). So the practical
public seed for candidate chains is NVD *multi-CWE co-occurrence*: when a CVE lists two or
more of the 8 catalog CWEs, and some ordering of them is an admissible edge, that ordered
pair is a BRONZE chain seed (plan section 3: BRONZE = NVD multi-CWE with admissible
ordering, no dataflow/execution).

NVD does not encode CWE *order*, so ordering is imposed by the admissible-pair catalog
(which encodes causal direction). A CVE whose catalog-CWEs admit exactly one ordering
yields one seed; ambiguous multi-CWE sets yield every admissible ordered pair among them.

Uses the NVD REST API 2.0 (https://services.nvd.nist.gov/rest/json/cves/2.0). Without an
API key NVD allows ~5 requests / 30s; pass one via `api_key` to raise the limit.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from itertools import permutations

import httpx

from ..cwe import CWE_NAMES, is_admissible_edge

NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"


@dataclass
class NvdSeed:
    """A candidate chain seed derived from one CVE's co-occurring CWEs."""

    cve: str
    cwe_sequence: list[int]
    chain_string: str
    all_catalog_cwes: list[int] = field(default_factory=list)
    fix_refs: list[str] = field(default_factory=list)


# Reference URLs that point at a fix commit / patch (used to make an NVD seed minable and
# tierable via patch co-signal). Ordered by how directly they identify a single commit.
_FIX_REF_HINTS = ("/commit/", "a=commit", "?id=", "/patch", "patchwork", "github.com")


def fix_refs_of(cve_item: dict) -> list[str]:
    """Extract reference URLs from an NVD CVE item that look like a fix commit/patch."""
    refs: list[str] = []
    for ref in cve_item.get("cve", {}).get("references", []):
        url = ref.get("url", "")
        if any(h in url for h in _FIX_REF_HINTS):
            refs.append(url)
    return refs


def catalog_cwes_of(cve_item: dict) -> set[int]:
    """Extract the set of in-catalog CWE ids listed on an NVD CVE item."""
    cwes: set[int] = set()
    for weakness in cve_item.get("cve", {}).get("weaknesses", []):
        for desc in weakness.get("description", []):
            val = desc.get("value", "")
            if val.startswith("CWE-") and val[4:].isdigit():
                cid = int(val[4:])
                if cid in CWE_NAMES:
                    cwes.add(cid)
    return cwes


def seeds_from_cwe_set(
    cve: str, cwes: set[int], fix_refs: list[str] | None = None
) -> list[NvdSeed]:
    """Turn a CVE's co-occurring catalog CWEs into admissible ordered chain seeds.

    Every admissible ordered pair among the CWEs becomes a 2-link seed. A set with fewer
    than two catalog CWEs, or no admissible ordering, yields nothing.
    """
    ordered = sorted(cwes)
    seeds: list[NvdSeed] = []
    for a, b in permutations(ordered, 2):
        if is_admissible_edge(a, b):
            seeds.append(
                NvdSeed(
                    cve=cve,
                    cwe_sequence=[a, b],
                    chain_string=f"CWE-{a}->CWE-{b}",
                    all_catalog_cwes=ordered,
                    fix_refs=list(fix_refs or []),
                )
            )
    return seeds


class NvdClient:
    """NVD REST API 2.0 client. Use as a context manager to reuse the connection."""

    def __init__(
        self, base_url: str = NVD_API, api_key: str | None = None, timeout: float = 45.0
    ) -> None:
        headers = {"User-Agent": "chainforge-miner/0.0 (research)"}
        if api_key:
            headers["apiKey"] = api_key
        self._client = httpx.Client(base_url=base_url, headers=headers, timeout=timeout)

    def __enter__(self) -> NvdClient:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def close(self) -> None:
        self._client.close()

    def page_by_cwe(self, cwe_id: int, start_index: int = 0, per_page: int = 200) -> dict:
        """Fetch one page of CVEs classified under CWE-<cwe_id>."""
        params = {
            "cweId": f"CWE-{cwe_id}",
            "resultsPerPage": per_page,
            "startIndex": start_index,
        }
        resp = self._client.get("", params=params)
        resp.raise_for_status()
        return resp.json()

    def seeds_for_source_cwe(
        self, source_cwe: int, max_pages: int = 1, per_page: int = 200
    ) -> list[NvdSeed]:
        """Harvest chain seeds from CVEs classified under a source CWE.

        Pages through NVD results for `source_cwe`, and for each CVE that also lists a
        second admissible catalog CWE, emits the ordered seed(s). Deduplicated by
        (cve, chain_string).
        """
        seen: set[tuple[str, str]] = set()
        out: list[NvdSeed] = []
        for page in range(max_pages):
            data = self.page_by_cwe(source_cwe, start_index=page * per_page, per_page=per_page)
            items = data.get("vulnerabilities", [])
            if not items:
                break
            for item in items:
                cve = item.get("cve", {}).get("id", "")
                cwes = catalog_cwes_of(item)
                if len(cwes) < 2:
                    continue
                refs = fix_refs_of(item)
                for seed in seeds_from_cwe_set(cve, cwes, fix_refs=refs):
                    key = (seed.cve, seed.chain_string)
                    if key not in seen:
                        seen.add(key)
                        out.append(seed)
        return out
