"""OSV.dev metadata harvester (plan sections 2, 7).

OSV.dev unifies GHSA, distro DBs, and OSS-Fuzz into one JSON schema with git commit
ranges (introduced/fixed) and cross-database aliases. Used as metadata *glue* to resolve
fix commits and version ranges for chain candidates surfaced elsewhere — not as a chain
source itself.

API (https://google.github.io/osv.dev/api/):
  POST /v1/query       single package or commit query
  POST /v1/querybatch  up to 1000 queries per call
  GET  /v1/vulns/{id}  full record by id
Rate limit ~100 req/min; bulk consumers should prefer the daily GCS dumps
(gs://osv-vulnerabilities) over the API. This client covers the API surface; GCS-dump
ingestion is handled separately when mining at scale on ROAR.
"""

from __future__ import annotations

import io
import json
import re
import urllib.parse
import urllib.request
import zipfile
from collections.abc import Iterator
from dataclasses import dataclass, field

import httpx

OSV_API = "https://api.osv.dev"

# Daily GCS dumps: one zip of every record per ecosystem. Preferred over the API for bulk
# mining (the API is rate-limited ~100/min). See survey in FINDINGS: the ecosystems that
# carry real GIT fix commits (not just distro version ranges) are GIT (general C/C++,
# ~98k records) and Linux (~28k kernel CVEs); the distro DBs are advisory-only.
OSV_GCS = "https://storage.googleapis.com/osv-vulnerabilities"

# The 8-CWE ChainForge catalog (source + sink CWEs). A dump record whose CWE label is one of
# these is a chain-candidate END (source or sink); the other end is derived by our dataflow.
_CHAIN_CWES = frozenset({20, 119, 125, 190, 416, 476, 787})
_CWE_RE = re.compile(r"CWE-?(\d+)")


@dataclass
class CommitRange:
    """A GIT-typed affected range from an OSV record."""

    introduced: str | None = None
    fixed: str | None = None
    last_affected: str | None = None
    repo: str | None = None


@dataclass
class OsvRecord:
    """The subset of an OSV record CHAINFORGE consumes."""

    id: str
    aliases: list[str] = field(default_factory=list)
    summary: str | None = None
    commit_ranges: list[CommitRange] = field(default_factory=list)
    cwe_ids: list[str] = field(default_factory=list)
    raw: dict = field(default_factory=dict)


def _extract_git_ranges(record: dict) -> list[CommitRange]:
    ranges: list[CommitRange] = []
    for affected in record.get("affected", []):
        for rng in affected.get("ranges", []):
            if rng.get("type") != "GIT":
                continue
            repo = rng.get("repo")
            cr = CommitRange(repo=repo)
            for event in rng.get("events", []):
                if "introduced" in event:
                    cr.introduced = event["introduced"]
                elif "fixed" in event:
                    cr.fixed = event["fixed"]
                elif "last_affected" in event:
                    cr.last_affected = event["last_affected"]
            ranges.append(cr)
    return ranges


def _extract_cwes(record: dict) -> list[str]:
    # OSV encodes CWEs under database_specific and/or severity; CWE ids most reliably
    # appear in database_specific.cwe_ids (GHSA) — collect whatever is present.
    cwes: list[str] = []
    db = record.get("database_specific", {})
    for key in ("cwe_ids", "cwes"):
        val = db.get(key)
        if isinstance(val, list):
            cwes.extend(str(c) for c in val)
    return cwes


def _cwe_ints(cwe_strs: list[str]) -> set[int]:
    """Parse 'CWE-190'/'190' strings into a set of ints (drops unparseable)."""
    out: set[int] = set()
    for s in cwe_strs:
        m = _CWE_RE.search(str(s))
        if m:
            out.add(int(m.group(1)))
    return out


def parse_record(record: dict) -> OsvRecord:
    """Parse a raw OSV JSON record into the fields CHAINFORGE consumes."""
    return OsvRecord(
        id=record.get("id", ""),
        aliases=list(record.get("aliases", [])),
        summary=record.get("summary"),
        commit_ranges=_extract_git_ranges(record),
        cwe_ids=_extract_cwes(record),
        raw=record,
    )


class OsvClient:
    """Thin OSV.dev API client. Use as a context manager to reuse the connection."""

    def __init__(self, base_url: str = OSV_API, timeout: float = 30.0) -> None:
        self._client = httpx.Client(base_url=base_url, timeout=timeout)

    def __enter__(self) -> OsvClient:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def close(self) -> None:
        self._client.close()

    def get_vuln(self, vuln_id: str) -> OsvRecord:
        """Fetch a full OSV record by id (e.g. 'CVE-2021-3156', 'GHSA-...')."""
        resp = self._client.get(f"/v1/vulns/{vuln_id}")
        resp.raise_for_status()
        return parse_record(resp.json())

    def query_package(self, name: str, ecosystem: str) -> list[OsvRecord]:
        """Query vulnerabilities affecting a package."""
        payload = {"package": {"name": name, "ecosystem": ecosystem}}
        resp = self._client.post("/v1/query", json=payload)
        resp.raise_for_status()
        return [parse_record(v) for v in resp.json().get("vulns", [])]

    def query_commit(self, commit: str) -> list[OsvRecord]:
        """Query vulnerabilities affecting a specific commit hash."""
        resp = self._client.post("/v1/query", json={"commit": commit})
        resp.raise_for_status()
        return [parse_record(v) for v in resp.json().get("vulns", [])]

    def query_batch(self, queries: list[dict]) -> list[list[str]]:
        """Batch query (<=1000). Returns, per query, the list of matching vuln ids.

        The batch endpoint returns ids only; call get_vuln to hydrate the ones you want.
        """
        if len(queries) > 1000:
            raise ValueError("querybatch accepts at most 1000 queries per call")
        resp = self._client.post("/v1/querybatch", json={"queries": queries})
        resp.raise_for_status()
        results = resp.json().get("results", [])
        return [[v["id"] for v in r.get("vulns", [])] for r in results]


@dataclass
class ChainCandidate:
    """A repo+fix-commit vuln surfaced from an OSV bulk dump, ready for our clone-based mine.

    Unlike ARVO/OSS-Fuzz cases (which ship a buildable container + PoC → GOLD), a GIT/Linux
    OSV record carries only (repo, introduced?, fixed commit) + an optional single CWE label.
    That is enough to CLONE the repo, check out the pre-fix revision, extract source, and run
    our Joern dataflow → SILVER. The OSV CWE label seeds ONE end of the chain (source or sink);
    the other end and the ordering come from our dataflow, not from OSV.
    """

    osv_id: str
    repo: str
    fixed_commit: str
    introduced_commit: str | None
    aliases: list[str] = field(default_factory=list)
    cwes: set[int] = field(default_factory=set)
    summary: str | None = None

    @property
    def chain_cwes(self) -> set[int]:
        """The labelled CWEs that are in the ChainForge catalog (may be empty)."""
        return self.cwes & _CHAIN_CWES


def _dump_url(ecosystem: str) -> str:
    return f"{OSV_GCS}/{urllib.parse.quote(ecosystem)}/all.zip"


def download_dump(ecosystem: str, timeout: float = 180.0) -> zipfile.ZipFile:
    """Download an ecosystem's daily all.zip and return it as an in-memory ZipFile.

    ecosystem is the OSV name, e.g. 'GIT', 'Linux', 'OSS-Fuzz'. The GIT dump is ~3MB zipped
    / ~98k records; fits comfortably in memory.
    """
    with urllib.request.urlopen(_dump_url(ecosystem), timeout=timeout) as resp:  # noqa: S310
        data = resp.read()
    return zipfile.ZipFile(io.BytesIO(data))


def iter_chain_candidates(
    ecosystem: str = "GIT",
    *,
    require_chain_cwe: bool = True,
    zf: zipfile.ZipFile | None = None,
) -> Iterator[ChainCandidate]:
    """Yield chain candidates from an OSV bulk dump.

    A candidate needs a GIT range with BOTH a repo and a fixed commit (so we can clone and
    diff). With require_chain_cwe=True (default) we further require at least one catalog CWE
    label, giving high-precision seeds for the thin arms (190/476/416). Set it False to also
    surface unlabelled records — those still mine (our dataflow infers the CWEs) but at lower
    precision. Pass a pre-downloaded zf to avoid re-fetching.
    """
    z = zf or download_dump(ecosystem)
    for name in z.namelist():
        if not name.endswith(".json"):
            continue
        rec = parse_record(json.loads(z.read(name)))
        cwes = _cwe_ints(rec.cwe_ids)
        if require_chain_cwe and not (cwes & _CHAIN_CWES):
            continue
        for cr in rec.commit_ranges:
            if cr.repo and cr.fixed:
                yield ChainCandidate(
                    osv_id=rec.id,
                    repo=cr.repo,
                    fixed_commit=cr.fixed,
                    introduced_commit=cr.introduced,
                    aliases=rec.aliases,
                    cwes=cwes,
                    summary=rec.summary,
                )
                break  # one candidate per record (first fixable range)
