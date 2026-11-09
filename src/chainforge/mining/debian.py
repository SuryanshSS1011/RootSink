"""Debian Security Tracker harvester (plan sections 2, 7).

The Debian Security Tracker is a git repo whose ``data/CVE/list`` maps each CVE to the
Debian source package(s), the fixed source version per release, and (in NOTE lines) the
upstream fix commit URLs. BinPool mined it for 603 CVEs / 162 packages. Used here for
version + fix-commit metadata glue, not as a chain source.

File grammar (tab-indented under a column-0 CVE header)::

    CVE-2026-53994 (ProFTPD mod_sftp contains a heap-based buffer overflow ...)
        - proftpd-dfsg 1.3.9b~dfsg-1
        NOTE: Fixed by: https://github.com/proftpd/proftpd/commit/8685930... (v1.3.9b)
    CVE-2026-0001 (...)
        - linux 7.0.12-1
        [trixie] - linux 6.12.94-1
        [bookworm] - linux <not-affected> (Vulnerable code not present)

A ``- <pkg> <version>`` line means "fixed in that source version" (unstable when no
``[release]`` prefix). ``<unfixed>`` / ``<not-affected>`` are status placeholders rather
than versions. Non-package annotations (``NOT-FOR-US``, ``TODO``, ``RESERVED``,
``REJECTED``, ``NOTE`` except "Fixed by") are ignored for version data but "Fixed by"
NOTE lines are harvested for upstream commit hashes.

Parsing streams line-by-line so the ~40 MB file need not be held in memory. On ROAR the
list is cloned from git; ``parse_cve_list`` accepts any iterable of lines.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Iterator
from dataclasses import dataclass, field

_CVE_HEADER_RE = re.compile(r"^(CVE-\d{4}-\d+)\s*(?:\((.*)\))?\s*$")
# tab-indented package line, optional [release] prefix, '- <pkg> <version-or-status>'
_PKG_RE = re.compile(r"^\t(?:\[(?P<release>[a-z0-9-]+)\]\s+)?-\s+(?P<pkg>\S+)\s+(?P<version>\S+)")
# 'NOTE: Fixed by: <url> (vX)' — harvest the trailing commit hash from git URLs.
_FIXED_BY_RE = re.compile(r"NOTE:\s*Fixed by:\s*(?P<url>\S+)")
_COMMIT_IN_URL_RE = re.compile(r"/commit/([0-9a-f]{7,40})")

_STATUS_PLACEHOLDERS = frozenset({"<unfixed>", "<not-affected>", "<removed>", "<undetermined>"})


@dataclass
class PackageFix:
    """One package/release fix status for a CVE."""

    package: str
    release: str | None  # None => unstable/sid
    version: str  # a Debian source version, or a <status> placeholder
    fixed: bool  # True if `version` is a concrete fixed version

    @property
    def is_status_placeholder(self) -> bool:
        return self.version in _STATUS_PLACEHOLDERS


@dataclass
class DebianCveEntry:
    """A parsed CVE entry from the Debian tracker."""

    cve: str
    description: str = ""
    packages: list[PackageFix] = field(default_factory=list)
    fix_commits: list[str] = field(default_factory=list)  # upstream commit hashes

    @property
    def source_packages(self) -> set[str]:
        return {p.package for p in self.packages}


def _parse_package_line(line: str) -> PackageFix | None:
    m = _PKG_RE.match(line)
    if not m:
        return None
    version = m.group("version")
    return PackageFix(
        package=m.group("pkg"),
        release=m.group("release"),
        version=version,
        fixed=version not in _STATUS_PLACEHOLDERS,
    )


def _parse_fixed_by(line: str) -> str | None:
    m = _FIXED_BY_RE.search(line)
    if not m:
        return None
    cm = _COMMIT_IN_URL_RE.search(m.group("url"))
    return cm.group(1) if cm else None


def parse_cve_list(lines: Iterable[str]) -> Iterator[DebianCveEntry]:
    """Stream-parse Debian ``data/CVE/list`` lines into CVE entries.

    Yields one :class:`DebianCveEntry` per CVE header encountered.
    """
    current: DebianCveEntry | None = None
    for raw in lines:
        line = raw.rstrip("\n")
        header = _CVE_HEADER_RE.match(line)
        if header:
            if current is not None:
                yield current
            current = DebianCveEntry(
                cve=header.group(1), description=(header.group(2) or "").strip()
            )
            continue
        if current is None:
            continue  # preamble / stray lines before first CVE
        pkg = _parse_package_line(line)
        if pkg is not None:
            current.packages.append(pkg)
            continue
        commit = _parse_fixed_by(line)
        if commit is not None and commit not in current.fix_commits:
            current.fix_commits.append(commit)
    if current is not None:
        yield current
