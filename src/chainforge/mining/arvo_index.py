"""ARVO consolidated-index reader (plan sections 2, 4).

The ARVO-Meta release ships ``arvo.db`` — a single SQLite table (`arvo`, 6138 rows) with
one row per reproducible OSS-Fuzz case. This is the efficient join surface for the pilot:
resolve a fix-commit hash to a reproducible ARVO case, and enumerate chain-candidate cases
by sink CWE, without fetching thousands of per-case JSON files.

Columns used (verified from the v3.0.0 db):
    localId, project, fix_commit (bare 40-hex git hash), patch_url, sanitizer, crash_type,
    language ('c' | 'c++'), repo_addr, reproduced (all 1 in v3.0.0).

The db lives on ROAR at $CF_WORK/arvo.db (156 MB). This reader is pure stdlib (sqlite3),
so it is unit-testable against a tiny in-memory fixture db.
"""

from __future__ import annotations

import re
import sqlite3
from dataclasses import dataclass

from .arvo import ARVO_IMAGE, cwe_from_crash_type

_HEX40 = re.compile(r"\b[0-9a-f]{40}\b")

# Columns the reader selects; kept in one place so row parsing stays consistent.
_COLS = (
    "localId",
    "project",
    "fix_commit",
    "patch_url",
    "sanitizer",
    "crash_type",
    "language",
    "repo_addr",
    "reproduced",
)


@dataclass
class ArvoIndexRow:
    """One row of the ARVO index, with the fields the pilot needs."""

    local_id: int
    project: str | None
    fix_commit: str | None
    patch_url: str | None
    sanitizer: str | None
    crash_type: str | None
    language: str | None
    repo_addr: str | None
    reproduced: bool

    @property
    def vul_image(self) -> str:
        return f"{ARVO_IMAGE}:{self.local_id}-vul"

    @property
    def fix_image(self) -> str:
        return f"{ARVO_IMAGE}:{self.local_id}-fix"

    @property
    def sink_cwes(self) -> tuple[int, ...]:
        """Candidate sink CWEs implied by this case's crash_type (advisory)."""
        return cwe_from_crash_type(self.crash_type)


def _row(r: sqlite3.Row) -> ArvoIndexRow:
    return ArvoIndexRow(
        local_id=int(r["localId"]),
        project=r["project"],
        fix_commit=r["fix_commit"],
        patch_url=r["patch_url"],
        sanitizer=r["sanitizer"],
        crash_type=r["crash_type"],
        language=r["language"],
        repo_addr=r["repo_addr"],
        reproduced=bool(r["reproduced"]),
    )


class ArvoIndex:
    """Read-only accessor over arvo.db. Use as a context manager."""

    def __init__(self, db_path: str) -> None:
        self._conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
        self._conn.row_factory = sqlite3.Row

    def __enter__(self) -> ArvoIndex:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def close(self) -> None:
        self._conn.close()

    def _select(self, where: str, params: tuple) -> list[ArvoIndexRow]:
        cols = ", ".join(_COLS)
        cur = self._conn.execute(f"SELECT {cols} FROM arvo WHERE {where}", params)
        return [_row(r) for r in cur.fetchall()]

    def by_fix_commit(self, commit_hash: str) -> ArvoIndexRow | None:
        """Look up a reproducible ARVO case by its exact fix-commit hash.

        This is the NVD-seed <-> ARVO-case join key: an OSV-resolved fix commit for a
        chain-labeled CVE, matched to a case ARVO can already reproduce.
        """
        commit_hash = commit_hash.strip().lower()
        rows = self._select("lower(fix_commit) = ?", (commit_hash,))
        return rows[0] if rows else None

    def candidates_by_sink_cwe(
        self, sink_cwe: int, language: str | None = None, limit: int | None = None
    ) -> list[ArvoIndexRow]:
        """Enumerate reproducible cases whose crash_type maps to a given sink CWE.

        These are chain-candidate cases: the sink is execution-witnessed already; the
        pilot must establish an upstream source (CWE-190/20) from code/patch to form a
        chain. Optionally restrict by language ('c' | 'c++').
        """
        cols = ", ".join(_COLS)
        sql = f"SELECT {cols} FROM arvo WHERE reproduced = 1"
        params: list = []
        if language:
            sql += " AND language = ?"
            params.append(language)
        cur = self._conn.execute(sql, tuple(params))
        out: list[ArvoIndexRow] = []
        for r in cur.fetchall():
            row = _row(r)
            if sink_cwe in row.sink_cwes:
                out.append(row)
                if limit and len(out) >= limit:
                    break
        return out

    def all_rows(self) -> dict[int, ArvoIndexRow]:
        """Every row, keyed by localId — for batch joins against the whole index."""
        cols = ", ".join(_COLS)
        cur = self._conn.execute(f"SELECT {cols} FROM arvo")
        return {int(r["localId"]): _row(r) for r in cur.fetchall()}

    def count(self) -> int:
        """Total rows in the index."""
        return self._conn.execute("SELECT COUNT(*) FROM arvo").fetchone()[0]
