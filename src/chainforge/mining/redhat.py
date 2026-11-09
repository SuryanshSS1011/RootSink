"""Red Hat cwe-toolkit `->` chain-notation parser (plan sections 2, 3).

Red Hat is the one vendor encoding CWE chains machine-readably. Their notation:

    CWE-190->CWE-122                       simple chain
    CWE-20->CWE-805->(CWE-125|CWE-787)     chain ending in an alternation group
    CWE-125|CWE-787                        bare alternation (no chain)

`->` is causal ordering (source on the left). `|` is alternation: any of the listed
CWEs may be the actual weakness, so a `(a|b)` group expands into separate candidate
chains. Parentheses group an alternation within a chain. ~8% of Red Hat CVEs (2012-2020)
use `->`, ~2% use `|` — the single richest chain-label seed to reproduce.

This module expands a notation string into concrete ordered CWE sequences, then keeps
only those whose consecutive pairs are admissible edges in the 8-CWE catalog. Expanded
candidates seed BRONZE records (co-occurrence with admissible ordering, plan section 3).

NOTE (verified 2026-07-20): the PUBLIC Red Hat security-data API
(access.redhat.com/hydra/rest/securitydata) flattens each CVE to a single `CWE` field and
does NOT expose the `->`/`|` notation — 0 of 14k+ 2013-2019 records carried it. The chains
live in Red Hat's internal cwe-toolkit/Bugzilla data. So this parser is fed notation
strings from that internal data when available; for public seed generation at scale, use
NVD multi-CWE co-occurrence instead (see chainforge.mining.nvd), which is the practical
public equivalent of the BRONZE co-occurrence seed.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from itertools import product

from ..cwe import parse_cwe_id, validate_chain

# One position in a chain: either a single CWE token or a parenthesized alternation.
_TOKEN_RE = re.compile(
    r"""
    \s*
    (?:
        \( (?P<group>[^)]*) \)      # ( CWE-a | CWE-b )
      | (?P<single>[^->()|]+)       # CWE-a  (a bare token, may itself contain '|')
    )
    \s*
    """,
    re.VERBOSE,
)


@dataclass
class ParsedChain:
    """Result of parsing one Red Hat chain-notation string."""

    raw: str
    # Every concrete ordered CWE sequence the notation expands to.
    candidates: list[list[int]] = field(default_factory=list)
    # Subset of candidates that are admissible in the 8-CWE catalog.
    admissible: list[list[int]] = field(default_factory=list)
    # Tokens that could not be parsed into a CWE id.
    unparsed: list[str] = field(default_factory=list)


def _split_positions(notation: str) -> list[str]:
    """Split a notation string on top-level `->`, keeping parenthesized groups intact."""
    positions: list[str] = []
    depth = 0
    buf: list[str] = []
    i = 0
    while i < len(notation):
        ch = notation[i]
        if ch == "(":
            depth += 1
            buf.append(ch)
        elif ch == ")":
            depth = max(0, depth - 1)
            buf.append(ch)
        elif ch == "-" and depth == 0 and notation[i : i + 2] == "->":
            positions.append("".join(buf))
            buf = []
            i += 2
            continue
        else:
            buf.append(ch)
        i += 1
    positions.append("".join(buf))
    return [p for p in (p.strip() for p in positions) if p]


def _position_alternatives(position: str) -> tuple[list[int], list[str]]:
    """Expand one chain position into its alternative CWE ids.

    A position is either 'CWE-a', '(CWE-a|CWE-b)', or 'CWE-a|CWE-b'. Returns the list of
    CWE ids it may take and any tokens that failed to parse.
    """
    inner = position.strip()
    if inner.startswith("(") and inner.endswith(")"):
        inner = inner[1:-1]
    ids: list[int] = []
    unparsed: list[str] = []
    for alt in inner.split("|"):
        alt = alt.strip()
        if not alt:
            continue
        cwe = parse_cwe_id(alt)
        if cwe is None:
            unparsed.append(alt)
        else:
            ids.append(cwe)
    return ids, unparsed


def parse_chain_notation(notation: str) -> ParsedChain:
    """Parse a Red Hat chain-notation string into concrete candidate CWE sequences.

    Alternation groups are expanded by cartesian product, so
    ``CWE-20->(CWE-125|CWE-787)`` yields ``[[20, 125], [20, 787]]``.
    """
    result = ParsedChain(raw=notation)
    positions = _split_positions(notation)
    if not positions:
        return result

    per_position: list[list[int]] = []
    for pos in positions:
        ids, unparsed = _position_alternatives(pos)
        result.unparsed.extend(unparsed)
        if not ids:
            # A position with no parseable CWE breaks the whole chain.
            return result
        per_position.append(ids)

    for combo in product(*per_position):
        seq = list(combo)
        result.candidates.append(seq)
        if validate_chain(seq).admissible:
            result.admissible.append(seq)

    return result


@dataclass
class RedHatSeed:
    """A candidate chain seed harvested from a Red Hat CVE record."""

    cve: str
    chain_string: str  # normalized CHAINFORGE form, e.g. CWE-20->CWE-190->CWE-787
    cwe_sequence: list[int]


def seeds_from_notation(cve: str, notation: str) -> list[RedHatSeed]:
    """Turn one CVE's Red Hat chain notation into admissible chain seeds (may be empty)."""
    parsed = parse_chain_notation(notation)
    seeds: list[RedHatSeed] = []
    for seq in parsed.admissible:
        chain_string = "->".join(f"CWE-{c}" for c in seq)
        seeds.append(RedHatSeed(cve=cve, chain_string=chain_string, cwe_sequence=seq))
    return seeds
