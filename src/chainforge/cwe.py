"""CWE ontology backbone.

Defines the admissible directed CWE edges CHAINFORGE will label, validated against
CWE-1000 CanPrecede/CanFollow relations and MITRE Named-Chain/Composite definitions
(plan sections 3a and 3). Chain edges outside this catalog are not admissible.

The admissible edge set is the project's own catalog. Each edge is classified against MITRE
CWE release 4.20 (`mitre_chains.CWE_CATALOG_VERSION`) by `mitre_chains.classify_edge` as
direct CanPrecede, transitive (CanPrecede to an ancestor of the target via ChildOf), hierarchy
(one is an ancestor of the other) or catalog-only.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

# The CWEs in scope (plan section 3a). Names for readability / reporting. The original
# 8-CWE catalog is extended with MITRE-endorsed upstream sources for new chain arms (each
# addition is a literal `CanPrecede` edge in cwec_v4.20; see mitre_chains.classify_edge).
CWE_NAMES: dict[int, str] = {
    20: "Improper Input Validation",
    # PR-17: MITRE-allowed children of the DISCOURAGED CWE-20, chosen by what the check bounds.
    1284: "Improper Validation of Specified Quantity in Input",
    1285: "Improper Validation of Specified Index, Position, or Offset in Input",
    119: "Improper Restriction of Operations within Bounds of a Memory Buffer",
    125: "Out-of-bounds Read",
    190: "Integer Overflow or Wraparound",
    416: "Use After Free",
    476: "NULL Pointer Dereference",
    787: "Out-of-bounds Write",
    # MITRE-endorsed race arm: CWE-362 CanPrecede CWE-416 and CWE-476 (both mitre-direct).
    362: "Concurrent Execution using Shared Resource with Improper Synchronization",
    # New ARVO-reproducible arms (each MITRE-grounded; see mitre_chains.classify_edge):
    129: "Improper Validation of Array Index",  # 129 CanPrecede 119 (mitre-direct)
    843: "Access of Resource Using Incompatible Type (Type Confusion)",  # 843->119 (mitre-direct)
    252: "Unchecked Return Value",  # 252 CanPrecede 476 (mitre-direct)
    415: "Double Free",  # race->double-free sink; grounded via child 364 (364->415
    # mitre-direct, 364 ChildOf 362) -> classifier flags the broad 362->415 as
    # catalog-only (honest, not direct).
    # Uninitialised-memory arm. MSan built with -fsanitize-memory-track-origins reports
    # WHERE the uninitialised value was created (the allocation or declaration), so both links
    # are execution-witnessed at a site. The CWE-456 site is that creation site, which is where
    # the value lacks initialisation; it is not necessarily where the developer added it.
    # NOTE: extends the preregistered 8-CWE catalog (PR-2); disclose as a scope change.
    456: "Missing Initialization of a Variable",
    457: "Use of Uninitialized Variable",
}

# Admissible directed source->sink pairs (plan section 3a). An edge (X, Y) means
# "weakness X can causally enable weakness Y" and is a candidate chain link.
ADMISSIBLE_PAIRS: frozenset[tuple[int, int]] = frozenset(
    {
        (20, 190),
        (20, 125),
        (20, 787),
        # PR-17: CWE-20's allowed children inherit its edges (mitre-inherited grounding).
        (1284, 125),
        (1284, 787),
        (1284, 190),
        (1284, 119),
        (1285, 125),
        (1285, 787),
        (1285, 190),
        (1285, 119),
        (190, 787),
        (190, 119),
        (190, 125),
        (476, 787),
        (416, 787),
        # (416, 125): use-after-free READ. A UAF read reads freed-but-often-in-bounds memory,
        # so CWE-125 (out-of-bounds read) is a documented modeling APPROXIMATION of the sink
        # (see PREREGISTRATION PR-2), consistent with 416 as the freed-pointer-reuse source.
        (416, 125),
        # Race arm (MITRE-direct CanPrecede edges in cwec_v4.20): a data race on shared state
        # causally enables a use-after-free (416) or NULL-pointer dereference (476). Sourced
        # from NVD multi-CWE co-occurrence + patch co-signal (fix adds a locking primitive),
        # not static single-threaded dataflow (Joern cannot witness a race).
        (362, 416),
        (362, 476),
        # ARVO-reproducible arms, MITRE-grounded, filling weak/new strata:
        (
            129,
            119,
        ),  # improper array index -> buffer bounds (mitre-direct); ARVO Index-out-of-bounds
        # PR-17: a UBSan index sink takes its access direction (mitre-transitive via 119).
        (129, 125),
        (129, 787),
        (843, 119),  # type confusion -> buffer bounds (mitre-direct); ARVO Bad-cast
        (252, 476),  # unchecked return value -> NULL deref (mitre-direct); ARVO null-deref/SEGV
        # (456, 457) mitre-direct. Largest reproducible class in ARVO: 1183 cases (19.3%),
        # 127 projects. A 40-case trial gave 33/40 clean differentials and 24/40 with BOTH
        # links localized from the MSan ORIGIN block ("was created by an allocation of 'buf'
        # in the stack frame of ..."), i.e. the site where the uninitialised value was
        # created is execution-witnessed, not inferred (it is not necessarily where the fix
        # adds the initialisation). An earlier attempt to attribute the source from
        # patches scored only 6/29 and led to a wrong rejection - the sanitizer had the
        # answer all along.
        (456, 457),
        (362, 415),  # race -> double free; 364->415 is mitre-direct and 362 is 364's parent.
        # ARVO Heap-double-free sink is ASan-witnessed; race precedence from patch/structure.
    }
)

# CWEs that only ever appear as chain sources (never sinks) in the catalog.
SOURCE_CWES: frozenset[int] = frozenset(src for src, _ in ADMISSIBLE_PAIRS)
# CWEs that appear as sinks (terminal weaknesses).
SINK_CWES: frozenset[int] = frozenset(dst for _, dst in ADMISSIBLE_PAIRS)

_CWE_RE = re.compile(r"CWE[-\s]?(\d+)", re.IGNORECASE)


def parse_cwe_id(token: str) -> int | None:
    """Extract a numeric CWE id from a token like 'CWE-190', 'cwe190', or '190'.

    Returns None if no CWE number is present.
    """
    token = token.strip()
    m = _CWE_RE.search(token)
    if m:
        return int(m.group(1))
    if token.isdigit():
        return int(token)
    return None


def is_admissible_edge(src: int, dst: int) -> bool:
    """True if src->dst is an admissible chain edge in the 8-CWE catalog."""
    return (src, dst) in ADMISSIBLE_PAIRS


def in_scope(cwe_id: int) -> bool:
    """True if the CWE is one of the 8 in scope."""
    return cwe_id in CWE_NAMES


@dataclass(frozen=True)
class ChainValidation:
    """Result of validating an ordered CWE sequence against the catalog."""

    admissible: bool
    edges: tuple[tuple[int, int], ...]
    inadmissible_edges: tuple[tuple[int, int], ...]
    out_of_scope: tuple[int, ...]


def validate_chain(cwe_sequence: list[int]) -> ChainValidation:
    """Validate an ordered CWE sequence as a chain of admissible edges.

    A sequence [a, b, c] is admissible iff every consecutive pair (a,b), (b,c) is an
    admissible edge and every CWE is in scope. Sequences shorter than 2 are not chains.
    """
    out_of_scope = tuple(c for c in cwe_sequence if not in_scope(c))
    edges = tuple(zip(cwe_sequence, cwe_sequence[1:], strict=False))
    inadmissible = tuple(e for e in edges if e not in ADMISSIBLE_PAIRS)
    admissible = bool(edges) and not inadmissible and not out_of_scope
    return ChainValidation(
        admissible=admissible,
        edges=edges,
        inadmissible_edges=inadmissible,
        out_of_scope=out_of_scope,
    )
