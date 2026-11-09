"""MITRE CWE chain ontology (version-pinned subset of cwec_v4.20.xml).

CHAINFORGE's admissible edges (``cwe.ADMISSIBLE_PAIRS``) are a hand-curated 8-CWE
catalog. This module grounds those edges in the *authoritative* MITRE ontology so every
chain record can carry its epistemic status: is a given source->sink pair a chain MITRE
itself recognizes, or a CHAINFORGE modeling decision?

MITRE encodes causal chains as ``CanPrecede`` / ``CanFollow`` relations and the weakness
hierarchy as ``ChildOf``. A pair (X, Y) is classified as:

  - ``mitre-direct``     : X CanPrecede Y is a literal edge in the catalog.
  - ``mitre-transitive`` : X CanPrecede A where Y is-a A (Y descends to A through ChildOf),
                           i.e. MITRE endorses the chain at a more abstract sink. Example:
                           CWE-190 CanPrecede CWE-119 and CWE-787 ChildOf CWE-119, so
                           190->787 is a transitive MITRE chain.
  - ``mitre-hierarchy``  : Y is-a X or X is-a Y (a specialization, not a precede-chain).
                           Example: CWE-190 ChildOf CWE-20, so 20->190 is a specialization
                           edge, not a causal precede-chain.
  - ``catalog-only``     : neither of the above; a CHAINFORGE modeling approximation
                           (e.g. 476->787; 416->125 is mitre-inherited since PR-17).

The data below is a focused subset (edges touching CHAINFORGE's in-scope CWEs and the
candidate expansion arms) extracted from the official ``cwec_v4.20.xml`` catalog
(Version 4.20, 2026-04-30). Regenerate with ``scripts/gen_mitre_chains.py`` when bumping
the CWE catalog version.
"""

from __future__ import annotations

from dataclasses import dataclass

CWE_CATALOG_VERSION = "4.20"

# X CanPrecede Y  (causal chain edges MITRE recognizes)
CANPRECEDE: frozenset[tuple[int, int]] = frozenset(
    {
        (20, 22),
        (20, 41),
        (20, 74),
        (20, 119),
        (20, 770),
        (120, 123),
        (128, 119),
        (129, 119),
        (129, 789),
        (129, 823),
        (131, 119),
        (134, 123),
        (170, 120),
        (190, 119),
        (193, 119),
        (193, 170),
        (193, 617),
        (195, 119),
        (231, 120),
        (252, 476),
        (362, 416),
        (362, 476),
        (364, 123),
        (364, 416),
        (416, 120),
        (416, 123),
        (456, 120),
        (456, 457),  # real MITRE edge; kept for correct classification even though
        # ChainForge does not admit the pair (source not attributable - see cwe.py)
        (479, 123),
        (481, 697),
        (562, 672),
        (562, 825),
        (590, 123),
        (662, 362),
        (681, 682),
        (682, 170),
        (754, 416),
        (781, 822),
        (789, 476),
        (822, 125),
        (1284, 789),
        (822, 787),
        (823, 125),
        (823, 787),
        (824, 125),
        (824, 787),
        (825, 125),
        (825, 787),
        (826, 672),
        (839, 119),
        (839, 124),
        (839, 195),
        (839, 682),
        (843, 119),
        (911, 672),
        (1257, 119),
        (1260, 119),
        (1265, 416),
        (1325, 476),
        (1339, 119),
        (1341, 672),
    }
)

# X ChildOf Y  (weakness hierarchy; used to compute transitive chains and specializations)
CHILDOF: frozenset[tuple[int, int]] = frozenset(
    {
        (20, 707),
        (118, 664),
        (119, 20),
        (119, 118),
        (120, 20),
        (120, 119),
        (120, 787),
        (123, 119),
        (123, 787),
        (125, 119),
        (129, 20),
        (129, 1285),
        (131, 682),
        (190, 20),
        (190, 682),
        (193, 682),
        (195, 681),
        (252, 754),
        (362, 662),
        (416, 672),
        (416, 825),
        (476, 710),
        (476, 754),
        (662, 664),
        (662, 691),
        (666, 664),
        (672, 666),
        (681, 704),
        (704, 664),
        (754, 703),
        (787, 119),
        (822, 119),
        (823, 119),
        (824, 119),
        (825, 119),
        (825, 672),
        (839, 1023),
        (843, 704),
        (1023, 697),
        (1284, 20),
        (1285, 20),
    }
)


def _ancestors(cwe: int) -> set[int]:
    """All CWEs reachable from `cwe` via ChildOf (its abstractions), including itself."""
    seen = {cwe}
    stack = [cwe]
    while stack:
        c = stack.pop()
        for child, parent in CHILDOF:
            if child == c and parent not in seen:
                seen.add(parent)
                stack.append(parent)
    return seen


@dataclass(frozen=True)
class EdgeProvenance:
    """MITRE-ontology classification of a single source->sink chain edge."""

    src: int
    dst: int
    kind: str  # mitre-direct | mitre-transitive | mitre-inherited | mitre-hierarchy | catalog-only
    detail: str

    @property
    def mitre_recognized(self) -> bool:
        """True if MITRE endorses this as a causal chain (a direct, transitive or inherited
        precede edge)."""
        return self.kind in ("mitre-direct", "mitre-transitive", "mitre-inherited")


def classify_edge(src: int, dst: int) -> EdgeProvenance:
    """Classify a source->sink CWE pair against the MITRE chain ontology."""
    if (src, dst) in CANPRECEDE:
        return EdgeProvenance(src, dst, "mitre-direct", f"CWE-{src} CanPrecede CWE-{dst}")
    # transitive: src CanPrecede A where dst is-a A (dst's abstractions include A).
    dst_abstractions = _ancestors(dst)
    for a in sorted(dst_abstractions):
        if (src, a) in CANPRECEDE:
            return EdgeProvenance(
                src,
                dst,
                "mitre-transitive",
                f"CWE-{src} CanPrecede CWE-{a}; CWE-{dst} is-a CWE-{a}",
            )
    # inherited (PR-17): an abstraction of src CanPrecede an abstraction of dst, so MITRE
    # endorses the chain one level up (CWE-1284 is-a CWE-20, CWE-20 CanPrecede CWE-119,
    # CWE-125 is-a CWE-119). Reported apart from direct and transitive.
    for s in sorted(_ancestors(src) - {src}):
        for a in sorted(dst_abstractions):
            # The sink's abstraction must not be one of src's own abstractions, or the path
            # runs through the sink's own hierarchy (CWE-416 is-a CWE-119 is-a CWE-20).
            if (s, a) in CANPRECEDE and a not in _ancestors(src):
                return EdgeProvenance(
                    src,
                    dst,
                    "mitre-inherited",
                    f"CWE-{src} is-a CWE-{s}; CWE-{s} CanPrecede CWE-{a}; CWE-{dst} is-a CWE-{a}",
                )
    # hierarchy: one is an abstraction of the other (specialization, not a precede-chain).
    if dst in _ancestors(src):
        return EdgeProvenance(src, dst, "mitre-hierarchy", f"CWE-{src} is-a CWE-{dst}")
    if src in _ancestors(dst):
        return EdgeProvenance(src, dst, "mitre-hierarchy", f"CWE-{dst} is-a CWE-{src}")
    return EdgeProvenance(src, dst, "catalog-only", "CHAINFORGE modeling edge (not in MITRE)")


@dataclass(frozen=True)
class ChainProvenance:
    """MITRE classification of a full ordered chain (all its edges)."""

    edges: tuple[EdgeProvenance, ...]

    @property
    def all_mitre_recognized(self) -> bool:
        """True if every edge is a MITRE-recognized (direct/transitive) chain edge."""
        return bool(self.edges) and all(e.mitre_recognized for e in self.edges)

    @property
    def any_catalog_only(self) -> bool:
        """True if any edge is a CHAINFORGE-only modeling edge."""
        return any(e.kind == "catalog-only" for e in self.edges)


def classify_chain(cwe_sequence: list[int]) -> ChainProvenance:
    """Classify every consecutive edge of an ordered CWE chain against MITRE."""
    edges = tuple(classify_edge(s, d) for s, d in zip(cwe_sequence, cwe_sequence[1:], strict=False))
    return ChainProvenance(edges=edges)
