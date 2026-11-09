"""Silver-label harness: static dataflow candidate generation (plan section 3b).

A chain edge X->Y earns SILVER evidence when a static dataflow path links a CWE-X source
site to a CWE-Y sink site AND the pair is ontology-admissible. This module maps each
admissible CWE pair to concrete Joern CPGQL source/sink patterns, emits a Joern script
that runs ``sink.reachableBy(source)``, and parses the path count from the output.

Deliberately capped at SILVER (plan section 3b): Joern lacks argument-level granularity
and full inter-procedural taint, and ~66% of real chains are cross-scope, which static
dataflow under-captures. A positive result is candidate evidence, never a GOLD witness.

Joern runs on ROAR (see infra/roar/silver_joern.sh). This module is pure Python — it
generates the query and parses results — so it is unit-testable offline.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from .cwe import ADMISSIBLE_PAIRS, is_admissible_edge

# CWE -> Joern CPGQL fragment producing the candidate nodes for that weakness.
# Sources are the call SITES that introduce the tainted/underchecked value; sinks are the
# ARGUMENTS of the dangerous operation. Patterns are intentionally broad (high recall, low
# precision) because this only gates SILVER — precision comes from the GOLD execution pass.
#
# Each entry is (role, cpgql_fragment). `cpg` is in scope in the generated script.
_SOURCE_PATTERNS: dict[int, str] = {
    # CWE-20 Improper Input Validation: values entering from untrusted input readers.
    20: (
        'cpg.call.name("(scanf|sscanf|fscanf|fgets|gets|read|recv|'
        'getenv|atoi|atol|strtol|strtoul)")'
    ),
    # CWE-190 Integer Overflow (as a length-2 SOURCE): a SIZE-CONTEXT arithmetic expression that
    # can wrap. The value IS the multiplication/left-shift node itself, and we let reachableBy
    # follow it to the sink — rather than requiring it to be the allocator's DIRECT argument.
    # The old pattern (`allocator.argument.isCall.name(arith)`) only matched the inlined form
    # `malloc(a*b)`; it MISSED the common `n = a*b; ... malloc(n)` (argument is the identifier n,
    # not the multiplication call) and fired 0% on the whole C++ corpus. Keying on the arithmetic
    # nodes directly catches both. Scope to multiplication|shiftLeft ONLY — those are the ops that
    # actually wrap into allocation sizes; addition/subtraction are ubiquitous (thousands of nodes,
    # intractable + noisy) and rarely the size-overflow culprit. This is the SAME node set reused
    # as the length-3 intermediate (_INTERMEDIATE_PATTERNS[190]) so the two roles cannot drift.
    190: 'cpg.call.name("<operator>.(multiplication|shiftLeft)")',
    # NOTE: CWE-416 (use-after-free) and CWE-476 (null deref) are NOT here — they are
    # lifecycle bugs, not taint flows (reachableBy returns 0 for them), and are detected via
    # the shared-variable query in _LIFECYCLE_SITE below, not reachability.
}

_SINK_PATTERNS: dict[int, str] = {
    # CWE-787 OOB write: destination/size args of memory-writing operations.
    787: 'cpg.call.name("(memcpy|memmove|strcpy|strncpy|strcat|sprintf|memset)").argument',
    # CWE-125 OOB read: source/size args of memory-reading operations + indexing.
    125: 'cpg.call.name("(memcpy|memmove|strncpy|strncmp|memcmp|read)").argument',
    # CWE-119 buffer bounds (generic): args of bounded/unbounded buffer ops.
    119: 'cpg.call.name("(memcpy|memmove|strcpy|strncpy|strcat|sprintf)").argument',
}

# Intermediate-link patterns: a CWE that sits BETWEEN a source and a sink in a 3-CWE chain.
# CWE-190's intermediate node set is IDENTICAL to its length-2 source node set (size-context
# arithmetic) — this is the composition property that lets a length-3 20->190->787 spine be
# validated as 20->190 stacked on 190->787. Reuse the same pattern so the two roles cannot
# drift apart.
_INTERMEDIATE_PATTERNS: dict[int, str] = {
    190: _SOURCE_PATTERNS[190],
}


@dataclass
class SilverQuery:
    """A generated Joern dataflow query for one admissible CWE pair."""

    src_cwe: int
    sink_cwe: int
    script: str


@dataclass
class SilverResult:
    """Parsed outcome of running a SilverQuery on a source tree."""

    src_cwe: int
    sink_cwe: int
    path_count: int
    has_dataflow: bool = field(init=False)

    def __post_init__(self) -> None:
        self.has_dataflow = self.path_count > 0


class UnsupportedPairError(ValueError):
    """Raised for a CWE pair with no source/sink pattern or that is inadmissible."""


_MARKER = "CF_REACHABLE"


def _import_c(source_dir: str) -> str:
    """Joern import line that FORCES the C/C++ frontend (c2cpg).

    Plain ``importCode(dir)`` auto-detects the language by file counts. That is fine for an
    ARVO project subset (all C/C++), but a raw git checkout (clone-based OSV mining) is a whole
    repo: mruby ships .rb files, most projects ship JS/Python/docs, so auto-detect picks the
    wrong frontend (observed: mruby -> RubyCpgGenerator) and the C sink/source call nodes never
    exist -> every query returns 0. ``importCode.c`` pins c2cpg so only the C/C++ translation
    units are parsed, regardless of what else is in the tree.
    """
    return f'importCode.c(inputPath="{source_dir}")'


def build_query(src_cwe: int, sink_cwe: int, source_dir: str = "src") -> SilverQuery:
    """Build a Joern script that reports the dataflow path count for src_cwe->sink_cwe.

    Raises UnsupportedPairError if the pair is inadmissible or lacks a pattern.
    """
    if not is_admissible_edge(src_cwe, sink_cwe):
        raise UnsupportedPairError(f"CWE-{src_cwe}->CWE-{sink_cwe} is not an admissible edge")
    if src_cwe not in _SOURCE_PATTERNS:
        raise UnsupportedPairError(f"no source pattern for CWE-{src_cwe}")
    if sink_cwe not in _SINK_PATTERNS:
        raise UnsupportedPairError(f"no sink pattern for CWE-{sink_cwe}")

    src_expr = _SOURCE_PATTERNS[src_cwe]
    sink_expr = _SINK_PATTERNS[sink_cwe]
    script = (
        f"{_import_c(source_dir)}\n"
        f"val src = {src_expr}\n"
        f"val sink = {sink_expr}\n"
        f'println("{_MARKER}=" + sink.reachableBy(src).size)\n'
    )
    return SilverQuery(src_cwe=src_cwe, sink_cwe=sink_cwe, script=script)


_RESULT_RE = re.compile(rf"{_MARKER}=(\d+)")


def parse_result(src_cwe: int, sink_cwe: int, joern_output: str) -> SilverResult:
    """Parse the path count from a Joern run's stdout.

    Raises ValueError if the marker line is absent (i.e. the query did not complete).
    """
    m = _RESULT_RE.search(joern_output)
    if not m:
        raise ValueError(f"no {_MARKER}= marker in Joern output (query did not complete)")
    return SilverResult(src_cwe=src_cwe, sink_cwe=sink_cwe, path_count=int(m.group(1)))


def build_multi_query(src_cwes: list[int], sink_cwe: int, source_dir: str = "src") -> SilverQuery:
    """Build ONE Joern script testing several source CWEs against a single sink.

    Building the CPG (``importCode``) is by far the slowest step, and it is identical for
    every source CWE, so the pilot must build it once and run every source query against it
    — not rebuild per pair (that was a ~4x wall-clock blowup). Each source's result is
    tagged with a per-source marker ``CF_REACHABLE_<src>=<n>``. Inadmissible/unsupported
    sources are skipped. Raises UnsupportedPairError if no source is usable for the sink.
    """
    if sink_cwe not in _SINK_PATTERNS:
        raise UnsupportedPairError(f"no sink pattern for CWE-{sink_cwe}")
    # Reachability (taint-flow) sources and lifecycle (shared-variable) sources are detected
    # differently; a source is "usable" if it has EITHER kind of pattern and is admissible.
    reach = [s for s in src_cwes if is_admissible_edge(s, sink_cwe) and s in _SOURCE_PATTERNS]
    life = [s for s in src_cwes if is_admissible_edge(s, sink_cwe) and s in _LIFECYCLE_SITE]
    if not (reach or life):
        raise UnsupportedPairError(f"no usable source CWE for sink CWE-{sink_cwe}")

    lines = [_import_c(source_dir), f"val sink = {_SINK_PATTERNS[sink_cwe]}"]
    for s in reach:
        lines.append(f"val src_{s} = {_SOURCE_PATTERNS[s]}")
        lines.append(f'println("{_MARKER}_{s}=" + sink.reachableBy(src_{s}).size)')
    # Lifecycle sources (416/476): shared-variable count, not reachability (see the lifecycle
    # section below). Reuses the same CPG — near-free extra queries.
    if life:
        idents = "argument.isIdentifier.name.l.distinct.toSet"
        lines.append(f'val lc_used = cpg.call.name("{_LIFECYCLE_USE}").{idents}')
        # DISCRIMINATOR (fixes the 416<->476 confusion found in the SILVER precision study):
        # a pointer that is FREED is a use-after-free (416) candidate; a malloc'd pointer is a
        # null-deref (476) candidate ONLY IF it is NOT also freed. Without this, every malloc'd-
        # then-freed pointer (i.e. almost every heap object) matched BOTH, and specificity picked
        # 416 even when the real bug was 476 (and vice versa). Compute the freed set once and
        # subtract it from the 476 set so the two node sets are disjoint by construction.
        lines.append(f'val lc_freed = cpg.call.name("{_LIFECYCLE_SITE[416]}").{idents}')
        for s in life:
            if s == 476:
                # null-deref: alloc'd + used, but NOT freed here (freed -> that's a UAF, 416).
                lines.append(
                    f'val lc_{s} = cpg.call.name("{_LIFECYCLE_SITE[s]}").{idents}.diff(lc_freed)'
                )
            else:
                lines.append(f'val lc_{s} = cpg.call.name("{_LIFECYCLE_SITE[s]}").{idents}')
            lines.append(f'println("{_LIFECYCLE_MARKER}_{s}=" + lc_{s}.intersect(lc_used).size)')
    script = "\n".join(lines) + "\n"
    # src_cwe on the returned query is a sentinel (0) since it covers several sources.
    return SilverQuery(src_cwe=0, sink_cwe=sink_cwe, script=script)


def parse_multi_result(sink_cwe: int, joern_output: str) -> list[SilverResult]:
    """Parse reachability AND lifecycle markers from a multi-source Joern run.

    Reachability sources emit ``CF_REACHABLE_<src>=<n>`` (n = path count); lifecycle sources
    (416/476) emit ``CF_LIFECYCLE_<src>=<n>`` (n = shared-variable count). Both are returned
    as SilverResult with ``path_count`` set to the respective count, so the pilot consumes
    them uniformly — a positive lifecycle source becomes a positive source-link just like a
    reachability one. Empty if none completed.
    """
    results: list[SilverResult] = []
    for m in re.finditer(rf"{_MARKER}_(\d+)=(\d+)", joern_output):
        results.append(
            SilverResult(src_cwe=int(m.group(1)), sink_cwe=sink_cwe, path_count=int(m.group(2)))
        )
    for m in re.finditer(rf"{_LIFECYCLE_MARKER}_(\d+)=(\d+)", joern_output):
        results.append(
            SilverResult(src_cwe=int(m.group(1)), sink_cwe=sink_cwe, path_count=int(m.group(2)))
        )
    return results


def supported_pairs() -> list[tuple[int, int]]:
    """Admissible pairs for which both a source and sink pattern exist."""
    return sorted(
        (s, d) for (s, d) in ADMISSIBLE_PAIRS if s in _SOURCE_PATTERNS and d in _SINK_PATTERNS
    )


@dataclass
class ChainDataflowResult:
    """Result of a 3-CWE chain query: both hops' path counts."""

    src_cwe: int
    mid_cwe: int
    sink_cwe: int
    hop1_paths: int  # source -> intermediate (mid nodes reached by source)
    hop2_paths: int  # intermediate -> sink
    shared_mid: int = 0  # H3: mid nodes on BOTH hops (the strict, same-node chain witness)
    has_chain: bool = field(init=False)

    def __post_init__(self) -> None:
        # STRICT chain: the same intermediate node is reached-by-source AND reaches-the-sink.
        # H1>0 & H2>0 alone can be two DIFFERENT arithmetic nodes -> not a real 3-link chain.
        self.has_chain = self.shared_mid > 0


_CHAIN_MARKER = "CF_CHAIN"


def build_chain_query(
    src_cwe: int, mid_cwe: int, sink_cwe: int, source_dir: str = "src"
) -> SilverQuery:
    """Build a Joern script for a 3-CWE chain source->intermediate->sink.

    Emits two hop counts: ``CF_CHAIN_H1=<n>`` (mid reachableBy src) and
    ``CF_CHAIN_H2=<n>`` (sink reachableBy mid). Both edges must be admissible and every
    link must have a pattern. This is the flagship CWE-20->CWE-190->CWE-787 detector: the
    intermediate (arithmetic) is only meaningful because it is pinned on BOTH sides.
    """
    if not (is_admissible_edge(src_cwe, mid_cwe) and is_admissible_edge(mid_cwe, sink_cwe)):
        raise UnsupportedPairError(
            f"CWE-{src_cwe}->CWE-{mid_cwe}->CWE-{sink_cwe} is not an admissible chain"
        )
    if src_cwe not in _SOURCE_PATTERNS:
        raise UnsupportedPairError(f"no source pattern for CWE-{src_cwe}")
    if mid_cwe not in _INTERMEDIATE_PATTERNS:
        raise UnsupportedPairError(f"no intermediate pattern for CWE-{mid_cwe}")
    if sink_cwe not in _SINK_PATTERNS:
        raise UnsupportedPairError(f"no sink pattern for CWE-{sink_cwe}")

    # H1 = mid nodes reached by the source; H2 = sink args reached by the mid; H3 = the STRICT
    # chain: mid nodes that are BOTH reached-by-source AND reach-the-sink (the same arithmetic
    # node is on both hops). H1>0 & H2>0 alone allows the input to reach ONE arithmetic and a
    # DIFFERENT arithmetic to reach the sink — not a genuine 3-link chain. A reviewer would (and
    # should) demand the shared-node form; H3>0 is the real length-3 witness. H1/H2 are kept for
    # diagnostics (they explain WHY H3 is 0 when it is: which hop is missing).
    # Two design constraints, both learned the hard way:
    #  (1) Joern traversals are LAZY and single-use — iterating `mid` twice gives 0 the 2nd time
    #      (real bug: H2=0 while the standalone query found 849). So materialize node ids ONCE.
    #  (2) Per-node reachability (`midL.filter(m => sink.reachableBy(m)...)`) is INTRACTABLE —
    #      it runs a full reachability pass PER mid node (849 nodes -> >1h walltime, job killed).
    #      Instead do TWO set-level reachability calls and intersect by node id:
    #        H1 set = mid ids reachable-BY src  (midL.reachableBy(srcL) — one pass)
    #        H2 set = mid ids that REACH sink   (mid ids appearing in sink.reachableByFlows(mid))
    #      reachableByFlows returns full paths; the mid nodes ON those paths are the ones that
    #      actually reach the sink. H3 = |H1set ∩ H2set| = same arithmetic node on both hops.
    src = _SOURCE_PATTERNS[src_cwe]
    mid = _INTERMEDIATE_PATTERNS[mid_cwe]
    sink = _SINK_PATTERNS[sink_cwe]
    script = (
        f"{_import_c(source_dir)}\n"
        f"val midIds = ({mid}).id.l.toSet\n"
        f"val h1ids = ({mid}).reachableBy({src}).id.l.toSet\n"
        f"val flowNodes = ({sink}).reachableByFlows({mid}).flatMap(_.elements).id.l.toSet\n"
        "val h2ids = flowNodes.intersect(midIds)\n"
        f'println("{_CHAIN_MARKER}_H1=" + h1ids.size)\n'
        f'println("{_CHAIN_MARKER}_H2=" + h2ids.size)\n'
        f'println("{_CHAIN_MARKER}_H3=" + h1ids.intersect(h2ids).size)\n'
    )
    return SilverQuery(src_cwe=src_cwe, sink_cwe=sink_cwe, script=script)


def parse_chain_result(
    src_cwe: int, mid_cwe: int, sink_cwe: int, joern_output: str
) -> ChainDataflowResult:
    """Parse the two hop counts from a 3-CWE chain Joern run.

    Raises ValueError if either hop marker is missing (query did not complete).
    """
    h1 = re.search(rf"{_CHAIN_MARKER}_H1=(\d+)", joern_output)
    h2 = re.search(rf"{_CHAIN_MARKER}_H2=(\d+)", joern_output)
    h3 = re.search(rf"{_CHAIN_MARKER}_H3=(\d+)", joern_output)
    if not (h1 and h2):
        raise ValueError(f"missing {_CHAIN_MARKER} hop markers in Joern output")
    return ChainDataflowResult(
        src_cwe=src_cwe,
        mid_cwe=mid_cwe,
        sink_cwe=sink_cwe,
        hop1_paths=int(h1.group(1)),
        hop2_paths=int(h2.group(1)),
        # H3 (strict shared-node) is absent in older traces -> fall back to the weaker H1&H2 AND.
        shared_mid=int(h3.group(1)) if h3 else (min(int(h1.group(1)), int(h2.group(1))) and 1),
    )


# --- Lifecycle-CWE detection (CWE-416 use-after-free, CWE-476 null deref) ---
#
# These are NOT taint flows: a UAF is the SAME pointer freed then reused, and a null-deref is
# an allocation result used without a null check. `reachableBy` (forward data propagation)
# returns 0 for them. Instead detect a SHARED VARIABLE: an identifier that appears both at the
# lifecycle site (free / alloc) and at a later use (memory op). This is verified valid CPGQL
# and returns a meaningful count on real code (e.g. 4 shared names on mdbtools).
#
# COARSE by design (SILVER only): the intersection is by identifier NAME across the whole CPG,
# so it ignores scope and control-flow ordering — "freed AND used-in-a-write somewhere", not
# strictly "freed THEN written to the same object". Precision comes from the GOLD execution
# pass (the sanitizer witnesses the actual UAF); this only gates the SILVER dataflow evidence.

# Lifecycle source patterns: (call-name regex producing the identifier we track).
_LIFECYCLE_SITE: dict[int, str] = {
    # Freed pointer. Includes CUSTOM free wrappers — the precision study found a real 416 miss
    # (nokogiri CVE-2026-57436) where the free was a wrapper, not bare libc free. `.*_(free|
    # destroy|dealloc)` catches project free helpers; these suffixes are almost always frees, so
    # low over-match risk. Verified: broadening flipped nokogiri to the correct 416 and did NOT
    # inflate path counts on qemu/libxml2 (co-present-bug cases stay bounded).
    416: "(free|g_free|kfree|xfree|vfree|kvfree|xmlFree|.*_(free|destroy|dealloc))",
    # Alloc: keep only high-precision alloc NAMES. Deliberately NOT `.*_(new|create)` — those
    # suffixes match too many non-alloc functions (list_new, ctx_create) and would over-fire 476.
    476: "(malloc|calloc|realloc|g_malloc|kmalloc|kzalloc|vmalloc|.*_alloc)",
}
# The "use" side both lifecycle CWEs share: identifiers used in a memory operation.
_LIFECYCLE_USE = "(memcpy|memmove|strcpy|strncpy|strcat|memset|sprintf)"

_LIFECYCLE_MARKER = "CF_LIFECYCLE"


@dataclass
class LifecycleResult:
    """Result of a lifecycle (shared-variable) query for CWE-416 / CWE-476."""

    src_cwe: int
    sink_cwe: int
    shared_count: int  # identifiers both at the lifecycle site and a later memory-op use
    has_evidence: bool = field(init=False)

    def __post_init__(self) -> None:
        self.has_evidence = self.shared_count > 0


def build_lifecycle_query(src_cwe: int, sink_cwe: int, source_dir: str = "src") -> SilverQuery:
    """Build a Joern script detecting a lifecycle CWE (416/476) as a shared variable.

    Counts identifiers appearing both as an argument to the lifecycle call (free/alloc) and
    as an argument to a memory op. Emits ``CF_LIFECYCLE_<src>=<count>``.
    """
    if not is_admissible_edge(src_cwe, sink_cwe):
        raise UnsupportedPairError(f"CWE-{src_cwe}->CWE-{sink_cwe} is not an admissible edge")
    if src_cwe not in _LIFECYCLE_SITE:
        raise UnsupportedPairError(f"CWE-{src_cwe} is not a lifecycle CWE (416/476)")

    site = _LIFECYCLE_SITE[src_cwe]
    idents = "argument.isIdentifier.name.l.distinct.toSet"
    lines = [
        _import_c(source_dir),
        f'val lifecycle = cpg.call.name("{site}").{idents}',
        f'val used = cpg.call.name("{_LIFECYCLE_USE}").{idents}',
    ]
    if src_cwe == 476:
        # 476 (null-deref) vs 416 (UAF) discriminator: a null-deref candidate is an alloc'd+used
        # pointer that is NOT freed (a freed pointer is a UAF, 416). Subtract the freed set so the
        # two lifecycle CWEs don't both fire on every malloc'd-then-freed object (the SILVER
        # precision-study 416<->476 confusion). See the build_multi_query lifecycle section.
        lines.append(f'val freed = cpg.call.name("{_LIFECYCLE_SITE[416]}").{idents}')
        expr = "lifecycle.diff(freed).intersect(used).size"
        lines.append(f'println("{_LIFECYCLE_MARKER}_{src_cwe}=" + {expr})')
    else:
        lines.append(f'println("{_LIFECYCLE_MARKER}_{src_cwe}=" + lifecycle.intersect(used).size)')
    return SilverQuery(src_cwe=src_cwe, sink_cwe=sink_cwe, script="\n".join(lines) + "\n")


def parse_lifecycle_result(src_cwe: int, sink_cwe: int, joern_output: str) -> LifecycleResult:
    """Parse the shared-variable count from a lifecycle Joern run.

    Raises ValueError if the marker is missing (query did not complete).
    """
    m = re.search(rf"{_LIFECYCLE_MARKER}_{src_cwe}=(\d+)", joern_output)
    if not m:
        raise ValueError(f"missing {_LIFECYCLE_MARKER}_{src_cwe} marker in Joern output")
    return LifecycleResult(src_cwe=src_cwe, sink_cwe=sink_cwe, shared_count=int(m.group(1)))
