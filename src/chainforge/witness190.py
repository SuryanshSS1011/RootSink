"""CWE-190 GOLD predicate: decide whether an execution witness earns GOLD (PR-1 oracle switch).

ASan alone reports only the DOWNSTREAM memory error, not the integer overflow. To witness CWE-190
AS THE SOURCE we run the PoV under combined ASan + UBSan in RECOVER mode (see witness_190.sh), so a
single trace contains BOTH the UBSan integer-overflow report AND the downstream ASan memory
violation, IN EXECUTION ORDER. This module turns such a trace (plus repro outcome) into a tier
decision, so the rule lives in ONE tested place instead of inline bash.

GOLD-190 requires ALL of (mirrors ChainRecord's GOLD invariant + PR-1):
  1. overflow witnessed  — a UBSan integer-overflow runtime error appears in the vulnerable trace
  2. sink witnessed      — an ASan memory violation (OOB write/read) appears in the same trace
  3. ordered             — the overflow appears BEFORE the sink (overflow ENABLES the sink)
  4. reproduced          — vulnerable revision crashed, patched revision clean (differential)
  5. patch present       — a fix/patch exists (the upstream overflow guard)
Anything less that still has the overflow signal is SILVER (source witnessed, chain not fully
ordered/differential); no overflow signal at all is not a 190 witness (BRONZE/exclude upstream).
"""

from __future__ import annotations

import re
from dataclasses import dataclass

# UBSan integer-overflow markers (signed/unsigned wrap, shift, negation, range).
_OVERFLOW_RE = re.compile(
    r"runtime error:.*?(overflow|cannot be represented|outside the range|shift)"
    r"|integer overflow|negation of",
    re.IGNORECASE,
)
# ASan memory-violation (the downstream sink).
_SINK_RE = re.compile(
    r"(?:ERROR: )?AddressSanitizer[\s\S]*?"
    r"(heap-buffer-overflow|stack-buffer-overflow|global-buffer-overflow|out-of-bounds)",
    re.IGNORECASE,
)


@dataclass
class Witness190:
    """Decision + evidence for one CWE-190 execution-witness attempt."""

    local_id: int
    witnessed_overflow: bool
    witnessed_sink: bool
    ordered: bool  # overflow position < sink position in the trace
    reproduced: bool  # vulnerable crashed AND patched clean
    has_patch: bool
    overflow_snippet: str | None = None
    sink_kind: str | None = None

    @property
    def tier(self) -> str:
        """GOLD only when the ordered overflow->sink is witnessed AND differential + patched."""
        if (
            self.witnessed_overflow
            and self.witnessed_sink
            and self.ordered
            and self.reproduced
            and self.has_patch
        ):
            return "gold"
        # Overflow seen but not a complete ordered/differential/patched chain -> SILVER.
        if self.witnessed_overflow:
            return "silver"
        return "bronze"

    @property
    def gold_eligible(self) -> bool:
        return self.tier == "gold"


def classify_witness(
    local_id: int,
    trace: str,
    *,
    reproduced: bool,
    has_patch: bool,
) -> Witness190:
    """Classify a combined ASan+UBSan-recover trace into a CWE-190 witness decision.

    `trace` is the full console/sanitizer log from the vulnerable-revision PoV run. `reproduced`
    is the differential outcome (vul crashed, patched clean) from the repro step; `has_patch` is
    whether a fix commit / patch diff is known.
    """
    ovf = _OVERFLOW_RE.search(trace)
    sink = _SINK_RE.search(trace)
    ovf_pos = ovf.start() if ovf else None
    sink_pos = sink.start() if sink else None
    ordered = ovf_pos is not None and sink_pos is not None and ovf_pos < sink_pos
    return Witness190(
        local_id=local_id,
        witnessed_overflow=ovf is not None,
        witnessed_sink=sink is not None,
        ordered=ordered,
        reproduced=reproduced,
        has_patch=has_patch,
        overflow_snippet=(ovf.group(0)[:120] if ovf else None),
        sink_kind=(sink.group(1).lower() if sink else None),
    )
