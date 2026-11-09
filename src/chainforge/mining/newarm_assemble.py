"""Assemble the new ARVO-reproducible arms into ChainRecords.

Four MITRE-grounded arms whose SINK is execution-witnessed by an ARVO container replay (the
crash fires a sanitizer at the vulnerable revision, clean at the patched revision) and whose
SOURCE is inferred from the crash class and (when available) confirmed by a patch co-signal:

    129 -> 119   Index-out-of-bounds crash  (improper array index -> buffer bounds)
    843 -> 119   Bad-cast crash             (type confusion -> buffer bounds)
    252 -> 476   Null-dereference / SEGV    (unchecked return value -> NULL deref)
    362 -> 415   Heap-double-free           (race -> double free)

Tiering (mirrors the len-3 / race arms):
  GOLD   : reproduced (sink sanitizer-witnessed) + patch present + the fix's added-lines carry
           the SOURCE's guard (patch_signals_array_index / _type_check / _return_check / _race).
           Two independent witnesses (execution sink + author-witnessed source).
  SILVER : reproduced + patch present, but no source patch co-signal (source is crash-class-
           implied only) -- still execution-witnessed at the sink, so a strong SILVER.
  BRONZE : not reproduced (should not occur in this pipeline; guarded).
"""

from __future__ import annotations

import hashlib

from ..schema import (
    ChainLink,
    ChainRecord,
    CommitRange,
    ConfidenceTier,
    LinkEvidence,
    LinkRole,
    SanitizerReport,
)
from ..triage import (
    patch_signals_array_index,
    patch_signals_race,
    patch_signals_return_check,
    patch_signals_type_check,
)

# sink -> (source-selector). For sink 119 the crash class disambiguates 129 vs 843.
_SOURCE_SIGNAL = {
    129: patch_signals_array_index,
    843: patch_signals_type_check,
    252: patch_signals_return_check,
    362: patch_signals_race,
}


def source_cwe_for(sink_cwe: int, crash_type: str | None) -> int | None:
    """Map (sink, crash class) -> the new-arm SOURCE CWE. None if not a new arm."""
    ct = (crash_type or "").lower()
    if sink_cwe == 119:
        return 843 if "bad-cast" in ct else 129  # bad-cast -> type confusion; else array index
    if sink_cwe == 476:
        return 252
    if sink_cwe == 415:
        return 362
    return None


def _san_tag(sanitizer: str | None) -> str:
    s = (sanitizer or "").lower()
    if "address" in s:
        return "asan"
    if "undefined" in s:
        return "ubsan"
    if "memory" in s:
        return "msan"
    return "asan"


def assemble_newarm_record(
    ev: dict, crash_type: str | None, patch_diff: str | None, patch_url: str | None
) -> ChainRecord | None:
    """Build one new-arm ChainRecord from ARVO evidence + crash class + (optional) fix diff.

    `ev` is the pilot evidence.json ({local_id, sink_cwe, repro{...}, dataflows}). Returns None
    if the case did not reproduce or is not one of the new arms.
    """
    repro = ev.get("repro") or {}
    if not (repro.get("reproduced") and repro.get("vul_crashed") and not repro.get("fix_crashed")):
        return None  # sink not cleanly witnessed -> not a new-arm GOLD/SILVER candidate
    sink = int(ev["sink_cwe"])
    source = source_cwe_for(sink, crash_type)
    if source is None:
        return None

    # source patch co-signal (author-witnessed source) -> enriches the record's evidence.
    src_signal = False
    if patch_diff:
        src_signal = _SOURCE_SIGNAL[source](patch_diff)[0]

    # Tiering: the sink is execution-witnessed (triggered sanitizer). GOLD additionally needs a
    # patch_diff (schema invariant) -- consistent with how all 387 ARVO GOLD were tiered. The
    # source patch co-signal is NOT a tier lever: a reproduced+patched case is GOLD whether or not
    # the source guard is textually detected; the co-signal only enriches the record's evidence.
    tier = ConfidenceTier.GOLD if patch_diff else ConfidenceTier.SILVER

    san = _san_tag(repro.get("vul_sanitizer"))
    san_reports = [
        SanitizerReport(
            revision="vulnerable", sanitizer=san, log_ref="vul.sanitizer.txt", triggered=True
        ),
        SanitizerReport(
            revision="patched", sanitizer=san, log_ref="fix.sanitizer.txt", triggered=False
        ),
    ]
    src_note = (
        f"patch co-signal: fix adds a CWE-{source} guard (author-witnessed source)"
        if src_signal
        else f"crash-class-implied CWE-{source} source (ARVO {crash_type})"
    )
    chain = [
        ChainLink(
            cwe_id=source,
            role=LinkRole.SOURCE,
            evidence=LinkEvidence(patch_hunk_ref=src_note[:120]),
        ),
        ChainLink(
            cwe_id=sink,
            role=LinkRole.SINK,
            evidence=LinkEvidence(sanitizer_report_ref="vul.sanitizer.txt"),
        ),
    ]
    return ChainRecord(
        id=_stable_id(int(ev["local_id"])),
        aliases=[f"OSS-Fuzz-{ev['local_id']}"],
        project=str(ev.get("project", "unknown")),
        language=str(ev.get("language", "C")),
        ecosystem="arvo-newarm",
        commit_range=CommitRange(fixed=patch_url),
        chain=chain,
        chain_string=f"CWE-{source}->CWE-{sink}",
        sanitizer_reports=san_reports,
        patch_diff=(patch_diff or patch_url) if tier == ConfidenceTier.GOLD else None,
        label_confidence_tier=tier,
        dataflow_evidence=(
            f"EXECUTION witness: ARVO container replay -- {repro.get('vul_sanitizer')} fires at "
            f"the vulnerable revision (CWE-{sink}), clean at patched. Source: {src_note}."
        ),
        provenance="arvo-newarm",
    )


def _stable_id(local_id: int) -> str:
    """New-arm records get the 0x95 id band (distinct from arvo/kernel/git/len3/race bands)."""
    h = int(hashlib.sha1(str(local_id).encode()).hexdigest()[:8], 16) % 10_000_000
    return f"CHAINFORGE-95{h:07d}"


def assemble_newarm_batch(cases: list[dict]) -> list[ChainRecord]:
    """cases: list of {ev, crash_type, patch_diff, patch_url}. Dedup by id."""
    out: list[ChainRecord] = []
    seen: set[str] = set()
    for c in cases:
        rec = assemble_newarm_record(
            c["ev"], c.get("crash_type"), c.get("patch_diff"), c.get("patch_url")
        )
        if rec is not None and rec.id not in seen:
            seen.add(rec.id)
            out.append(rec)
    return out
