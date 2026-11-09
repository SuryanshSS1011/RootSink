"""Assemble a kernel ChainRecord from syzbot evidence (plan sections 3, 5).

Ties together the syzbot signals into one chain record:
- SINK: from the archived KASAN report (chainforge.mining.syzbot_chains) — a real, witnessed
  out-of-bounds / use-after-free / null-deref, with the ordered call path (syscall -> fault).
- SOURCE: patch-gated from the fixing commit diff — an added integer-overflow guard -> CWE-190,
  or an added input-validation guard -> CWE-20 (chainforge.triage). The most-specific proven
  source wins (190 over 20, since an overflow is the proximate enabling weakness).
- TIER: syzbot's KASAN trace is a real execution witness of the sink, and a patch-proven source
  is strong causal evidence — but we did NOT re-run the vuln-vs-patched DIFFERENTIAL ourselves
  (kernel repro needs qemu/KVM, unavailable — see FINDINGS). So, consistent with how ARVO's
  patch-proven CWE-190 cases were treated, cap at SILVER when the source is patch-proven, BRONZE
  when the source is unconfirmed. Never GOLD (no self-run differential).

Pure assembly (no network): callers fetch the report/diff and pass text in.
"""

from __future__ import annotations

from .. import triage
from ..cwe import is_admissible_edge
from ..schema import (
    ChainLink,
    ChainRecord,
    CommitRange,
    ConfidenceTier,
    LinkEvidence,
    LinkRole,
    SanitizerReport,
)
from .syzbot_chains import KasanChain, parse_kasan_report

# Source-CWE specificity when both patch signals fire (overflow is the proximate root).
_SOURCE_PRIORITY = (190, 20)


def _source_cwe_from_diff(diff_text: str | None) -> tuple[int | None, str]:
    """Patch-gate the source CWE from a fix diff. Returns (cwe or None, evidence-note)."""
    if not diff_text:
        return None, "no fix diff"
    ovf, ovf_m = triage.patch_signals_overflow(diff_text)
    val, val_m = triage.patch_signals_input_validation(diff_text)
    if ovf:
        return 190, f"patch adds integer-overflow guard: {ovf_m[0] if ovf_m else ''}"
    if val:
        return 20, f"patch adds input-validation guard: {val_m[0] if val_m else ''}"
    return None, "no overflow/validation guard added in fix"


def assemble_syzbot_chain(
    extid: str,
    record_id: str,
    kasan_report: str,
    fix_diff: str | None,
    fix_commit_hash: str | None = None,
    project: str = "linux-kernel",
    cve: str | None = None,
) -> ChainRecord | None:
    """Build a kernel ChainRecord from a syzbot bug's KASAN report + fix diff.

    Returns None if the KASAN report has no recognizable sink, or the (source, sink) pair is
    not admissible. Tier: SILVER if the source is patch-proven, else BRONZE (sink witnessed,
    source a candidate).
    """
    kc = parse_kasan_report(kasan_report)
    if kc.sink_cwe is None:
        # No admissible sink (e.g. null-ptr-deref, excluded per PR-2) -> not a chain.
        return None

    # Source selection (PR-2):
    #  1. KASAN-derived lifecycle source (416 for use-after-free): the report itself WITNESSES
    #     the free->use link, so it is the source when 416->sink is admissible. SILVER (real
    #     KASAN witness of the source link; not GOLD since no self-run differential, PR-1).
    #  2. Otherwise (out-of-bounds / overflow): patch-gate the source from the fix diff (190/20);
    #     SILVER if proven, else BRONZE candidate (first admissible source, sink still witnessed).
    if kc.source_cwe is not None and is_admissible_edge(kc.source_cwe, kc.sink_cwe):
        source_cwe = kc.source_cwe
        source_note = f"KASAN witnesses {kc.kasan_type} (free->use); source CWE-{source_cwe}"
        tier = ConfidenceTier.SILVER
    else:
        source_cwe, source_note = _source_cwe_from_diff(fix_diff)
        if source_cwe is not None and not is_admissible_edge(source_cwe, kc.sink_cwe):
            source_cwe = None
        tier = ConfidenceTier.SILVER if source_cwe is not None else ConfidenceTier.BRONZE
        if source_cwe is None:
            source_cwe = _first_admissible_source(kc.sink_cwe)
            if source_cwe is None:
                return None  # no admissible source exists for this sink

    return _build_record(
        extid=extid,
        record_id=record_id,
        kc=kc,
        source_cwe=source_cwe,
        source_note=source_note,
        tier=tier,
        fix_commit_hash=fix_commit_hash,
        project=project,
        cve=cve,
    )


def _first_admissible_source(sink_cwe: int) -> int | None:
    from ..cwe import ADMISSIBLE_PAIRS

    srcs = sorted(s for s, d in ADMISSIBLE_PAIRS if d == sink_cwe)
    return srcs[0] if srcs else None


def _build_record(
    *,
    extid: str,
    record_id: str,
    kc: KasanChain,
    source_cwe: int,
    source_note: str,
    tier: ConfidenceTier,
    fix_commit_hash: str | None,
    project: str,
    cve: str | None,
) -> ChainRecord:
    aliases = [f"syzbot-{extid}"]
    if cve:
        aliases.append(cve)

    source_link = ChainLink(
        cwe_id=source_cwe,
        role=LinkRole.SOURCE,
        evidence=LinkEvidence(patch_hunk_ref=source_note),
    )
    sink_link = ChainLink(
        cwe_id=kc.sink_cwe,
        role=LinkRole.SINK,
        evidence=LinkEvidence(
            sanitizer_report_ref=(
                f"KASAN {kc.kasan_type} {kc.access_kind or ''} @ {kc.fault_func}:{kc.fault_line}"
            )
        ),
    )

    # The archived KASAN trace is a real (Google-run) execution witness of the sink.
    sanitizer_reports = [
        SanitizerReport(
            revision="vulnerable",
            sanitizer="kasan",
            log_ref=f"syzbot:{extid}:CrashReport",
            triggered=True,
        )
    ]

    return ChainRecord(
        id=record_id,
        aliases=aliases,
        project=project,
        language="C",
        ecosystem="linux-kernel",
        commit_range=CommitRange(fixed=fix_commit_hash),
        chain=[source_link, sink_link],
        chain_string=f"CWE-{source_cwe}->CWE-{kc.sink_cwe}",
        sanitizer_reports=sanitizer_reports,
        label_confidence_tier=tier,
        locality=None,  # derived from witnessed locations (evidence.locality), never assumed
        dataflow_evidence=f"kasan-call-path: {kc.ordered_link_summary}",
        provenance="syzbot",
        license="GPL-2.0",
    )
