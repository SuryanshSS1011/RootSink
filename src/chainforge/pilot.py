"""Pilot orchestration: assemble ChainRecords and compute GATE-1 metrics (plan section 9).

The pilot draws chain candidates from ARVO's reproducible cases (the sink is already
execution-witnessed) and tries to establish an upstream source link, producing tiered
ChainRecords:

    GOLD   = sink reproduced (crash at vul, clean at fix) + patch present + source-link
             dataflow evidence. (Full execution witness of the chain end + patch corroborator.)
    SILVER = source->sink dataflow path found (Joern) but not the full execution witness.
    BRONZE = admissible sink CWE only (co-occurrence / ontology), no dataflow or execution.

This module is the pure-Python assembler: it consumes the JSON outputs of the ROAR-side
reproduction (infra/roar/arvo_repro.sh) and silver harness (infra/roar/silver_joern.sh)
plus an ArvoIndex row, and emits a validated ChainRecord and per-case evidence. Running the
ROAR steps and iterating over cases is driven by infra/roar/pilot_run.sh; keeping the
decision logic here makes tier assignment unit-testable offline.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .cwe import ADMISSIBLE_PAIRS
from .mining.arvo_index import ArvoIndexRow
from .schema import (
    ChainLink,
    ChainRecord,
    CommitRange,
    ConfidenceTier,
    LinkEvidence,
    LinkRole,
    SanitizerReport,
)

# Admissible source CWEs that can precede a given sink, from the catalog.
_SOURCES_FOR_SINK: dict[int, list[int]] = {}
for _s, _d in ADMISSIBLE_PAIRS:
    _SOURCES_FOR_SINK.setdefault(_d, []).append(_s)

# Source-CWE specificity for picking the chain root when several sources are dataflow-
# connected. Higher = more specific = preferred. CWE-20 (improper input validation) is the
# broad catch-all — it reaches almost every sink, so it is the LOWEST priority and acts as a
# fallback only. The memory-lifecycle roots (use-after-free, null-deref) and integer overflow
# are more specific root causes and win when they are dataflow-connected.
_SOURCE_SPECIFICITY: dict[int, int] = {
    416: 4,  # use-after-free (freed-pointer reuse)
    476: 3,  # null-pointer dereference (unchecked allocation)
    190: 2,  # integer overflow feeding a size
    20: 1,  # improper input validation (broad; fallback)
}


@dataclass
class ReproOutcome:
    """Parsed result of infra/roar/arvo_repro.sh (its result.json)."""

    reproduced: bool
    vul_crashed: bool
    fix_crashed: bool
    vul_sanitizer: str | None = None

    @classmethod
    def from_result_json(cls, d: dict) -> ReproOutcome:
        return cls(
            reproduced=bool(d.get("reproduced")),
            vul_crashed=bool(d.get("vul_crashed")),
            fix_crashed=bool(d.get("fix_crashed")),
            vul_sanitizer=d.get("vul_sanitizer") or None,
        )


@dataclass
class DataflowOutcome:
    """Parsed result of infra/roar/silver_joern.sh for one source->sink pair."""

    src_cwe: int
    sink_cwe: int
    has_dataflow: bool
    path_count: int = 0

    @classmethod
    def from_result_json(cls, d: dict) -> DataflowOutcome:
        return cls(
            src_cwe=int(d["src_cwe"]),
            sink_cwe=int(d["sink_cwe"]),
            has_dataflow=bool(d.get("has_dataflow")),
            path_count=int(d.get("path_count", 0)),
        )


@dataclass
class CandidateEvidence:
    """All evidence gathered for one ARVO chain candidate before tiering."""

    row: ArvoIndexRow
    sink_cwe: int
    repro: ReproOutcome | None = None
    dataflows: list[DataflowOutcome] = field(default_factory=list)
    has_patch: bool = False
    # CWE-190 patch-overflow evidence: the fix commit adds an integer-overflow guard, proving
    # the overflow was the enabling weakness (triage.patch_signals_overflow). This is a real
    # 190-source signal even when static dataflow cannot witness the cross-scope 190->sink link
    # and the UBSan execution witness is infra-blocked (see PREREGISTRATION PR-1) -> SILVER.
    patch_overflow_190: bool = False

    def best_source_dataflow(self) -> DataflowOutcome | None:
        """The most-specific source->sink dataflow with a positive path, if any.

        Chosen by SOURCE SPECIFICITY, not path count: the broad CWE-20 input-reader pattern
        has dataflow on almost every case (input reaches everything) and would otherwise
        mask the true root — a use-after-free (416) or overflow (190) that ALSO has a CWE-20
        path further upstream. A more specific root that is dataflow-connected is the real
        chain source; CWE-20 is the fallback only when no more-specific source connects.
        Ties in specificity break by higher path_count.
        """
        positive = [d for d in self.dataflows if d.has_dataflow and d.sink_cwe == self.sink_cwe]
        if not positive:
            return None
        return max(positive, key=lambda d: (_SOURCE_SPECIFICITY.get(d.src_cwe, 0), d.path_count))

    def effective_source_cwe(self) -> int | None:
        """The chain's true source CWE, or None if undeterminable.

        A PATCH-PROVEN CWE-190 overflow outranks any dataflow: the fix adding an overflow
        guard is direct evidence the overflow is the root, and it beats even a positive CWE-20
        dataflow (untrusted input reaches the overflowing arithmetic too, but 190 is the
        proximate enabling weakness the maintainer fixed). Otherwise use the most-specific
        positive dataflow's source.
        """
        if self.patch_overflow_190 and (190, self.sink_cwe) in ADMISSIBLE_PAIRS:
            return 190
        df = self.best_source_dataflow()
        return df.src_cwe if df is not None else None

    def copresent_source_dataflows(self) -> list[DataflowOutcome]:
        """ALL independent positive source->sink dataflows for this reproduced sink.

        A single reproduced PoV can carry MULTIPLE co-present chains: e.g. a heap-write whose
        dataflow independently connects BOTH a use-after-free (416) AND a null-deref-prone
        pointer (476) to the write, via DISJOINT node sets (the 416<->476 discriminator in
        silver.py subtracts the freed set from the 476 set, so a 476 hit is not a re-labelled
        416). The single-source picker (best_source_dataflow) keeps only the most-specific and
        DISCARDS the others -- but those others are real, execution-witnessed chains. This
        returns every distinct source, most-specific first, so the assembler can emit each as a
        co-present record (cross-linked). One source per src_cwe (dedup); CWE-20 is included only
        when it is the SOLE source (it is the broad catch-all and co-present-20 alongside a
        specific root would be double-labelling the same input path, not a distinct chain).
        """
        positive = [d for d in self.dataflows if d.has_dataflow and d.sink_cwe == self.sink_cwe]
        if not positive:
            return []
        by_src: dict[int, DataflowOutcome] = {}
        for d in positive:
            cur = by_src.get(d.src_cwe)
            if cur is None or d.path_count > cur.path_count:
                by_src[d.src_cwe] = d
        specific = {s: d for s, d in by_src.items() if s != 20}
        chosen = specific if specific else by_src  # drop bare-20 when a specific root co-fires
        return sorted(
            chosen.values(),
            key=lambda d: (_SOURCE_SPECIFICITY.get(d.src_cwe, 0), d.path_count),
            reverse=True,
        )


def assign_tier(ev: CandidateEvidence) -> ConfidenceTier:
    """Assign a confidence tier from gathered evidence (plan section 3).

    GOLD requires the sink reproduced (crash@vul, clean@fix) AND a patch AND a source-link
    dataflow (so the chain, not just the sink, is evidenced). SILVER requires a source-link
    dataflow. Otherwise BRONZE.
    """
    reproduced = ev.repro is not None and ev.repro.reproduced

    # Patch-proven CWE-190 cases: the source is 190 (effective_source_cwe), and any coincident
    # CWE-20 dataflow does NOT witness the cross-scope 190->sink link, so it can neither promote
    # to GOLD nor stand as a 190 SILVER dataflow-witness. Tier these by their OWN evidence:
    #   reproduced -> SILVER (patch + sink reproduction; 190 link unwitnessed, PR-1)
    #   not reproduced -> BRONZE (patch co-occurrence only; no execution, no 190-link witness)
    # Handled before the generic dataflow branch so the CWE-20 path can't mislabel the case.
    if ev.patch_overflow_190 and (190, ev.sink_cwe) in ADMISSIBLE_PAIRS:
        return ConfidenceTier.SILVER if reproduced else ConfidenceTier.BRONZE

    df = ev.best_source_dataflow()
    if reproduced and ev.has_patch and df is not None:
        return ConfidenceTier.GOLD
    if df is not None:
        return ConfidenceTier.SILVER
    return ConfidenceTier.BRONZE


def build_chain_record(
    ev: CandidateEvidence, record_id: str, commit_range: CommitRange | None = None
) -> ChainRecord:
    """Assemble a validated 2-link ChainRecord for a candidate.

    The source CWE is taken from the best positive source->sink dataflow when present;
    for a BRONZE candidate with no dataflow, the first admissible source for the sink is
    used (co-occurrence only). Raises if no admissible source exists for the sink.
    """
    # effective_source_cwe() encodes the priority: patch-proven CWE-190 > most-specific
    # positive dataflow. Fall back to the first admissible catalog source (co-occurrence only).
    source_cwe = ev.effective_source_cwe()
    if source_cwe is None:
        sources = _SOURCES_FOR_SINK.get(ev.sink_cwe)
        if not sources:
            raise ValueError(f"no admissible source CWE for sink CWE-{ev.sink_cwe}")
        source_cwe = sorted(sources)[0]

    tier = assign_tier(ev)

    df = ev.best_source_dataflow()
    dataflow_ref = None
    if ev.patch_overflow_190 and source_cwe == 190:
        dataflow_ref = "patch:overflow-guard-added (cross-scope; static/UBSan witness N/A, PR-1)"
    elif df is not None:
        dataflow_ref = f"joern:reachableBy paths={df.path_count}"

    source_link = ChainLink(
        cwe_id=source_cwe,
        role=LinkRole.SOURCE,
        evidence=LinkEvidence(dataflow_path=dataflow_ref),
    )
    sink_link = ChainLink(
        cwe_id=ev.sink_cwe,
        role=LinkRole.SINK,
        evidence=LinkEvidence(
            sanitizer_report_ref=(
                "vul.sanitizer.txt" if ev.repro and ev.repro.vul_crashed else None
            )
        ),
    )

    sanitizer_reports: list[SanitizerReport] = []
    patch_diff = None
    if ev.repro is not None:
        sanitizer_reports.append(
            SanitizerReport(
                revision="vulnerable",
                sanitizer=_san_tag(ev.repro.vul_sanitizer),
                log_ref="vul.sanitizer.txt",
                triggered=ev.repro.vul_crashed,
            )
        )
        sanitizer_reports.append(
            SanitizerReport(
                revision="patched",
                sanitizer=_san_tag(ev.repro.vul_sanitizer),
                log_ref="fix.sanitizer.txt",
                triggered=ev.repro.fix_crashed,
            )
        )
    # GOLD requires patch_diff in the schema; supply a marker when a patch is known.
    if ev.has_patch and tier == ConfidenceTier.GOLD:
        patch_diff = ev.row.patch_url or "patch:present"

    chain_string = f"CWE-{source_cwe}->CWE-{ev.sink_cwe}"
    aliases = [f"OSS-Fuzz-{ev.row.local_id}"]

    return ChainRecord(
        id=record_id,
        aliases=aliases,
        project=ev.row.project or "unknown",
        language="C" if (ev.row.language or "").lower() == "c" else "C++",
        commit_range=commit_range or CommitRange(fixed=ev.row.fix_commit),
        chain=[source_link, sink_link],
        chain_string=chain_string,
        docker_image_ref={"vulnerable": ev.row.vul_image, "patched": ev.row.fix_image},
        sanitizer_reports=sanitizer_reports,
        patch_diff=patch_diff,
        label_confidence_tier=tier,
        dataflow_evidence=dataflow_ref,
        provenance="arvo",
    )


def _san_tag(sanitizer_name: str | None) -> str:
    """Normalize a sanitizer name to the asan|ubsan|msan tag used in SanitizerReport."""
    s = (sanitizer_name or "").lower()
    if "undefined" in s or "ubsan" in s:
        return "ubsan"
    if "memory" in s or "msan" in s:
        return "msan"
    return "asan"


@dataclass
class GateMetrics:
    """GATE-1 metrics over a pilot batch (plan section 9: >=50% SILVER+, >=20 GOLD)."""

    total: int
    gold: int
    silver: int
    bronze: int

    @property
    def silver_or_better(self) -> int:
        return self.gold + self.silver

    @property
    def silver_or_better_frac(self) -> float:
        return self.silver_or_better / self.total if self.total else 0.0

    @property
    def passes_gate1(self) -> bool:
        """GATE 1: >=50% reach SILVER+ and >=20 reach GOLD (plan section 9)."""
        return self.silver_or_better_frac >= 0.5 and self.gold >= 20


def compute_metrics(tiers: list[ConfidenceTier]) -> GateMetrics:
    """Tally tier counts into GATE-1 metrics."""
    return GateMetrics(
        total=len(tiers),
        gold=sum(t == ConfidenceTier.GOLD for t in tiers),
        silver=sum(t == ConfidenceTier.SILVER for t in tiers),
        bronze=sum(t == ConfidenceTier.BRONZE for t in tiers),
    )


def evidence_from_json(row: ArvoIndexRow, evidence_json: dict) -> CandidateEvidence:
    """Reconstruct a CandidateEvidence from a pilot_case.sh evidence.json + index row."""
    repro_d = evidence_json.get("repro")
    repro = ReproOutcome.from_result_json(repro_d) if repro_d else None
    dataflows = [DataflowOutcome.from_result_json(d) for d in evidence_json.get("dataflows", [])]
    return CandidateEvidence(
        row=row,
        sink_cwe=int(evidence_json["sink_cwe"]),
        repro=repro,
        dataflows=dataflows,
        has_patch=bool(row.patch_url or row.fix_commit),
        patch_overflow_190=bool(evidence_json.get("patch_overflow_190")),
    )


def assemble_batch(
    evidences: list[CandidateEvidence], id_start: int = 1
) -> tuple[list[ChainRecord], GateMetrics]:
    """Assemble ChainRecords from a batch of evidence and compute GATE-1 metrics.

    Candidates whose sink has no admissible source (e.g. a source-only CWE mislabeled as a
    sink) are skipped rather than fabricated. Records are numbered CHAINFORGE-<id_start...>.
    """
    records: list[ChainRecord] = []
    tiers: list[ConfidenceTier] = []
    next_id = id_start
    for ev in evidences:
        record_id = f"CHAINFORGE-{next_id:04d}"
        try:
            rec = build_chain_record(ev, record_id)
        except ValueError:
            continue  # sink not admissible as a chain terminus; not a valid chain
        records.append(rec)
        tiers.append(rec.label_confidence_tier)
        next_id += 1
    return records, compute_metrics(tiers)
