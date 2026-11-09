"""Per-record CHAINFORGE schema (plan section 5).

OSV-aligned where possible. A record describes one causally-ordered, dataflow-connected
multi-CWE chain, reproduced at both a vulnerable and a patched revision, with a
confidence tier reflecting the strength of the causal evidence (plan section 3).
"""

from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, Field, field_validator, model_validator

from .cwe import CWE_NAMES, validate_chain
from .mitre_chains import CWE_CATALOG_VERSION, classify_chain


class ConfidenceTier(StrEnum):
    """Tiered confidence in the causal-chain label (plan section 3).

    GOLD   = execution-witnessed (sanitizer trace of ordered links on the PoV) AND
             patch evidence (upstream guard resolves downstream sink), at both revisions.
    SILVER = static dataflow path (Joern/CodeQL) + ontology-admissible pair, no execution
             witness of both links.
    BRONZE = CWE-cooccurrence/heuristic (Red Hat `->` or NVD multi-CWE) with admissible
             ordering, no dataflow or execution.
    GOLD_UPSTREAM = execution-witnessed by the discovering project (syzbot), one-sided and not
             re-performed by us (PREREGISTRATION PR-3). Never returned by a filter on GOLD.
    """

    GOLD = "gold"
    GOLD_UPSTREAM = "gold-upstream"
    SILVER = "silver"
    BRONZE = "bronze"


class LinkRole(StrEnum):
    """Position of a CWE within a chain."""

    SOURCE = "source"
    INTERMEDIATE = "intermediate"
    SINK = "sink"


class Locality(StrEnum):
    """Where the root cause sits relative to the sink, from their witnessed locations
    (`evidence.locality`). SAME_FILE means one end's function is unknown."""

    IN_FUNCTION = "in-function"
    CROSS_FUNCTION = "cross-function"
    SAME_FILE = "same-file"
    CROSS_FILE = "cross-file"
    CROSS_PROJECT = "cross-project"


class CommitRange(BaseModel):
    """Git commit range for the vulnerability, OSV-style."""

    introduced: str | None = None
    fixed: str | None = None  # as the source gave it (sha, URL, or several shas)
    fix_commits: list[str] = []  # every 40-hex fix sha, canonical (normalize_fix_commits.py)
    repo: str | None = None  # repository the fix commits belong to


class LinkLocation(BaseModel):
    """Where in the source a link was witnessed.

    This is what makes a chain usable as step-level supervision: without a concrete
    file:line per link, the label is recoverable from record metadata alone (a leakage
    test predicts chain_string ~89% of the time), so a policy can score well without ever
    reading code. A line number is not predictable from metadata.

    Populated from execution witnesses, not inference: ASan/UBSan crash frames for
    container cases, and the symbolized alloc/free/use stages of a KASAN report for kernel
    cases (see mining.kasan_report).
    """

    file: str
    line: int
    function: str | None = None
    stage: str | None = Field(
        default=None,
        description="witness stage this came from, e.g. allocated|freed|use|crash",
    )


class LinkEvidence(BaseModel):
    """Evidence supporting one chain link's causal assertion."""

    dataflow_path: str | None = Field(
        default=None, description="Joern/CodeQL trace ref linking this link's source->sink"
    )
    sanitizer_report_ref: str | None = Field(
        default=None, description="Ref into sanitizer_reports witnessing this link"
    )
    patch_hunk_ref: str | None = Field(
        default=None, description="Ref to the fix hunk that guards this link"
    )
    location: LinkLocation | None = Field(
        default=None, description="execution-witnessed file:line for this link"
    )
    # The strongest evidence a source link can carry. Attestation says the fix adds a guard
    # NEAR the bug; this says the guard's absence CAUSED the sink, established by applying that
    # hunk alone to the vulnerable revision, rebuilding, and replaying the same PoV. The
    # unmodified rebuild must crash first, or a clean result would be indistinguishable from a
    # build that cannot reproduce.
    causal_proof: dict | None = Field(
        default=None,
        description="guard-ablation proof: {method, hunk, file, added, control, with_guard}",
    )
    # Legacy name; the content is a SUFFICIENT TESTED HUNK, not a minimized patch. The
    # developer's diff is split at its own @@ hunks (code files only, harness and test paths
    # dropped), the hunks are tried alone smallest first, and the first whose build runs the
    # same input with no sanitizer report is kept. Nothing is minimized below a hunk, a hunk
    # may hold several changes, and larger hunks are not tried once one succeeds.
    minimal_guard_patch: str | None = Field(
        default=None,
        description="smallest developer hunk that alone stopped the crash on this input "
        "(legacy name: sufficient tested hunk, not minimized)",
    )


class ChainLink(BaseModel):
    """One CWE in the ordered chain, with its role and per-link evidence."""

    cwe_id: int
    role: LinkRole
    evidence: LinkEvidence = Field(default_factory=LinkEvidence)
    # What this link is actually backed by, as a value rather than as prose to be parsed:
    # causally-proven | execution | attested | dataflow | inferred | none. Derived by
    # chainforge.evidence.classify_link and stamped here so a consumer can filter without
    # importing our code or regexing our free text.
    evidence_kind: str | None = Field(
        default=None, description="causally-proven|execution|attested|dataflow|inferred|none"
    )
    # Where this link's CWE LABEL came from, separate from what was observed about the link:
    # every CWE is assigned by a rule, and this names the strongest input that rule had
    # (chainforge.evidence.CWE_BASES). An intervention tests the site, not the CWE.
    cwe_basis: str | None = Field(
        default=None,
        description="guard-class|msan-origin|sanitizer-class|fix-pattern|crash-class-implied|"
        "dataflow-rank|advisory|catalogue-default",
    )
    # What the recorded site is (chainforge.evidence.site_kind): a tested repair site, a
    # sanitizer-reported origin, a crash site, a witnessed intermediate, or an annotated site no
    # run placed. Separate from evidence_kind, which is about the instance's CWE and claim.
    site_kind: str | None = Field(
        default=None,
        description="tested-repair-site|origin-site|crash-site|witnessed-site|annotated-site",
    )

    @field_validator("cwe_id")
    @classmethod
    def _known_cwe(cls, v: int) -> int:
        if v not in CWE_NAMES:
            raise ValueError(f"CWE-{v} is not in the 8-CWE catalog: {sorted(CWE_NAMES)}")
        return v


class SanitizerReport(BaseModel):
    """A sanitizer run log at one revision."""

    revision: str = Field(description="'vulnerable' or 'patched', or a commit hash")
    sanitizer: str = Field(description="asan|ubsan|msan")
    log_ref: str = Field(description="path/ref to the archived sanitizer log")
    triggered: bool = Field(description="whether the sanitizer fired at this revision")
    # Who actually ran the program. "self" = we executed it and archived the log here;
    # "upstream" = the observation was made and published by the discovering project
    # (syzbot) and we cite its permanent report URL. Both are execution witnesses, but
    # they are different claims and the dataset must not blur them: a consumer auditing
    # reproducibility needs to know which runs we can re-perform. Kernel cases are
    # necessarily "upstream" here - a patched-revision replay failed 0/20 twice.
    observed_by: str | None = Field(
        default=None, description="self|upstream - who performed the run"
    )
    # A run that witnesses a link OTHER than the sink, on a different build (the UBSan rebuild
    # that witnesses a CWE-190 intermediate). It is not a replay of the sink crash, so PR-3 I5
    # never counts it as the vulnerable side of the two-sided run.
    witnesses: str | None = Field(
        default=None, description="'intermediate' if this run is not the sink replay"
    )


class ChainRecord(BaseModel):
    """One CHAINFORGE dataset record."""

    id: str = Field(pattern=r"^CHAINFORGE-\d{4,}$")
    aliases: list[str] = Field(default_factory=list, description="CVE/GHSA/OSS-Fuzz/syzbot ids")

    project: str
    language: str = "C"
    ecosystem: str | None = None

    commit_range: CommitRange = Field(default_factory=CommitRange)

    chain: list[ChainLink] = Field(min_length=2)
    chain_string: str = Field(description="Red Hat-style, e.g. CWE-20->CWE-190->CWE-787")

    pov_input: str | None = Field(default=None, description="path/ref to triggering input")
    docker_image_ref: dict[str, str] = Field(
        default_factory=dict, description="{'vulnerable': ref, 'patched': ref}"
    )
    sanitizer_reports: list[SanitizerReport] = Field(default_factory=list)
    patch_diff: str | None = None

    label_confidence_tier: ConfidenceTier
    # Whether the witness is TWO-SIDED: the sanitizer fired at the vulnerable revision AND
    # ran clean at the patched one. Container (ARVO) cases get this from a differential
    # replay. Kernel (syzbot) cases generally cannot: re-running the reproducer on a patched
    # kernel needs a second kernel build, and a 20-case experiment re-fired 0/20 (old commits
    # fail to build with modern gcc, races do not reopen under emulation, and some bugs have
    # no C reproducer at all). Those records are still execution-witnessed - syzbot observed
    # and published a symbolized KASAN report - but the evidence is one-sided, and a consumer
    # filtering for causal-fix supervision needs to see that rather than infer it.
    differential_complete: bool | None = Field(
        default=None,
        description="True iff witnessed crashing at vulnerable AND clean at patched",
    )
    locality: Locality | None = None
    # Evaluation split. MUST be project-disjoint: linux-kernel alone is ~49% of GOLD, so a
    # random split puts the same project (often the same subsystem and bug family) in both
    # train and test, and every reported number is inflated by memorisation. Assigned whole
    # projects to folds, never individual records.
    split: str | None = Field(default=None, description="train|validation|test - project-disjoint")
    # An ALTERNATIVE held-out protocol, orthogonal to `split`. A project-disjoint split answers
    # "does this generalize to unseen code?"; it cannot answer "does this generalize to an
    # unseen KIND of chain?", because every arm appears in training. Marking those strata here
    # rather than folding them into `split` keeps the two protocols honest: they cannot both
    # hold at once (moving a whole arm to test would put its projects on both sides), so a
    # consumer picks one, excludes the marked records from training, and evaluates on them.
    #   unseen_arm  entire chain_string withheld -> tests chain-type generalization
    #   length3     length-3 records withheld    -> tests causal propagation past one hop
    eval_stratum: str | None = Field(
        default=None, description="unseen_arm|length3 - alternative held-out protocol"
    )
    # Date the fix landed upstream (ISO). Carried so a consumer can build a TEMPORAL split,
    # which is the only control for the contamination that matters here: base models are
    # pretrained on public GitHub including these projects, so a model may recall a fix rather
    # than derive it. Evaluating only on fixes that postdate a model's cutoff separates
    # generalization from recall. The cutoff is the consumer's choice, so we ship the date
    # rather than a precomputed fold.
    # The WEAKEST link's evidence kind - what the record as a whole can honestly claim.
    # SPECIFICATION R3 requires the weak link to be visible; a record with an
    # execution-witnessed sink and an inferred source is not an execution-witnessed chain, and
    # this is the field that says so. Selecting "every link at least execution-witnessed" is
    # the query an RL consumer needs and could not previously express.
    evidence_floor: str | None = Field(
        default=None, description="weakest evidence_kind across all links"
    )
    # STRUCTURAL difficulty, 0 easiest to 1 hardest, from chainforge.difficulty. It is a proxy,
    # never a pass rate: real difficulty for GRPO is the base policy's success probability, is
    # model- and time-dependent, and cannot be read off the data. Named `_proxy` so the two can
    # never be confused, and intended for stratified sampling so groups are not all-solved or
    # all-failed. Driven mostly by locality and chain length, so it is coarse by construction.
    difficulty_proxy: float | None = Field(default=None, description="0=easy..1=hard, structural")
    difficulty_band: str | None = Field(default=None, description="easy|medium|hard")
    # Optional per-record weight that evens out projects and multi-input bugs for sampling
    # (infra/verify/stamp_sampling_weight.py): 1 / (inputs in the duplicate group x sqrt(bugs in
    # the project)), within tier, rescaled to mean 1 per (tier, split). Harness-only.
    sampling_weight: float | None = Field(
        default=None, description="project-balancing sampling weight, mean 1 per tier and split"
    )
    # PR-12: the scorer works for this record. True when, in one scoring run, the unmodified
    # vulnerable build scored `crash` and the developer's fix scored `pass`; False with the
    # outcome pair in rl_scoring otherwise; None when not scored or the run never executed
    # (an infrastructure outcome, R10). Independent of the tier and the labels. Harness-only.
    rl_ready: bool | None = Field(default=None, description="scorer separates broken from fixed")
    rl_scoring: dict | None = Field(default=None, description="PR-12 outcome pair and resources")
    fix_date: str | None = Field(default=None, description="ISO date the fix commit landed")
    # NVD publication date, kept SEPARATE from fix_date rather than blended into one column.
    # They are different events and can be months apart: a fix lands, a CVE is published later.
    # Either can drive a temporal control, but only if the consumer knows which they filtered on.
    disclosure_date: str | None = Field(
        default=None, description="ISO date the CVE was published (NVD)"
    )
    dataflow_evidence: str | None = Field(
        default=None, description="Joern/CodeQL query + trace ref"
    )

    # Synthetic / length-3 stratum (plan section 5; adviser's tier-flagged flagship). A
    # synthetic record is composed/templated, not mined from a single real reproduced case;
    # it is CLEARLY flagged so a reviewer can subset it out. Its credibility comes from
    # link_validation: each constituent length-2 hop is verified against the real corpus.
    synthetic: bool = Field(
        default=False, description="true = composed/templated, not a single real mined case"
    )
    link_validation: list[str] = Field(
        default_factory=list,
        description="for synthetic chains: per-hop refs to the real length-2 records "
        "that validate each constituent edge (verified link-by-link)",
    )

    # MITRE chain-ontology grounding (computed in the validator, not user-set). Records the
    # epistemic status of each edge against the pinned CWE catalog: which of our chain's
    # source->sink pairs MITRE itself recognizes as causal chains (CanPrecede, directly or
    # transitively through the weakness hierarchy) vs. CHAINFORGE modeling edges.
    mitre_chain: dict = Field(
        default_factory=dict,
        description="computed: {catalog_version, all_recognized, any_catalog_only, edges[]}",
    )

    # Cross-references to other records describing the SAME underlying bug from a different
    # evidence angle (e.g. a GOLD execution-witnessed length-2 view and a SILVER patch-witnessed
    # length-3 view of one ARVO case). These share an alias but are kept as distinct records; the
    # link tells a consumer they are one bug seen two ways, NOT two independent findings.
    related_records: list[str] = Field(
        default_factory=list,
        description="ids of other records for the same bug (different evidence view)",
    )

    license: str | None = Field(default=None, description="per source project")
    provenance: str | None = None
    datasheet_ref: str | None = None

    @model_validator(mode="after")
    def _check_chain_consistency(self) -> ChainRecord:
        cwe_seq = [link.cwe_id for link in self.chain]

        # chain_string must match the ordered cwe_ids.
        expected = "->".join(f"CWE-{c}" for c in cwe_seq)
        if self.chain_string != expected:
            raise ValueError(
                f"chain_string {self.chain_string!r} does not match chain order {expected!r}"
            )

        # roles must be source ... intermediate* ... sink.
        roles = [link.role for link in self.chain]
        if roles[0] != LinkRole.SOURCE:
            raise ValueError("first link must have role=source")
        if roles[-1] != LinkRole.SINK:
            raise ValueError("last link must have role=sink")
        if any(r != LinkRole.INTERMEDIATE for r in roles[1:-1]):
            raise ValueError("interior links must have role=intermediate")

        # every consecutive CWE pair must be an admissible edge.
        v = validate_chain(cwe_seq)
        if not v.admissible:
            raise ValueError(
                f"chain {expected} is not admissible; inadmissible edges: {v.inadmissible_edges}"
            )

        # GOLD requires execution + patch evidence (plan section 3).
        if self.label_confidence_tier == ConfidenceTier.GOLD:
            if not any(r.triggered for r in self.sanitizer_reports):
                raise ValueError("GOLD tier requires at least one triggered sanitizer report")
            if not self.patch_diff:
                raise ValueError("GOLD tier requires patch evidence (patch_diff)")

        # A synthetic (composed/templated) chain is not a single execution-witnessed case, so
        # it cannot be GOLD. Its credibility is the per-hop validation against the real corpus:
        # require one link_validation entry per constituent edge (len(chain) - 1 hops).
        if self.synthetic:
            if self.label_confidence_tier == ConfidenceTier.GOLD:
                raise ValueError("synthetic chains cannot be GOLD (not execution-witnessed)")
            n_hops = len(self.chain) - 1
            if len(self.link_validation) != n_hops:
                raise ValueError(
                    f"synthetic chain needs one link_validation ref per hop "
                    f"({n_hops} expected, got {len(self.link_validation)})"
                )

        # Ground the chain in the MITRE ontology (computed, never user-set): classify each
        # source->sink edge as a MITRE-recognized causal chain vs. a CHAINFORGE modeling edge.
        cp = classify_chain(cwe_seq)
        self.mitre_chain = {
            "catalog_version": CWE_CATALOG_VERSION,
            "all_recognized": cp.all_mitre_recognized,
            "any_catalog_only": cp.any_catalog_only,
            "edges": [
                {"src": e.src, "dst": e.dst, "kind": e.kind, "detail": e.detail} for e in cp.edges
            ],
        }

        return self
