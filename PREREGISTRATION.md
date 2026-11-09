# CHAINFORGE Pre-Registered Decisions

Pre-committed labeling decisions, recorded BEFORE seeing the results they govern, to keep
tier assignment honest (the demotion-discipline principle: criteria are fixed before we see
which records meet them, never relaxed for records that fail).

This is the rule log the paper cites. Entries are kept as written. Short hexadecimal ids in it
(8-character commits, 12-character release ids) name states of the private development
repository and its dataset, which are not published; they identify the order of events, not files
a reader can retrieve. The public release is identified by its version number and DOI.

## PR-1: CWE-190 cross-scope cases — oracle switch, not bar relaxation (2026-07-22)

**Context.** 21 patch-backed real CWE-190 cases reproduce, but Joern's static dataflow cannot
witness the 190->sink link because it is interprocedural / cross-scope (the ~66%-cross-scope
structure the plan's thesis is about; concretely verified on jq 42531297, where the overflow
`len * n` feeds an allocation in another function and the OOB write happens later still).

**Decision (locked before running the witness pass).** Do NOT relax GOLD. Instead switch the
oracle from static dataflow to EXECUTION, per the project's own thesis (when static analysis
is foreclosed on a CWE, the driver + sanitizers witness the non-local link that shape-matching
cannot see). Reproduce these 21 under combined ASan + UBSan in RECOVER mode
(`-fsanitize-recover`, `halt_on_error=0`) so a single execution can report the CWE-190 integer
overflow AND the downstream CWE-787/125 memory violation IN EXECUTION ORDER.

- A case whose trace witnesses **overflow-then-sink in order → GOLD** (under the unmodified
  criterion: execution-witnessed ordered links + patch corroborator).
- A case that does **NOT** witness the ordered sequence → **SILVER** (strong patch + repro
  evidence, but no link witness). Never GOLD-by-patch-alone.

**Caveats acknowledged up front (expected attrition; not all 21 will convert):**
- UBSan must be in recover mode or it aborts at the overflow and the write is never reached.
- Unsigned wraparound is not UB — needs the explicit unsigned-overflow check, which also fires
  on intentional wraparound (hashing/checksums/PRNGs); such reports are manually ruled benign.
- Overflows inside uninstrumented dependencies won't witness.

**Reported as results:** the witness yield on these 21 (how often execution rescues what static
analysis forecloses) is a first-class dataset metric and empirical support for the escape-route
claim. Real 190-hop witnesses also close the length-3 validation gap (synthetic 20->190->787
spines can then be validated link-by-link against real middle hops).

**OUTCOME (2026-07-23).** The UBSan overflow witness was NOT reachable on ROAR/Apptainer: all 21
candidates are ASan-built (0 UBSan-native) and `arvo compile` (the rebuild that would add UBSan)
fails under Apptainer's rootless model — the OSS-Fuzz build needs Docker (see FINDINGS). Running
pre-built PoVs witnesses only the ASan sink, never the overflow. Per this pre-registration, with
no ordered-link witness the 21 are labeled **SILVER** (real, reproduced, patch-proven CWE-190
chains; strong patch + sink-reproduction evidence, overflow link unwitnessed) — NOT GOLD, and
explicitly NOT relaxed to GOLD-by-patch-alone. The GOLD path (single-trace overflow-then-sink)
remains open as future work on a Docker-capable host. Witness yield here = 0/21 GOLD by execution
= a measured (infrastructure-bounded) result, honestly reported.

## PR-2: syzbot kernel UAF / null-deref chain modeling (2026-07-24)

Pre-committed BEFORE the syzbot harvest, split by bug class (per adviser). The rule is fixed
here so it is never a per-record judgment call.

**UAF Write -> CWE-416 -> CWE-787 (clean, unmodified catalog).** A "slab/global/stack-use-
after-free Write" IS the structure the existing admissible edge 416->787 already models: the
freed-pointer reuse (416) enabling the out-of-bounds write (787). No catalog change.

**UAF Read -> CWE-416 -> CWE-125 (accepted MODELING CONVENTION, documented).** A UAF read reads
freed-but-(often)-in-bounds memory, so CWE-125 (out-of-bounds read) is an APPROXIMATION of the
sink, not self-evident. We adopt 416->125 as a stated convention (the freed-pointer reuse
enabling a read), and add 416->125 as an admissible edge alongside 416->787. This is applying
the existing "lifecycle-source -> memory-access-sink" model to the read case, NOT inventing a
new role for 416 — 416 stays a SOURCE. Documented in the datasheet as a convention.

**null-ptr-deref -> NOT forced.** A plain null dereference crashes AT the deref; nothing
downstream is enabled, so it does not decompose into an admissible source->sink chain (and the
real cause is CWE-690 unchecked-return->null-deref, not input->null-deref — we do NOT assert a
20->476 edge the ontology doesn't support). null-ptr-deref bugs are EXCLUDED from the chain
dataset (held as a separate non-chain stratum if wanted later). The existing 476->787 rows
(from ARVO) capture a genuinely different structure (a null-adjacent computation whose result
lands OOB), not a plain null-deref crash.

**KASAN link-witness predicate (pre-committed).** A syzbot record's SINK is "witnessed" iff the
KASAN report is present AND its bug type + access kind map to an admissible sink CWE per the
above. The KASAN report inherently shows the faulting (use/write) site with a stack trace; for
UAF it also reports the free site. Access kind (Read/Write) determines the sink CWE (125/787).
We do NOT additionally require the report to prove the access was out-of-bounds relative to the
original allocation (KASAN's slab-out-of-bounds vs use-after-free typing already distinguishes
these); this is stated so the predicate is fixed, not decided per record. Tier stays SILVER
(patch-proven source) / BRONZE (source candidate) — never GOLD (no self-run differential; PR-1).

**Cross-scope note (why this row matters):** kernel UAF free-site and use-site are frequently in
different functions/subsystems reached via a syscall sequence — strong evidence for the project's
cross-scope thesis. The KASAN call path (bug_path) captures this ordering.

## PR-3: Integrity rules for the MSR 2027 release (2026-10-01)

**Amends PR-2.** PR-2 said syzbot records are "never GOLD (no self-run differential)".
`promote_syzbot.py` later promoted 652 of them to GOLD without amending PR-2. That was a
pre-registration violation; this amendment restores PR-2 and states how such a record can earn GOLD.

**Disclosure.** The aggregate effect of these rules was measured before they were locked:
applied strictly they leave 504 of 1,539 GOLD rows (1,127 if upstream-witnessed kernel records
form their own class). No rule below was chosen or adjusted to move that number, and none will
be adjusted after per-record outcomes of the re-runs are seen. If a rule proves wrong, it is
amended here, dated, with the reason — never silently.

**Rules.** A record is GOLD only if ALL hold:

- **I1 One crash, one record.** Byte-identical rows are removed. A crash (same alias) carrying
  several chains with mutually exclusive sources keeps one record; the others go to
  `dropped.jsonl` with the reason. Which one is kept: first, views consistent with the crash's
  own sanitizer report (source per I2, sink per access direction); among those, the pipeline's
  declared source priority (416 > 476 > 190 > 20). Never which one is better evidenced.
  Exception: views that differ in evidence angle, not in claim (same source and sink, len-2 vs
  len-3), stay cross-linked. *(Wording corrected 2026-10-01 before any rule was applied: the
  first draft ranked by priority alone, which would have kept a view I2 then demotes over a
  consistent one of the same crash.)*
- **I2 The source may not contradict the sink's own sanitizer report.** For self-run records
  with a statically assigned source: CWE-416 requires a use-after-free report, CWE-476 a NULL
  dereference. Otherwise SILVER. The source can re-earn GOLD only by guard ablation, which then
  names the source from the proven hunk.
- **I3 The patch must be able to carry the guard** (`guard_evidence_defect` is None): not
  harness/doc/build-only, not truncated, the commit the record names.
- **I4 Length-3 needs a witnessed intermediate** (evidence kind `execution` or
  `causally-proven`), per the 2026-08-04 len-3 rule. PR-1's "never GOLD-by-patch-alone" applies.
- **I5 Two-sided, self-run, archived.** `differential_complete` is true, the vulnerable run
  crashed, the patched run is clean, both logs are in the repository, and we ran both.
  - A patched run is *clean* only if the input demonstrably executed (libFuzzer's
    `Executed /tmp/poc`; for the kernel, the environment came up and the reproducer ran for the
    full window or exited). Silence is not cleanliness (R10).
  - Kernel: vulnerable = `fix^`, patched = `fix`, both from the fix's own tree; the KASAN report
    at `fix^` must match the syzbot bug (type + function); the patched kernel is booted twice.
  - ARVO: the vulnerable crash signature (class + first project frame) must match the shipped
    log; the patched image is run twice.
- **I6 A causal proof on a non-guard path is withdrawn** (`is_non_guard_path`), and the link's
  evidence kind is recomputed from what remains.

Records failing only I5 because the witness is upstream's (syzbot ran it; we could not) get tier
`gold-upstream`: execution-witnessed, one-sided, not re-performed by us. A filter on
`tier == "gold"` therefore returns only records meeting every rule above.

**Reported as results:** the count removed by each rule, the re-run reproduction rate with
Wilson CI, and every record whose tier changed, in `corrections_changelog.jsonl` with its rule id.

## PR-4: What a causal proof establishes about the source CWE (2026-10-02)

**Problem.** Guard ablation shows that applying one hunk of the fix, alone, silences the crash.
That locates the missing guard; it does not say which weakness the source is. The attach step
credited the proof to whatever CWE already sat in the source slot, so a proof could "confirm" a
CWE-416 label with a bounds check. Locked before any of the 2026-10-01 batch's proving hunks were
classified.

**Rule.** The source CWE is derived from what the proving hunk's ADDED lines check, by a fixed
classifier (`chainforge.evidence.guard_class`), precedence top-down:

| guard adds | source |
|---|---|
| an integer-overflow check (`*_MAX` bound on arithmetic, `__builtin_*_overflow`, `check_*_overflow`) | CWE-190 |
| a NULL test of a pointer before use | CWE-476 |
| a lifetime fix (clearing a pointer after free, a reference count, moving or removing a free) | CWE-416 |
| initialisation of a value or buffer (`memset`, `= {0}`, zero-init) | CWE-456 |
| a comparison of an index against a count/size, sink CWE-119 | CWE-129 |
| any other rejection or clamp of input (bounds, length, early return/error) | CWE-20 |
| none of the above | undetermined |

- The derived source must form an admissible pair with the record's sink. If it does, the link
  becomes `causally-proven` with that CWE; if it differs from the current label the chain is
  relabelled and logged. If it is inadmissible or undetermined, the proof is kept as
  `guard_site_proof` (a proven site, no CWE credited) and the link's kind is unchanged.
- Applies to every proof in the release, including the 128 attached before this rule.
- The classifier's output is validated by the inter-rater study (annotators label the source
  CWE blind); its agreement is reported. If the study shows the rule is wrong, it is amended
  here, dated.

**Implementation note (2026-10-02, before any record in the release changed).** The first
implementation of the CWE-20 row matched only a comparison inside a single-line `if (...)`. A
dry run left 118 of 215 proofs undetermined, and reading a sample showed most were guards the
row's own wording covers — loop bounds (`i + 3 < nbytes`), check macros
(`VerifyOrExit(len <= sizeof ...)`), conditions continued across lines, a bare `continue` that
skips bad input. The matcher was widened to that wording (any relational comparison outside
`->`, shifts and template brackets; clamps; check macros; bare error exits), with tests written
from textbook guard shapes rather than from these hunks. The table itself is unchanged. This note
discloses that the change followed a look at the dry-run outcome.

**Known coverage gaps (2026-10-02), deliberately NOT patched on outcomes.** Applied as locked,
50 of the 128 earlier proofs lose CWE credit and are kept as `guard_site_proof`: 18 `129→119`
guards compare an index not named as one (classed CWE-20, inadmissible toward 119); 4 length-3
proofs are overflow guards, which evidence the intermediate CWE-190 link that PR-4 does not
address; 3 `252→476` guards check a return value, for which the table has no row; 25 match no
class. Each is a candidate amendment. Whether to make it is decided by the inter-rater study's
blind source labels on these records, not by how many proofs it would restore.

## PR-5: Which records are multi-weakness chains (2026-10-07)

**Problem.** SPECIFICATION R2 says the stages of one weakness are not a chain, yet PR-2 adopts
`416 → 787/125` as a declared convention: the "source" is the use-after-free and the "sink" is the
same freed-memory access. Counting those as chains overstates the headline.

**Rule.** Every record carries `chain_kind`:
- the tail `CWE-416 → CWE-125|CWE-787` is one weakness in two stages (the sink IS the freed-memory
  access), so it contributes one weakness, not two;
- `chain_kind = "multi-weakness"` if the chain then holds ≥ 2 distinct weaknesses, else
  `"stage-decomposition"`. So `416→787` is a stage-decomposition; `362→416→787` (a race enabling a
  use-after-free) is multi-weakness.
- The paper's chain counts use `multi-weakness` only; stage-decompositions stay in the release,
  subsettable, as the declared PR-2 convention.

**Considered and not adopted:** treating `456 → 457` (missing initialisation → use of an
uninitialised value) as a stage-decomposition. MITRE lists 456 CanPrecede 457 as distinct entries,
and the shape — an omission at one site enabling a consequence at another — is the same as
`252 → 476` and `20 → 125`, which are chains by any reading. It stays multi-weakness; the paper
reports its count separately so a reader who disagrees can subset it out.

**Kernel intermediates.** In a `362 → 416 → *` record the CWE-416 link is execution-witnessed when
our own run's KASAN report is a use-after-free (it records the allocation, free and use stacks);
that report is then attached to the link. This is what PR-3 I4 asks of a length-3 intermediate.

**PR-5 general rule (2026-10-20), replacing the case-by-case list.** The adviser asked for one
definition. Two consecutive CWEs are two stages of one defect when both classify the same
faulting operation, the one the sanitizer reports; they are two weaknesses when the first is
defined by a different, earlier operation that enables the second, such as a missing check (20,
129, 252), a computation (190), a missing initialisation (456) or a race (362). Recorded sites do
not decide it: a 416 instance placed at the free still names the use. Applied as
`evidence.STAGE_PAIRS`, re-stamped on every rebuild. `416 → 125|787` stays a stage-decomposition and
`456 → 457` stays multi-weakness, as before. `843 → 119` changes: the incompatibly typed access is
itself the bounds error, and the source is implied by the same Bad-cast report, so it is one defect.
That moves 24 GOLD records and 1 SILVER record from multi-weakness to stage-decomposition, and no
tier changes. The outcome was counted in a dry run before applying; the rule follows the
definition, not the count. Logged as `evidence-kind-restamp` (`chain_kind`). The `476 → 787` edge
stays multi-weakness. Its CWE-476 label comes from the PR-4 classifier naming a null-check guard,
and the omitted check is a different operation from the out-of-bounds write.

**PR-5 grounding (2026-10-07).** The `456 → 457` decision follows MITRE, not our reading: CWE-456
lists "CanPrecede CWE-457" in the Research Concepts view (View-1000), checked on
https://cwe.mitre.org/data/definitions/456.html. Of the edges in the catalogue, only
`416 → 787`, `416 → 125` and `476 → 787` are not MITRE relationships (`mitre_chain.edges[].kind
== "catalog-only"`); the first two are the PR-5 stage-decompositions, and `476 → 787` is reported
as a declared modeling edge.

**Further coverage gaps (2026-10-07, second ablation batch), again not patched on outcomes.** Of
64 new proofs, most stay `guard_site_proof`: 19 `129→119` index checks classed CWE-20; 9
`843→119` and 3 `252→476` guards, which the table has no row for; and 28 hunks toward 125/787
that are not guards at all in the table's sense — value corrections (a terminator write, a width
rounding), removal-only hunks, and check macros the matcher does not name (e.g.
`NDR_PULL_NEED_BYTES`). A proven site is still localised on the source link (stage "proven guard
site; CWE not established"); it credits no CWE.

**PR-3 clarification (2026-10-08).** I5's "the vulnerable run crashed with the witnessed sink" was
implemented as "a triggered vulnerable-side report exists"; it did not check that the sink LINK is
attributed to that report. Four GOLD records had a sink located only from ARVO's archived crash
output. The contract now also requires the sink link to be execution-witnessed; a sink is
attributed to our own vulnerable log when that log has a frame at the sink's file:line
(`backfill_functions.py`). All four met it on attribution; no tier changed.

**PR-3 implementation fixes (2026-10-08, second), rules unchanged.** Two places where the code did
less than I2/I5 say. (a) I2-sink ("CWE-787 is a WRITE, CWE-125 a READ") read the access only from
ASan's "READ of size" line, so a SEGV report, which states it as "caused by a READ memory
access", was never checked. Parsing that line demoted 3 GOLD whose CWE-787 sink is a NULL-page
READ, which PR-2 also says is not a chain sink. (b) I5's vulnerable side counted the UBSan
rebuild log that witnesses a CWE-190 intermediate. That log comes from a different build and
does not replay the sink crash. Such runs are now marked `witnesses: "intermediate"` and I5 does
not count them. No GOLD depended on it; 13 SILVER would have, once their sink was attributed. One
sink had been attributed to that log; the attribution was removed.

**PR-3 implementation fix (2026-10-19), rule unchanged.** The 13 SILVER named in (b) above were
not what (b) assumed. `attach_arvo_reruns.py` rewrote every vulnerable-side report when it
attached a re-run, including a UBSan intermediate report attached earlier, so on 12 hdf5 records
the report marked `witnesses: "intermediate"` pointed at our own ASan re-run of the sink
(`vul.rerun.sanitizer.txt`), not at the UBSan rebuild, and the sink-side report was gone; the
patched runs had inherited `sanitizer: ubsan` from it. On one c-blosc2 record the sink-side report
was gone the same way. (b) itself stands: a UBSan rebuild log still never counts for I5. The
importer now never touches an intermediate report, and `repair_intermediate_overwrite.py`
restores what the archived logs show: the intermediate report points back at `ubsan.vul.txt`,
and a sink-side report is re-added for the re-run only where the changelog records our re-run
crashing on the vulnerable side. Re-tiered by `integrity.py`: 11 SILVER became GOLD, all
length-3; the other 2 still fail I2-sink. Logged as `repair-intermediate-overwrite`.

**I1 sink-direction correction applied to later arms (2026-10-19), rule unchanged.**
`build_corrected.py` sets an ARVO sink from its own crash ("sink per access direction", I1): an
out-of-bounds READ is CWE-125 and a WRITE CWE-787. It ran before the length-3 arm joined, so 12
length-3 records kept a sink their own out-of-bounds report contradicts, which I2-sink demotes.
`apply_oob_direction.py` applies the same correction, with the build's own class set, to those
records only; use-after-free reports are untouched (PR-2/PR-8 decide those). The outcome was seen
before applying it: 5 SILVER became GOLD. Logged as `oob-direction`.

**Patch evidence fetched from GitHub mirrors (2026-10-19), rule unchanged.** I3 fails a record
whose fix commit was never fetched ("not a patch"). For records whose forge we could not reach,
`fetch_mirror_patches.py` fetches the recorded fix commit from the project's official GitHub
mirror by its git id, accepts it only if `git format-patch` names exactly that commit, and applies
the I3 guard check unchanged. 61 fetched patches passed and 54 SILVER became GOLD; 40 candidates
were refused (no mirror, a different commit, or a harness-only fix) and keep their tier. Logged as
`patch-materialized-mirror`.

**I5 sink attribution enforced as written (2026-10-20), rule unchanged.** I5 requires the sink
link to be attributed to a sanitizer report, and `classify_link` documents that a report counts as
an execution witness of a link only when the link says where. A fallback after that check still
returned `execution` for a bare report reference with no site. It is removed. A link now needs a
file, or for a kernel report without line information the function the report names, to be an
execution witness. Two kernel intermediates whose KASAN reports name the accessing function take
that function as their site, from the archived report. Eight `arvo-newarm` GOLD records whose
null-pointer crash jumped to address zero, leaving no frame to attribute, fail I5 and become
SILVER; 37 non-GOLD links change kind. Logged as `evidence-kind-restamp`. Found while answering
the adviser's review of the evidence categories; a dry run showed the outcome, which only demotes.

**Patched-run count (2026-10-20), enforced as written.** I5 says the fixed revision must run
clean twice. The code required at least one patched run, and 348 first-pass GOLD records (all
ARVO-backed but one osv record) carried one. `integrity.py` now requires two, and
`retier_all.py` re-judged every GOLD and SILVER record with it: those 348 became SILVER and nothing
else changed (logged as `contract-retier`). All ARVO-backed ones were re-run on clean hosts
with two patched runs; a record whose runs pass returns to GOLD through the same code. Outcome
(2026-10-20 15:30 UTC, all runs in): all 347 ARVO-backed records reproduced on both sides with the
archived crash and returned to GOLD, 35 of them after a retry of a pull that Docker Hub's rate limit
had blocked (an infrastructure stop, R10). The osv record, built from source, stays SILVER until it
is re-run twice.

**PR-4 for kernel proofs (2026-10-09), implementation fixes.** (a) `ran_clean` read the kernel boot
banner "KernelAddressSanitizer initialized" as a crash, so no kernel guard-only run could ever
count as clean. With a word boundary added, 9 of 12 re-verified kernel proofs derive CWE-20. Patched
kernel logs are short excerpts without the banner, so I5 was not affected. (b) The kernel
ablation harness counted any KASAN report as "control crashed". A control now has to reproduce
syzbot's bug under the PR-6 test (`integrity.kasan_same_bug`); otherwise the proof is dropped,
site included. All 12 met it.

## PR-6: When a kernel KASAN report is "the same bug" as syzbot's (2026-10-08)

**Problem.** The kernel differential requires the KASAN report at `fix^` to match syzbot's bug:
same KASAN class AND the same function in the report's first line. 51 runs fired a KASAN report
of the same class whose first-line function differs - plausibly the same bug reported one frame
higher or lower because our build inlines differently (other compiler, other config). Locked
before any of the 51 is re-examined.

**Rule.** A KASAN report at `fix^` matches syzbot's bug if its class matches (as before) AND
syzbot's function appears either in the report's first line (as before) or among the first 12
frames of that report's own call trace. Nothing else changes: the patched kernel must still run
clean on two boots, the access direction must still agree with the record's sink, and the
matched report (not the first report in the console) is the one archived. A report whose call
trace does not contain syzbot's function is a different bug, whatever its class.

**Reported as results:** how many of the 51 match under PR-6 and become two-sided, separately
from the strict-match count, so a reader can apply the stricter rule.

**Repeated-boot retry, symmetric (2026-10-20, before any retried case runs).** 146 gold-upstream
kernel records stopped at "reproducer did not trip the bug at fix^" after one boot. Races and
timing-dependent bugs fire intermittently, so these are re-run once with up to three boots of
`fix^`, stopping at the first matching report. To keep the comparison fair, the fixed kernel must
then stay clean on three boots, not two, so a bug that needs several tries to fire faces as many
chances to fire after the fix. Matching is PR-6 unchanged. Each result records how many `fix^` boots
it took and how many clean boots were required. Reported as results: the count that becomes
two-sided under the retry, separately from first-attempt differentials, and how many needed more
than one boot. The same retry applies, unchanged, to the 29 records that first reached this stop
after the build-compatibility retry (2026-10-20, before they run).

## PR-7: Execution-first mining of new chains (2026-10-08)

**Why now.** Earlier mining needed a static (Joern) dataflow path to label a root cause, which
rarely held, so most of ARVO's reproducible crashes were never used. PR-3/PR-4 and the GitHub
runner make a static step unnecessary: the sink is witnessed by a two-sided replay and the root
cause by guard ablation. Locked before any case is selected.

**Supply.** ARVO cases marked reproduced with a recorded fix, not already in the release; syzbot
fixed KASAN bugs with a C reproducer, not already in the release.

**Selection.** Seeded (2027) and diversity-first: at most 10 cases per project; strata by sink
class (heap/stack/global overflow READ, WRITE, use-after-free, NULL, uninitialised) filled in
inverse proportion to their share of current GOLD, so under-represented sinks are drawn first;
random within a stratum. The selection list is committed before results are seen.

**A mined case becomes a record only through the existing rules, with no static labelling:**
1. Two-sided replay (PR-3 I5): crash at the vulnerable revision, clean twice at the fix.
2. Guard ablation succeeds on a source hunk (I6 path rule), and PR-4 derives the root-cause CWE
   from the guard. No other source labelling is permitted.
3. The sink CWE comes from the witnessed report only: ASan READ → 125, WRITE → 787; KASAN by
   class and access as in PR-2; anything else → not admitted.
4. The chain [derived root cause → sink] must be admissible and `multi-weakness` (PR-5).
A case failing any step is logged with the step it failed and is NOT added. A case with a proven
site but no derived CWE is logged, not added: it establishes no chain.

**Reported:** the full funnel (selected → reproduced → proof → CWE derived → admitted → GOLD) and
the composition of what was admitted versus what was drawn.

**PR-4 addendum (2026-10-08): a causal proof needs its run logs.** The ablation verdict scored a
hunk "clean" when no sanitizer line appeared, which is the silence-is-not-cleanliness flaw PR-3
I5 closed for patched runs: a guard-only build whose binary never reached the input also prints
no sanitizer line. From now a proof counts only if its archived logs show the unmodified control
CRASHED and the guard-only run EXECUTED the input with no crash (`integrity.ran_clean`). An audit
found the original ablation batch kept no run logs at all; its proofs are kept as proven sites,
crediting no CWE, until re-verified by re-running the control and the proving hunk with logs
kept. Two later proofs whose logs show no execution marker are treated the same way.

**Infrastructure stops are retried, rules unchanged (2026-10-20).** A case stopped by a failed
image pull, a patched side that never ran, an unbuildable ablation control, or a fix diff the web
view would not serve has no verdict under steps 1–4 (R10), so it is re-run; no other case is. The
ablation fetcher now falls back to `git fetch` of the fix commit from its forge, then from the
forge's official GitHub mirror, and keeps the commit only if `git format-patch` names the same
40-hex id as ARVO's pointer (the PR-3 mirror rule above). `admit_pr7.py --retry-infra` re-evaluates
exactly the cases the batch funnel stopped for these reasons and leaves every other case and record
as it was; the funnel reports the retried outcome. Decided before any retried case ran.

**Glued fix pointers (2026-10-20), implementation fix.** ARVO writes some fix pointers as a
repository URL with the commit id appended directly (".../GNOME/glib" + id gives "glibb4c2...").
Taking the leftmost 40 hex digits then named an id one letter early, and I3 refused the true diff
as a different commit. Admission and the duplicate audit now take the last 40 hex digits of a hex
run. Three batch 3 records were affected; they pass I3 with the correct id.

**Per-project cap raised for batch 4 (2026-10-20, before batch 4 is selected).** After batch 3,
every ARVO case still eligible sat in 50 projects that had each reached the cap of 10, so the cap,
meant to keep GOLD diverse, had become the only thing stopping growth. It was the wrong unit, since
GOLD's concentration comes from the kernel (16.9% of GOLD) and from projects admitted before PR-7,
not from mined batches. Before selecting, we simulated caps of 15 to 60 with the 24.1% GOLD yield of
the earlier batches. Every cap up to 60 raised the effective number of projects (inverse
Herfindahl, 27.6 at cap 10). It kept the largest non-kernel project at or under 3.3% of GOLD and
moved the test fold by under 1.2 points, because the largest remaining projects are already in
train. Cases closed by a fix the release already holds were 10 to 17% of draws; they are now
skipped and do not count toward the cap. Batch 4 therefore uses a cap of 30 per project across all
batches. Above 30 the extra cases would come from only 15 projects, so we stopped there. It also
skips any case whose fix commit is already in the release or already drawn for its project, and
draws nothing from a non-kernel project already holding 4% or more of GOLD (none does now).
Selection, seed, strata and every admission rule are unchanged. `select_pr7.py --per-project 30
--skip-known-fix --max-gold-share 0.04`; the selection is committed before any case runs.

## PR-8: A use-after-free report is a CWE-125/787 sink only behind CWE-416 (2026-10-09)

**Disclosure.** Written after an audit found 5 GOLD records it affects, so it is not blind to
those outcomes. It applies to every record and changes nothing else.

**Rule.** PR-2 accepts CWE-125/787 as the sink of a use-after-free only as the stage after CWE-416
(`416 → 125/787`). A record whose sink is CWE-125 or CWE-787 while its own vulnerable-side report
is a use-after-free (any `use-after-*` class) contradicts its sink unless the link directly before
the sink is CWE-416 (I2-sink, so SILVER). The alternative was to insert a CWE-416 link, but
`20 → 416` is not an admissible edge in the catalogue, so this would have created chains the rules forbid.
The 5 records had statically assigned (inferred or dataflow) CWE-20 sources, and none was causally
proven.

## PR-9: Human validation of chain labels (2026-10-09, before any annotation)

**Sample.** Seeded (2027), stratified by tier × chain length × chain (`irr.py sample --gold 80
--other 20`), drawn from the frozen release. Only records whose vulnerable-side report is archived
in the repository are eligible, because a rater cannot judge a crash they cannot see. The packet
states the release digest it came from.

**Raters.** Two or more security researchers who did not build the dataset. They work
independently, are blind to all labels, tiers and evidence kinds, and use the packet's codebook.
The codebook states the dataset's declared conventions (416 → 125/787 and 456 → 457) and asks
"what does the fix enforce" for the source. That is the same principle PR-4 uses, and the paper
says so.

**Measures, fixed now.**
- *Primary:* label precision per question, meaning the share of items where a rater's answer
  equals the release label, with a Wilson 95% interval. It is reported for GOLD and for non-GOLD
  separately. `unclear` counts as not confirmed.
- *Secondary, for CWEs only:* hierarchy-compatible precision. A rater's CWE agrees when it is the
  same CWE or an ancestor or descendant in MITRE View-1000 (ChildOf), so 125 and 119 agree but
  125 and 787 do not.
- *Agreement between raters:* raw agreement, Cohen's κ and Gwet's AC1, each with a 95% bootstrap
  interval.

No item is dropped after scoring. Disagreements may be adjudicated for the error analysis, but the
numbers reported are the pre-adjudication ones.

**Location correctness (2026-10-21, before any rater is recruited or any item annotated).** The
adviser asked what makes a root-cause location correct across collection routes. Each instance
now carries `site_kind` (`chainforge.evidence.site_kind`): a tested repair site, a sanitizer
origin site (MSan's creation site for CWE-456, the free site for CWE-416), a crash site, a
witnessed intermediate, or an annotated site no run or test placed. The codebook adds two things.
`source_site` may name a function outside the listed sites (`other:<file>:<function>`), and
`site_roles` asks for a role for every listed site: `defect` (the weakness is here), `repair` (a
change here removes the cause for every input on this path), `crash` (a change here only stops
the symptom), `unrelated`, or `unclear`. Raters stay blind to which listed site is the root.
*Measures, fixed now, reported per root site kind:* function-granularity agreement of
`source_site` with the recorded root (same file and function); strict precision, the share whose
recorded root the rater calls `defect`; lenient precision, `defect` or `repair`; and the rate of
`unclear`, which never counts as confirmed. Line agreement within three lines is secondary.
Wilson 95% intervals throughout. The sample is unchanged.

## PR-10: Execution-witnessed length-3 views of GOLD length-2 chains (2026-10-19, before any rebuild)

**Why.** Length-3 GOLD so far comes from one arm selected by the fix's text (a fix that adds an
overflow guard). That signal is precise but rare: 6 untried GOLD length-2 records carry it. An
integer overflow on the crash path can instead be witnessed directly, whatever the fix looks like.

**Supply.** Every GOLD ARVO record whose chain is [CWE-20 or CWE-129 → CWE-125, CWE-787 or CWE-119],
whose ARVO case has never been UBSan-rebuilt (no `ubsan.*.txt` archived and absent from every
earlier runner UBSan list). One rebuild per ARVO case. The list is committed before any case runs
(`data/validation/pr10_supply.json`).

**Witness (the length-3 rule of 2026-08-04, unchanged).** `ubsan_rebuild.sh` rebuilds the ARVO
vulnerable and fixed images from their own trees with `SANITIZER=undefined` and replays the PoV
directly with unsigned-overflow reporting on. `attach_ubsan_witness.verdict` decides: both builds
conclusive, and an integer overflow in application code at the vulnerable revision whose file:line
is absent at the fix.

**Added requirement, stricter than the length-3 arm.** The overflow must belong to this chain: its
file appears in our own vulnerable crash stack or among the non-test files the developer's fix
changes. An overflow elsewhere is logged and not used.

**Admission.** A new record [source → CWE-190 → sink]: source and sink links are copied with their
evidence from the length-2 record, the CWE-190 link carries the UBSan site and both logs. It shares
the length-2 record's `duplicate_group` and split and the two are cross-linked in
`related_records` (the PR-3 I1 exception for views that differ in evidence, not claim). The
length-2 record is not changed. Edges must be admissible (PR-5). The tier is whatever
`integrity.py` assigns.

**Reported.** The funnel (supply → both builds conclusive → overflow at vulnerable → absent at fix
→ tied to the chain → admitted → GOLD), separately from the patch-selected length-3 arm. Distinct-bug
counts are unchanged by these views, since each shares its length-2 record's group.

**Second supply (2026-10-20, after release `7de36610e6b3` was sent for review, before any case
runs), rule unchanged.** GOLD length-2 records admitted after the first supply was drawn fall
under the same supply definition. The second supply is every record that meets it now and was
in neither the first supply nor any earlier UBSan list, plus the first supply's cases whose
verdict was an inconclusive build or a missing side (infrastructure outcomes, R10). The list is
committed as `data/validation/pr10_supply2.json` before any case runs. Witness, added
requirement and admission are unchanged; the funnel is reported per supply.

## PR-11: Execution-first mining of further crash classes (2026-10-20, before any case is selected)

**Why.** PR-7 admits ASan overflow sinks only. After batch 4, 32 eligible overflow cases remain
at the cap of 30, while about 3,700 reproduced ARVO cases with a recorded fix sit in classes PR-7
never admitted. The largest are MemorySanitizer use-of-uninitialised-value (924), ASan
heap-use-after-free READ/WRITE (427) and UBSan index-out-of-bounds (145). Release `7de36610e6b3`
(tag `draft-saha-2026-10-20`) is the version the reviewed draft reports; everything here goes
into a later release and is reported separately from it.

**Supply.** ARVO cases marked reproduced with a recorded fix, not already in the release and not
drawn by any PR-7 or PR-11 batch, whose ARVO crash type is one of the three classes below.

**Selection.** PR-7's, per class: seeded (2027); at most 30 cases per project per class, counted
across all batches of that class; cases whose fix is already in the release or already drawn are
skipped (PR-7 batch 4); nothing is drawn from a non-kernel project holding 4% or more of GOLD.
Within use-after-free, READ and WRITE are filled in inverse proportion to their share of current
GOLD sinks. Each class starts with a pilot of 100 cases; a full draw follows only after the
pilot's funnel is committed, under these rules unchanged. Every selection is committed before
any of its cases runs (`data/validation/pr11_<class>_<batch>.json`).

**Shared steps.** (1) Two-sided replay as PR-3 I5: crash at the vulnerable image, clean twice at
the fixed one, each patched run demonstrably executing the input. (2) The vulnerable report must
be of the case's class; another class stops the case. (3) Every instance's site is the first
frame outside the sanitizer runtime in the relevant stack of our own vulnerable-side report. A
site in a fuzzing harness or test file (the PR-3 I6 path rule) stops the case: such a value or
free belongs to the harness, not to the project. (4) The chain must be admissible (PR-5). The
tier is whatever `integrity.py` assigns. Nothing is labelled any other way, and every case is
logged with the step it failed.

**Class rules.**
- *Use of uninitialised value (MSan).* The chain is [CWE-456 → CWE-457], the rule of the
  existing MSan arm: CWE-456 at the origin block's creation site ("Uninitialized value was
  created by"), CWE-457 at the SUMMARY use site. A report without an origin block stops the case.
  Both instances are execution-witnessed from one run. PR-5 classifies the chain multi-weakness.
- *Heap use-after-free (ASan READ or WRITE).* The chain is [CWE-416 → CWE-125] for READ and
  [CWE-416 → CWE-787] for WRITE (PR-2, PR-8). CWE-416 sits at the free site, the first project
  frame of the report's "freed by" stack, which is where the pointer becomes dangling. The sink
  sits at the use. Both are execution-witnessed from one run. PR-5 classifies the chain
  stage-decomposition (one defect, two stages); records are counted as such and never as
  multi-weakness chains. They are admitted because the free site is a localisation target the
  sink report alone does not give.
- *Index out of bounds (UBSan).* The sink is CWE-119 at the report's site, as in the existing
  index arm. The root cause is derived exactly as PR-7 steps 2 and 4: guard ablation proves one
  library-source hunk, PR-4 derives the CWE from it, and the chain must be multi-weakness. A
  proven site with no derived CWE is logged and not added.

**Re-derivation of contradicted ARVO labels (same date).** An ARVO-backed SILVER record whose
own report contradicts its label (I2 or I2-sink) is re-evaluated by the rule of the class its
report actually shows: an overflow by PR-7, a use-after-free by the rule above. If that rule
admits a chain, the record keeps its id and takes the derived chain, logged `PR11-rederive` with
the old chain. Otherwise the record is unchanged. The list is committed before any case runs
(`data/validation/pr11_rederive.json`).

**Reported.** One funnel per class and per batch, the re-derivation outcome, and the composition
of what was admitted against what was drawn, separately from PR-7 and from the reviewed release.

## PR-7 batch 5 (2026-10-20, before batch 5 is selected)

**Disclosure.** Written after batch 4's outcome was seen. Batch 4 left 32 eligible overflow cases
at the cap of 30, so a batch at that cap cannot be drawn. Batch 5 raises the cap to 60 per project
across all PR-7 batches and keeps the 4% GOLD-share bound and known-fix skipping. In batch 4's
simulation the cases above a cap of 30 came from 15 projects; the 4% bound, not the cap, is what
limits any one project's share. Selection, seed, strata and admission are otherwise unchanged
(`select_pr7.py --name b5 --per-project 60 --skip-known-fix --max-gold-share 0.04`).

## PR-12: Repair environments ("RL-ready") (2026-10-20, before any case is scored)

**Why.** A repair reward needs a working environment, which is a different property from GOLD.
GOLD fixes how reproduction and labels were checked; an environment needs the scorer
(`infra/repro/score_patch.sh`) to separate a broken build from a fixed one.

**Rule.** An ARVO-backed record of any tier is `rl_ready` when, in one scoring run of its ARVO
case, the unmodified vulnerable build scores `crash` and the developer's fix (the commit the
record names, fetched as for PR-7) applied to the vulnerable tree scores `pass`. `not_run` on
either side is an infrastructure outcome and is retried, never scored (R10). Any other
combination makes the record not `rl_ready`, with the outcome pair recorded. The flag says the
scorer works for that record; it adds nothing to the record's tier or labels.

**Reported.** Counts of `rl_ready` by tier and split, the outcome pairs of the rest, and the
measured build and replay times.

**Coverage tolerance (2026-10-21, after the first scoring run, a reward parameter, not a
label).** `reward.coverage_kept` zeroes a repair whose seed-corpus coverage falls below a
tolerance of the vulnerable build's. The 0.9 default was a placeholder. It is checked against
developer fixes, which a sound tolerance must accept: `coverage_calibration.py` writes their
feature ratios to `data/validation/pr12_coverage.json`. The default stays 0.9, which accepts all
but one of the measured developer fixes. Only cases whose image ships a seed corpus are covered,
and the paper says so.

**Patch application (2026-10-22, after the first scoring run, before any re-scoring).** The
first run applied a patch only as a whole, so one file that did not apply rejected the patch.
306 developer fixes failed that way, yet in the 61 of them that also had single-hunk tests, all
469 hunks applied one at a time. That made patch application a scorer limit, not a property of
the record, and an infrastructure outcome under R10. `score_patch.sh` now applies a patch the
same way for the developer's fix and for a policy's patch. It first tries with context that must
match exactly (fuzz 0), then GNU patch's default fuzz. At each fuzz level it tries the whole
patch, then file by file, each file where it dry-runs, so a fix can span repositories under
`/src`. A file may be left out only if the image cannot build from it, because it is absent from
the image or is neither code nor build glue. A code or build file that exists and does not apply
is `patch_fail`. `result.json` lists every file and its fate, and the fuzz used. The rule is also
tightened. `rl_ready` now requires the developer's fix to apply at fuzz 0, since a fuzzed hunk
can land where its context does not match, and `reward.replay` scores a fuzzed pass as 0 by
default. Every supplied case is re-scored with this scorer, so all `rl_ready` flags come from one
version. The first run's counts are kept in `data/validation/pr12_funnel_v1.json`.

**Correction (2026-10-22, after the re-score).** The evidence cited above was miscounted. The
count read hunk outcomes named `patch_fail`, but hunk tests write `patchfail`, so every failed
hunk was missed. Counted correctly, 122 of the 306 cases had hunk tests, and every hunk applied in
only 23 of them, while 276 hunks failed to apply. Most of these patch failures therefore mean the
archived fix does not match the image's tree, which is a property of the record. They stay
outcomes, not infrastructure, as the original rule had them, and the scorer never treated them
otherwise. The scorer change stands on its own grounds. It applies one rule to every patch,
records the fuzz used, and recovered the cases whose fix spans repositories or touches files the
image lacks (32 of the 306 now pass).

**Second supply (2026-10-22, before any of its cases is scored), rule unchanged.** Every
ARVO-backed record whose case was not in the first supply, mostly records admitted after it
(`data/validation/pr12_supply2.json`, 687 cases), is scored with the same scorer. A scored case
sets `rl_ready` on every record whose vulnerable image is that case, including records admitted
after the supply was drawn.

## PR-11 full draws (2026-10-21, after the pilot funnels were committed)

The MSan and use-after-free pilots were committed with their funnels, so their full draws follow
under PR-11 unchanged (`select_pr11.py --cls msan|uaf --name full`; 379 and 250 cases, seed 2027,
cap 30 per project per class, known fixes skipped, 4% bound). The index-out-of-bounds pilot gave
1 GOLD of 100 (33 of 34 tested hunks classify as CWE-20, inadmissible before CWE-119). Its full
draw is not run and the class is reported as a negative pilot.

## I2-site: witnessed sites in harness or test code (2026-10-21)

**Disclosure.** Written after OPEN_ISSUES #24 counted the affected records (34 witnessed root or
sink sites on GOLD records), so it is not blind to them. It applies to every record.

**Rule.** A root or sink instance whose site is execution-witnessed or intervention-supported
fails I2 (`I2-site`, so SILVER) when its site, after resolving build-tree hops, is in a fuzzing
harness, test or libFuzzer file by the PR-3 I6 path rule. Such a site is where the harness
created a value or crashed, not a weakness of the project. **Exception, fixed before applying:**
library source vendored under a harness-looking directory is not harness code. A path is vendored
when a `src/` directory follows the harness-looking directory and its file name does not contain
`fuzz` (this exempts the wolfSSL and wolfSSH sources under `oss-fuzz/projects/wolf-ssl-ssh/`).

## PR-13: Hunk pairs and hunk minimization (2026-10-21, before any case runs)

**Why.** "No single hunk stops the crash" is the most common stop in PR-7, PR-11 and the
re-derivation, because hunks are never combined.

**(a) Pairs.** Supply: every ARVO-backed record or PR-7/PR-11 case whose single-hunk test had a
crashing control and no clean hunk, with 2 to 8 code hunks after the I6 path rule. Every pair of
those hunks is applied to the vulnerable revision, smallest combined size first, each with a
full rebuild and one replay, up to 28 pairs. The first clean pair is kept. A pair establishes that
those two hunks together suffice on this input and that neither did alone. It credits no CWE
(PR-4 reads a CWE from one hunk only), and its sites are recorded as `tested_pair`, a separate
site kind that is never merged with single-hunk tested repair sites or interventions.

**(b) Minimization.** Supply: a seeded (2027) sample of 200 GOLD interventions. Within the proving
hunk, added lines are removed by ddmin while the replay stays clean, each step a rebuild and a
replay. The result is a 1-minimal set of added lines, recorded as `minimal_lines` with its site.
It refines the site; it changes no CWE and no tier.

Infrastructure failures are retried and never scored (R10). Lists are committed before any case
runs (`data/validation/pr13_pairs.json`, `pr13_minimize.json`).

**Fuzz check of hunk tests (2026-10-22, before any check runs).** Every single-hunk test (PR-4)
and hunk-pair test (PR-13a) applied its hunks with GNU patch's default fuzz, which lets a hunk
land where up to two context lines do not match. A test whose hunk applied that way may have
patched a place other than the one it names. Each test's hunk(s) are therefore found again in the
re-fetched, re-split fix diff and dry-run on the vulnerable image, first with every context line
matching (fuzz 0) and then at the default fuzz (`fuzz_check.sh`; supply
`data/validation/fuzzcheck_supply.json`, 1121 tests). A test that applies at fuzz 0 is kept and
marked `application: strict`. A test that applies only with fuzz is withdrawn into
`evidence.fuzzed_test` until a strict re-test, and its record is re-tiered from what remains. A
test that cannot be determined (diff, image or hunk unavailable) changes nothing (R10). From now
on every hunk test applies at fuzz 0.

**Strict re-tests (2026-10-22, after the fuzz check, before any re-test runs).** The 37 tests
that applied only with fuzz, and the 5 proofs whose whole hunk did not stop the crash when PR-13b
re-ran it, are re-run at fuzz 0 with the same single-hunk or pair procedure. A sufficient hunk or
pair found at fuzz 0 restores the test, marked `application: strict`, through the same PR-4 or
PR-13(a) rule. If the control crashes and nothing suffices, a withdrawn test stays withdrawn and
an unreplicated proof is withdrawn into `evidence.unreplicated_test`. A control that does not
crash, or any infrastructure failure, changes nothing (R10). The 219 checks lost to image-pull
failures are retried.

## PR-14: Is the root site on the crashing path? (2026-10-21, before any case runs)

**Why.** A chain's order comes from the catalogue. Whether the root site even executed on the
crashing input was never observed.

**Method.** For every GOLD ARVO-backed record with a libFuzzer target and a root site, the
vulnerable image's prebuilt fuzz target runs the record's input under gdb with breakpoints at the
root site's file:line and at its function, and at the sink's function as a control. Outcomes:
`line-hit`, `function-hit` (function entered, line not hit), `not-hit`, and `inconclusive` when
the control is not hit or gdb cannot resolve a location. Anything hit executed before the crash,
since the crash ends the run.

**Reading.** A hit shows the site is on this input's path, not that it caused the sink. A miss
for a tested repair site is possible: the tested hunk may add a check that the vulnerable
revision lacks entirely, whose nearest executable line is elsewhere. Rates are reported per site
kind and evidence category. Nothing changes a tier. Stored as `chain[0].path_observed`.

**Resolution (2026-10-22, after two six-case smoke runs, before the full run).** The images ship
gdb 7.x, which does not match `break foo` against `ns::Class::foo`, and an unqualified name such
as `decode` resolved into libc. Functions are now set with `rbreak FILE:REGEX` on the bare name,
restricted to the site's file (the sink's file for the control). Each line breakpoint also reports
whether the function enclosing it in the debug info matches the recorded function, which measures
the recorded function names directly. Binaries without line tables leave the line `unresolved`,
which is `inconclusive`. The outcomes are unchanged.

**Site functions (2026-10-22, after the full run, prompted by its outcomes and disclosed as
such).** For 35 of the 183 root lines whose binary names a function, the debug information's
function differs from the recorded one. Tested sites took their function from git's hunk-header
context, the nearest preceding line that looks like a definition. That names the previous
function when a hunk opens a function body, and sometimes a macro or statement. Tested sites now
take their function from the source instead. Each fix's parent revision is fetched, the site's
file is parsed with tree-sitter, and the innermost function definition containing the site's
line is used (`site_functions_from_source.py`). A site keeps its name when no enclosing
definition is found, or when the parsed name is built by a macro or is a statement keyword. The
old name stays in `function_hunk_header`. Debug information is not ground truth here. At the
images' optimisation level a static function is often inlined, and gdb then names the caller.
On the 71 hunk-header root lines where gdb names a function, the parsed name matches it for 56
and the hunk-header name for 54, and in all 12 cases where both differ the parsed name equals the
hunk-header name. No CWE, line, file or tier changes. PR-14's function outcomes depend on the
recorded function, so cases whose function changed are probed again with the new name.

**Control for inlined sinks (2026-10-22, after the full run, disclosed as post hoc).** In 148 of
the 774 cases the control could not be set, mostly because the sink function is inlined (header
helpers such as `MEM_read64` or `list_del`) and has no symbol. Line tables keep inlined code, so
in those cases the control falls back to the sink's report line. The control's role and the
outcome rule are unchanged. Those 148 cases, and the 33 whose root function changed above and
whose line did not execute, are probed again, and both passes are reported.

## PR-15: Reproduction from upstream source (2026-10-21, before any case runs)

**Why.** The clean-host sample pulls ARVO's own images, so it shows portability, not independent
reproduction.

**Sample.** Seeded (2027), 60 GOLD ARVO-backed records stratified by provenance arm, drawn before
any build (`data/validation/pr15_sample.json`).

**Method.** For each record: the OSS-Fuzz repository at its last commit before the fix date, the
project's own repository at the fix's first parent and at the fix, built with OSS-Fuzz's
`helper.py build_image` and `build_fuzzers --sanitizer address`, then the record's input (taken
from ARVO's vulnerable image, since only the build is in question) replayed once on the
vulnerable build and twice on the fixed build with the release's clean and crash rules.

**Reported.** Build success per side, and among records whose two sides built, the share that
crash at the vulnerable build with the same class and first project frame and run clean twice at
the fix, with a Wilson interval. A build that fails is a limitation of rebuilding old projects,
reported as such and never as a failure to reproduce.

**Scoring (2026-10-22, after the first scoring pass).** The first pass counted no fixed run as
clean, because OSS-Fuzz's helper mounts the input at `/testcase` and the release's completion
marker names `/tmp/poc`; the same libFuzzer line with the helper's path is now accepted, and the
helper's colour codes are stripped before parsing. Both are parser defects, disclosed because they
were found after seeing outcomes. "First project frame" is compared by file name and function,
since the upstream revision can differ from the image's by unrelated commits
(`infra/verify/score_pr15.py`).

## PR-4 for origin roots (2026-10-21, before any MSan or use-after-free root is tested)

Single-hunk tests now run on the 513 GOLD and SILVER ARVO-backed records that never had one,
mostly MSan (CWE-456) and use-after-free (CWE-416) roots whose site is a sanitizer-witnessed
origin. For a root whose `site_kind` is `origin-site`: the origin stays the instance's site, since
it defines the CWE, and a sufficient hunk is recorded as `tested_site`. If PR-4 derives the
root's own CWE from that hunk, the instance becomes intervention-supported. If it derives a
different CWE, nothing is relabelled: the test is kept as `guard_site_proof` with the conflict
named, and the witnessed CWE stands. Every other root is handled by PR-4 unchanged.

**Third supply (2026-10-21, before any case runs), rule unchanged.** GOLD length-2 records that
meet the PR-10 supply definition and were in neither earlier supply nor any UBSan list
(`data/validation/pr10_supply3.json`).

**Audit snapshot (2026-10-21, before any rater sees an item).** Rater time, not data, limits the
audit, so its sample is drawn now from the committed release `9c46639046f9` (commit 5c264119)
rather than at the freeze. The audited population is that snapshot: records added later are
outside it, and records whose labels change later are scored against their snapshot labels, both
stated in the paper. The sample is unchanged in design (`irr.py sample --gold 80 --other 20
--seed 2027`), and a separate practice set of 6 items (seed 2028) is drawn first and excluded.

**Audit size and snapshot, superseding the entry above (2026-10-21, before any rater sees an
item).** No rater has seen an item from the `9c46639046f9` draw, so that draw is replaced, not
added to. The audit grows to 150 items, 130 GOLD and 20 non-GOLD, so that location precision has a
usable interval for each GOLD root site kind. Within GOLD, floors of 40 tested repair sites, 40
origin sites and 15 annotated sites are drawn first and the rest is stratified as before
(`irr.py sample --gold 130 --other 20 --floor tested-repair-site:40 --floor origin-site:40
--floor annotated-site:15 --seed 2027 --exclude data/irr/practice/sample.json`). The floors were
set from population counts alone. Any figure pooled over GOLD reweights each site kind to its
share of the eligible GOLD population. The snapshot is now the committed release `e3b3ccf9f951`
(commit efe2e775), with the same consequences as above. The practice set is unchanged and
excluded. Raters are two security researchers who did not build the dataset. A co-author
adjudicates disagreements for the error analysis only, and the reported numbers stay
pre-adjudication. Each rater's background (years in C/C++ security, sanitizer and CWE
experience, affiliation type) is reported.

**Snapshot names (2026-10-22, before any rater has returned an item).** Eleven site function
names in the audit snapshot had been stored cut at their first space (`Foo::bar(int,`), the same
defect `repair_function_names.py` repairs in the release. They were restored from each record's
own report and the packet regenerated. No label, site, file or line changed.

**Snapshot site functions (2026-10-22, before any rater has returned an item).** Ten audit
items had a tested root site whose function came from git's hunk header. Six named no
function and four named the neighbouring function. They take the function parsed from the
source, as in the release (PR-14 amendment), so raters see and are scored against the function
that contains the site. No CWE, file, line or tier changed, and the packet was regenerated.

## PR-16: NULL-dereference chains (2026-10-22, before any case is selected)

**Why.** Every GOLD sink so far is an out-of-bounds access, an uninitialised read or a double
free, and CWE-20 roots half of GOLD. ARVO holds about 600 reproduced ASan SEGV-class crashes
with a recorded fix, and the catalogue already admits [CWE-252 → CWE-476] (MITRE-direct). Mining
them adds a sink class and a root class without touching any existing rule.

**Supply and selection.** PR-11's, as a new class `nullderef`: ARVO cases marked reproduced with
a recorded fix, sanitizer ASan, crash type `Segv on unknown address`, `UNKNOWN READ`,
`UNKNOWN WRITE` or `Null-dereference READ|WRITE`, not in the release and not drawn before.
Seeded (2027), at most 30 per project, the 4% project rule, a pilot of 100 first, and the
selection committed before any case runs (`data/validation/pr11_nullderef_pilot.json`).

**Class rule.** PR-11's shared steps, with the sink and root as follows. The case continues only
if our own vulnerable report is a SEGV on a near-zero address, the release's NULL-page test
(`integrity._NULL_PAGE`); any other SEGV stops it at the class step. The sink is CWE-476 at the
first project frame. The root comes from a single-hunk test at fuzz 0 (PR-4, PR-7). One guard
rule is added and applies only toward a CWE-476 sink. A guard that tests for NULL a value the hunk
shows being assigned from a function call is CWE-252, the missing check of that call's result
(`evidence.unchecked_call_result`). Every other guard toward CWE-476 is derived as before, and
since no other class is admissible with CWE-476 it credits no CWE and is kept as a site proof.
Nothing toward any other sink changes. Tiers come from `integrity.py`.

**Reported.** The pilot funnel per step, and a full draw only after the pilot's funnel is
committed, under these rules unchanged.

## PR-16 pilot outcome (2026-10-23)

The pilot's 100 cases ran under the rules above, unchanged. 99 reproduced, but only 8 faulted on
the NULL page, so 91 stopped at the class step. Seven of the 8 had a single hunk that stopped the
crash, and none of those hunks tested for NULL a value assigned from a call, so no CWE was derived
and nothing was admitted (`data/validation/pr11_nullderef_pilot_funnel.json`). Under these
rules the class yields no records, so no full draw follows. Widening the guard rule now would be
tuned on these outcomes, and any widening will be a new rule with a new draw.

## Corrections to tested and origin sites (2026-10-23)

These change how sites are recorded, not any rule's outcome.

1. A CWE-456 root whose CWE an intervention named (basis `guard-class`) kept MSan's origin as its
   site, as PR-4 for origin roots requires, but `site_kind` called that site annotated because it
   keyed on the basis. It now calls any CWE-456 root site taken from the sanitizer report an
   origin site. This moved 7 GOLD and 3 silver roots from annotated to origin. No CWE or tier
   changed.
2. When the fuzz check withdrew a test, a root kept at its origin still carried the withdrawn
   test's `tested_site`. Such sites now move to `withdrawn_tested_site` (3 records).
3. Kernel single-hunk tests apply hunks with `git apply`, which requires every context line to
   match, so the fuzz check has nothing to check there. Their tests are marked
   `application: strict` with that basis.
4. The fuzz check covered the tests that existed when it ran. Tests added later and the 11 left
   undetermined get the same check (`data/validation/fuzzcheck_supply2.json`), with the same
   decisions, and keep their status until it reports.

## Scorer and GOLD (descriptive probe, 2026-10-23)

GOLD's patched runs use ARVO's fixed image. The scorer applies the archived fix commit's diff to
the vulnerable image. For a seeded sample of scored GOLD images (all 124 whose developer fix
still crashed in the scorer, 60 whose fix did not apply, 60 ready; seed 20261023,
`data/validation/fixdist_sample.json`), `fix_distance.sh` records whether the vulnerable image's
project repository sits at the fix's parent, how many commits and files lie between them,
whether the fixed image sits at the fix, and how many other repositories under `/src` differ
between the two images. It changes no record; it explains the scorer's outcomes.

**Outcome (2026-10-23).** The 6 GOLD tests the second check could not re-identify were re-run at
fuzz 0 under the strict re-test rule: 4 held and are marked strict, 1 was not replicated and moved
to `evidence.unreplicated_test` (`withdraw_unreplicated.py`), and 1 whose fix diff could not be
fetched keeps its status (`data/validation/retest_unresolved.json`). None of the 3 shifted
length-three tests held at fuzz 0, so they stay withdrawn.

## PR-17: Mapping roots and sinks to CWEs MITRE allows (2026-10-24, before any record is remapped)

**Why.** CWE 4.20 marks CWE-20 (Improper Input Validation) and CWE-119 (Improper Restriction of
Operations within the Bounds of a Memory Buffer) DISCOURAGED for mapping real vulnerabilities, and
says CWE-20 "can obscure the real underlying weakness or otherwise hide chaining and composite
relationships". Half of GOLD's roots were CWE-20 and 79 GOLD sinks were CWE-119. This rule is
motivated by MITRE's guidance alone. It is not tuned on any validation outcome, and the label audit
(PR-9) is scored against the snapshot it was drawn from (amendment below).

**Roots.** A CWE-20 root is mapped to an allowed child of CWE-20 by what the added check bounds,
following MITRE's definitions. The check is read from the tested hunk when the root has a
single-hunk test, and otherwise from the fix's added lines, in both cases on lines that compare,
clamp or reject (comments stripped, as in PR-4).
1. CWE-1285 (Improper Validation of Specified Index, Position, or Offset in Input, Base, ALLOWED)
   when a checked operand names an index, offset or position (`idx`, `index`, `offset`, `off`,
   `pos`, `position`, `cursor`, `ptr`, `cur`, `start`, `end`, and their `_`/camel forms).
2. Otherwise CWE-1284 (Improper Validation of Specified Quantity in Input, Base, ALLOWED) when a
   checked operand names a quantity (`len`, `length`, `size`, `sz`, `count`, `cnt`, `num`, `nb`,
   `total`, `remaining`, `avail`, `capacity`, `width`, `height`, `bytes`, `sizeof`).
3. Otherwise the root stays CWE-20, marked `cwe_mapping: "class-level"`, since MITRE allows a
   Class when no accurate Base applies. The paper reports how many remain.
The original CWE is kept in `cwe_class`. No site, evidence category or tier changes.

**Sinks.** A CWE-119 sink from a UBSan index-out-of-bounds report, which gives no access
direction, is mapped to CWE-125 or CWE-787 by reading the reported source line in the vulnerable
image: an indexed expression that is assigned to, incremented or decremented is a write, and any
other use is a read. A line that cannot be read or decided keeps CWE-119, marked `class-level`.
UBSan vptr reports (type confusion stopped before any access) keep CWE-119, also `class-level`.

**Grounding.** CWE-1284 and CWE-1285 have no CanPrecede edge to CWE-125 or CWE-787 in 4.20. An
edge whose source's MITRE ancestor CanPrecede an ancestor of its sink (CWE-20 CanPrecede CWE-119,
which CWE-125 and CWE-787 are ChildOf) is classified `mitre-inherited`, a new kind reported
separately from `mitre-direct` and `mitre-transitive`. The catalogue admits (1284|1285, 125|787|190).

## PR-9 amendment: the audit is scored against its snapshot (2026-10-24, before any rater answer is seen)

The 150-item audit was drawn from snapshot e3b3ccf9f951, and raters answer from a vocabulary
written for that snapshot (it lists CWE-20 and CWE-119). Its primary measures are therefore
scored against the snapshot's labels. For records PR-17 remaps, the paper also reports
hierarchy-compatible agreement with the remapped label (a CWE-20 answer agrees with CWE-1284 or
CWE-1285 as its parent), which PR-9 already defines as its secondary CWE measure.

## Review corrections (2026-10-24)

An independent read of the paper against the data found these, each fixed as stated.
1. **Site proofs held to the PR-4 addendum.** Site proofs (`guard_site_proof`, a successful hunk
   test whose CWE the guard rule did not set) had been stored without log paths, so the rule that
   a proof counts only when its archived logs show the control crashing and the guard-only run
   executing cleanly was never applied to them. `verify_site_proofs.py` found the run logs for 231
   GOLD site proofs, checked them with `integrity.ran_clean`, and archived them. The other 14 GOLD
   site proofs (13 with no log, 1 whose log does not show a clean executed run) moved to
   `evidence.unverified_test` and count as untested until a re-run with logs
   (`cases/v2_ablate_unverified.tsv`, `cases/v2_kablate_unverified.tsv` on the runner).
2. **Fix attribution separates untested from negative.** `fix_attribution.status` is false only
   when the recorded fix applied with exact context, built, and the crash remained (124 GOLD). A
   fix that did not apply exactly, did not build, or met an unmodified build that failed is null,
   no result under R10 (400 GOLD with the 43 unscored).
3. **Duplicate audit.** The changed-line parser read git format-patch's `-- ` signature line as
   a deletion, which joined five unrelated projects into one cluster spanning folds. It now stops
   at that line; no bug cluster spans folds.
4. **ARVO share.** The manifest's ARVO provenance set omitted `arvo-len3-exec`; GOLD is 90% ARVO.

## Release freeze (2026-10-24)

Version 1.0.0 is tagged once the re-runs in item 1 above are applied. After the tag no record is
added and no rule is changed for this release; a correction goes to a 1.0.x release with its
changelog entry, and the paper's numbers are regenerated from the tagged release. The label audit
(PR-9) continues against its snapshot and does not change labels.

## Corrections for 1.0.2 (2026-10-29, after the freeze)

**Disclosure.** Found after outcomes were seen, while writing the answer key for the audit's six
practice items. One practice record (GOLD) had its CWE-476 root credited from a NULL test the fix
only re-indented. Each item below corrects an implementation that did not do what a locked rule
says. None changes a rule's wording, and each is applied to every record.

1. **PR-4 reads the lines a fix adds.** The guard rule names a CWE from "the check a hunk adds".
   Its implementation counted every `+` line, including lines the fix only re-indents or re-braces,
   so a moved check could name the CWE. `evidence._added` now leaves out a `+` line equal to a `-`
   line of the same diff once whitespace and enclosing braces are removed. This applies wherever
   added lines are read, so PR-16 and PR-17 read the same lines. `reapply_guard_rule.py`
   re-derived every credited guard CWE offline, from the hunk `split_hunks.py` cuts from the
   record's own diff, judged against the next link as PR-4 saw it (`cwe_class` for a mapped sink).
   Of 737 credited proofs, 720 are unchanged and 5 whose hunk could not be matched to the proof
   exactly are left as they were. One GOLD root changes class (CWE-476 to CWE-20, then PR-17's
   CWE-1284). Two credits are withdrawn, and their roots return to the CWE that PR-4's relabel
   had replaced (CWE-416 in both); the GOLD one becomes silver, because its CWE-416 root
   contradicts its heap-buffer-overflow report (PR-3 I2). Nine records admitted by PR-7 lose their
   derived CWE (8 GOLD, 1 silver). PR-7 states that a case with a proven site but no derived CWE is
   not added, so they move to `dropped.jsonl`. PR-17 re-reads 13 roots, whose mapping changes where
   only moved lines named an operand.
2. **Criterion (d) needs a commit id.** GOLD's criterion (d) is a real patch "under the recorded
   commit id", but the gate checked the commit only when one was recorded. Fourteen GOLD records
   (13 hdf5 and c-blosc2 length-three chains and one tarantool) had none. `normalize_fix_commits.py`
   stamps every record with `commit_range.fix_commits`, every 40-hex sha in `commit_range.fixed`,
   or ARVO's own `fix_commit` when `fixed` holds none, and with `commit_range.repo`. The gate now
   fails criterion (d) (I3) when a record has no fix sha. All GOLD records have one, so no tier
   changes.
3. **Licences.** The datasheet said every GOLD record had a resolved licence. 65 GOLD records did
   not. Fourteen more projects were read by hand from their own licence files at a fix commit
   (`license_overrides.json`, with URLs). binutils-gdb, poppler and libspectre stay NOASSERTION
   until read, and the datasheet now says so.
4. **Not changed: return-value checks.** In 27 GOLD CWE-20-family roots the tested hunk checks a
   value a call returned (e.g. `if (len != -1)`), which a reader may call CWE-252. PR-16 limits
   CWE-252 to NULL-dereference sinks. That is a rule's scope, not an implementation error, so it
   stays as locked and is listed in OPEN_ISSUES #32.

The release is 1.0.2. The audit (PR-9) is unaffected: it is scored against its snapshot.

## PR-9: first rater sheet (2026-11-02, before the second sheet is returned)

One of the two sheets (`data/irr/returned/sheet_AL.csv`, 150 items, no empty cell) came back
on 2026-11-01 with the rater's stated background (`data/irr/returned/raters.json`): about one year
of secure-code-generation research, has not read sanitizer reports in depth, knows the common
CWE categories roughly, academic. PR-9 asked for two security researchers; this background is
reported as stated. `score_audit.py` scores the sheet with `irr.py precision` against the
snapshot's labels, as PR-9 and its 2026-10-24 amendment fix. The paper reports this one rater's
precision as preliminary, with Wilson intervals; agreement (kappa, AC1) waits for the second
sheet, and no number is adjudicated.

Two disclosures. (1) `irr.py`'s site-precision function pooled GOLD and non-GOLD items, while the
amendment of 2026-10-21 sets its site-kind floors on GOLD. It now also reports GOLD and non-GOLD
separately, and the paper uses GOLD. The pooled output is kept. (2) Two analyses are exploratory,
added after the sheet was read: source-CWE agreement per root site kind, and, where the rater
placed the source in an unlisted function, whether the fix's diff edits that function or file
(`irr.by_root_kind`). They describe this sheet and test no pre-registered claim.

## PR-9: raters are co-authors, one sheet excluded unscored (2026-11-05, before any second sheet is scored)

1. **Co-authorship.** The rater who returned `sheet_AL.csv` is now a co-author of the paper, and
   so is the replacement rater in item 3. Neither built the dataset or saw its labels before
   rating, so the PR-9 requirement that raters did not build the dataset still holds.
   Co-authorship is an interest in the paper, so the paper discloses it. Blinding remains the
   safeguard, because a rater who never sees the labels cannot lean toward them.
2. **A sheet excluded without scoring.** A second sheet returned on 2026-11-04 is excluded. The
   rater instructions forbid using an AI tool on the items, and this sheet could not be confirmed
   to have been made without one. No agreement with the labels or with the first sheet has been
   computed for it, so the exclusion does not depend on its outcome. It is kept in
   `data/irr/excluded/`, outside the directory `score_audit.py` reads.
3. **Replacement rater.** A graduate student who did not build the dataset rates the same
   150-item packet, practice set and codebook under the same instructions, without access to
   either earlier sheet. That sheet is scored as the second sheet when it is returned, and the
   rater's background is reported as PR-9 requires.
4. **Adjudication.** The 2026-10-21 amendment gives adjudication to a co-author. Because both
   raters are now co-authors, the adjudicator is a co-author who neither built the dataset nor
   rated. Adjudication serves the error analysis only, and reported numbers stay
   pre-adjudication.

## PR-9: exploratory AI raters (2026-11-05, before any model has seen an item)

1. **Question.** How well do current language models, given exactly what a human rater got,
   agree with the snapshot's labels and with the human raters? The analysis is exploratory and
   tests no pre-registered claim. An AI sheet never counts as a rater, never adjudicates and never
   enters the human figures.
2. **Models.** One model per provider, fixed now. They are Anthropic `claude-opus-5-5`; OpenAI
   `gpt-6.1-terra`, the newest general model in OpenAI's API changelog, or the newest GPT-6.x
   model the authors' key can reach; Google `gemini-3.8-flash`, the strongest model on the Gemini
   API free tier, which offers no Pro model; and the open-weights `Qwen/Qwen3.8-27B` served with
   vLLM on Modal (`infra/verify/modal_vllm.py`). Every response records the model version the
   provider reports. A model that has not answered all 150 items when results are reported is
   reported as incomplete, with the items it answered.
3. **Input.** The codebook of `data/irr/packet.md` without its human-only logistics (the time
   estimate, the sheet file and the request not to use an AI tool), the six practice items with
   the practice key's five keyed answers, then one item per request exactly as the packet shows
   it. No labels, tools, web access or other sheets. `infra/verify/ai_raters.py` builds the
   prompts and logs the SHA-256 of both with every response.
4. **Settings.** Temperature 0 where the API accepts it, otherwise the provider's default, as
   recorded per response. One answer per item, with no repeated sampling.
5. **Parsing.** The answer is one JSON object, validated against the codebook's vocabulary and the
   item's number of sites. An invalid answer is retried once with the validation error, and a
   second invalid answer becomes `unclear` in every cell, which scores as disagreement. An API or
   network failure is never an answer. The run stops and later resumes at that item.
6. **Measures.** The human measures, computed the same way by `infra/verify/score_ai_raters.py`.
   They are label precision against the snapshot with Wilson intervals, root-site precision per
   root site kind on the Reproduced tier, the population-weighted pooled figure, and agreement
   (raw, Cohen's kappa, Gwet's AC1) with each human sheet. The comparison of interest is
   AI-human agreement next to human-human agreement once the second human sheet is returned.
7. **Caveats reported with the results.** The models may have seen these public fixes in
   training, and the packet's 200-line diff cutoff limits them as it limits humans. Results
   describe these model versions on this packet only.

## PR-9: AI raters, Gemini model and settings (2026-11-05, before any Gemini or open-weights output)

1. **Gemini.** The Gemini model becomes `gemini-4-argon`, Google's flagship on the paid tier, in
   place of `gemini-3.8-flash`. The earlier choice followed the free tier, which offers no
   flagship model. Paid credits make the flagship available, so each provider now contributes its
   strongest general model. No Gemini output existed when this was decided.
2. **Opus temperature.** `claude-opus-5-5` rejects any temperature setting, so it runs at the
   provider's default, as item 4 of the entry above allows. The API refused the first request,
   before any answer existed, and every response records a null temperature.
3. **Reasoning text.** Only the final answer is scored. If the open-weights model separates its
   reasoning from its answer, vLLM's reasoning parser for that model is enabled, and
   `ai_raters.py` drops any `<think>` block before parsing. API models' hidden reasoning is never
   seen either.

## PR-9: AI raters, OpenAI model withdrawn (2026-11-05, before any OpenAI output)

The OpenAI API model is not run, because the authors have no paid OpenAI API access. A chat or
coding-agent subscription cannot stand in for it. An agent adds its own instructions and tools,
and it can read the repository, which holds the labels. No OpenAI output exists. The analysis
proceeds with the Anthropic, Google and open-weights models, and the paper names the three.

## Release 1.0.3 corrections (2026-11-05, written before either is applied)

1. **Kernel subsystems kept in one split (R9).** The release splits linux-kernel by subsystem, but
   13 subsystems had records in more than one fold. Duplicate groups caused it. When one fix
   touches several subsystems, `dedup_groups.py` pulls the group's members into one split.
   `split_components.py` now joins split units that share a duplicate group and moves each
   component that spans folds wholly into the fold holding most of its records. It runs after
   `dedup_groups.py`, every move is logged under R9, and the gate now fails when a subsystem spans
   folds. `linux`, the nvd-race catch-all, is left alone as before.
2. **One-hunk fixes tested by the scorer's runs (PR-4).** A record's fix may be a single hunk in
   library code, not a harness or test (PR-3 I6). If the PR-12 scorer applied that fix whole at
   fuzz 0, the unmodified build's replays crashed and the fixed build's replays executed the input
   cleanly, then those two runs are the single-hunk test of that hunk, because the hunk is the
   whole fix. The proof goes through `apply_pr4.py` unchanged. The scorer's archived replay logs
   serve as the control and guard-only logs and must pass the same crash and `ran_clean` checks,
   the guard rule derives the source CWE from the hunk, and a witnessed origin keeps its site and
   CWE. A hunk of a multi-hunk fix still needs its own run.
3. **Disclosure.** Both were written after the 1.0.0 freeze with their candidates known. Item 2
   covers 144 records (130 GOLD), every one with a passing scorer run. Item 1's 58 moves (18 GOLD)
   were counted on a copy before it was written. Both ship as release 1.0.3, and the paper's
   numbers are regenerated from it.
4. **Outcome (recorded after applying).** Item 1 made the 58 moves, and no subsystem or duplicate
   group spans folds. Item 2 found the scorer's archived run for all 144 records. 142 proofs
   stand. In 132 the guard rule set no CWE, so they are site proofs, and in 10 it set one, two of
   them relabelling the root to CWE-20, which PR-17 maps on as for any root. The other 2 stay
   untested, because the scorer's corpus check in the same log crashed on another input, so
   `ran_clean` fails as written. Untested GOLD roots fall from 999 to 870. No record changed
   tier.


## Release 1.0.4 supply: hunk tests and a kernel scorer on GitHub-hosted runners (2026-11-05, before any run)

1. **Hunk tests for roots never queued.** PR-4 runs unchanged on every GOLD root of release 1.0.3
   that has no hunk test and was never queued. That is 233 ARVO cases
   (`cases/cf3_ablate.tsv` on the runner), the GOLD roots whose full fix passes the scorer,
   deduplicated by OSS-Fuzz id, run through `ablate_docker.sh`, and 185 kernel cases
   (`cases/cf3_kablate.tsv`) run through `kablate_kvm.sh`. Both lists were drawn from release
   1.0.3 before any run. Results are applied with `apply_pr4.py` and ship as release 1.0.4. An
   infrastructure failure leaves its root untested (R10).
2. **Kernel patch scorer.** A kernel case may carry a third column naming a candidate patch,
   `devfix` or a path in the runner. `kablate_kvm.sh` then runs the same control and applies the
   candidate whole to fix^ as the only variant. The candidate passes when both boots run clean and
   crashes when syzbot's bug fires, as the ARVO scorer scores. A smoke test scores the developer's
   fix on 5 GOLD kernel records with a fix^/fix differential, drawn with seed 20261105 before
   running (`cases/cf3_kscore_smoke.tsv`). The tool counts as working only if every control
   crashes and every fix passes, with any exception an infrastructure outcome.
3. **Kernel readiness.** A GOLD kernel record's differential is the scorer's readiness test: fix^
   fires syzbot's bug, and the fix commit, which is fix^ with the developer's fix applied whole,
   runs clean on two boots. If the smoke test passes, those records are marked ready in 1.0.4, with
   the differential as the evidence.
4. **Smoke outcome (recorded after the run).** Run 42138977130 scored the developer's fix on the 5
   drawn records. For 4, the control crashed and the fix passed on both boots. The fifth stopped as
   `control_build_failed`, an infrastructure outcome. The tool counts as working under item 2, so
   item 3 marked 181 GOLD kernel records ready (`stamp_kernel_scoring.py`, evidence in
   `data/evidence/kscore_smoke/`). No record changed tier.
5. **ARVO outcome (recorded after the run).** Run 42138989291 returned results for 231 of the 233
   cases. One shard reached GitHub's six-hour limit, so 2 cases have no result and stay untested
   (R10). In 77 cases a hunk alone ran clean, giving 77 proofs. The guard rule set a CWE in 9 of
   them, as 7 CWE-456 and 2 CWE-416, and the other 68 are site proofs. In 141 cases every hunk
   alone still crashed or failed to build. In 13 the diff could not be fetched or the control did
   not crash or run, so they stay untested. Untested GOLD roots fall from 870 to 793, and no
   record changed tier.
6. **Kernel outcome (recorded after the run).** Run 42139001365 returned results for all 185
   cases. In 79 a hunk alone ran clean on both boots, giving 79 proofs. The guard rule set a CWE
   in 32 of them, as 30 CWE-20 and 2 CWE-416, and the other 47 are site proofs. In 38 no hunk was
   enough alone. 41 controls failed to build and 27 did not fire syzbot's bug, so those 68 have no
   verdict and stay untested (R10). The guard rule relabelled 24 roots to CWE-20. For 16 that
   replaced CWE-1284 or CWE-1285, which PR-17 maps on as for any root. The other 8 replaced
   CWE-416 on kernel use-after-free reports that record no origin site. Their chains became CWE-20
   then CWE-125 or CWE-787 with no CWE-416 link, which PR-8 forbids for a use-after-free report,
   so these 8 left GOLD for SILVER. That interaction is recorded as an open issue, and no rule was
   changed to avoid it. Untested GOLD roots fall from 793 to 714 (37%), and GOLD holds 1,925
   records. Release 1.0.4 ships these results.

## Release 1.0.5 supply: reruns of hunk tests that gave no verdict (2026-11-07, before any rerun)

1. **Why, and the environment fix.** Release 1.0.4 left 68 kernel cases of run 42139001365 and 2
   ARVO cases of run 42138989291 with no verdict. Reading the 68 showed two faults in
   `kablate_kvm.sh`, not in any rule. All 41 control build failures are kernels older than 5.6,
   plus one 5.12, and failed within seconds; `kdiff_kvm.sh` builds that era inside the gcc image
   syzbot used, and the hunk test lacked that step. Of the 27 controls that did not fire, 12 are
   records whose differential matched under PR-6, and the hunk test's classifier matched only the
   report's first line. `kablate_kvm.sh` now uses the differential's build and boot environment
   unchanged: the era compiler and image, the host-toolchain compatibility retry, the same config
   lines and the same classifier, PR-6 included. The kernel patch scorer is the same script, so it
   changes with it.
2. **What reruns.** The 68 kernel cases (`cases/cf4_kablate_rerun.tsv` on the runner: 41 control
   build failures, 27 controls that did not fire) and the 2 ARVO cases (`cases/cf4_ablate_rerun.tsv`,
   42470807 and 42524493, unchanged script, a job of their own). Both lists were drawn from those
   runs' results before any rerun. No case with a verdict reruns, neither a proof nor a case where
   no hunk sufficed.
3. **Repeated boots, symmetric.** As in the retry of 2026-10-20, the control may boot fix^ up to 3
   times, stopping at the first matching report, and every hunk must then run clean on 3 boots,
   not 2. This is stricter than the 2 boots behind the 1.0.4 kernel proofs, and is reported as such.
4. **No verdict stays no verdict.** A case where no hunk ran clean counts as "no single hunk
   sufficed" only if every hunk gave a verdict (a crash, an apply failure or a build failure). If
   any hunk's boot never ran, the case is `hunks_inconclusive`, an infrastructure outcome (R10).
   Any rerun with no verdict leaves its root untested.
5. **Checks on what already shipped.** The scorer smoke test reruns on the same 5 records
   (`cases/cf3_kscore_smoke.tsv`) with the new script, and the tool still counts as working only
   under item 2 of the 1.0.4 supply. The 38 kernel cases of 1.0.4 where no hunk sufficed are
   re-read with the new classifier from their archived first-boot logs; any whose hunk run did not
   execute is reported as no verdict, with no rerun.
6. **Rules unchanged.** PR-4, PR-6, PR-8 and PR-17 apply as before through `apply_pr4.py`. Results
   ship as release 1.0.5.

## Release 1.0.5 corrections (2026-11-07, written before they are applied)

1. **Candidates we ran.** PR-1 made a record a Candidate because no run of ours reached it. 35 ARVO
   Candidates have since gained our own archived runs, but neither `attach_arvo_reruns.py` nor
   `retier_all.py` re-tiers a Candidate, so they kept the tier. `retier_all.py` now judges every
   Candidate that has our own vulnerable-side log by the GOLD contract (PR-3), as it judges every
   GOLD and Partial record. The 210 advisory-only kernel races and 2 syzbot records have no run of
   ours and stay Candidates. A review found this on 2026-11-07, and a dry run then showed the
   effect (22 to GOLD, 13 to Partial), so the count was known before the change; it is disclosed
   here and the rule is the existing contract, unchanged.
2. **Licences.** The three projects left `NOASSERTION` in 1.0.2 (binutils-gdb, poppler,
   libspectre) were read from Debian's copyright files, since their upstream hosts were not
   reachable (`license_overrides.json`). No tier depends on a licence.
3. **A paper figure's population.** The share of Reproduced-tier records whose fix touches no file
   containing the crash was computed over multi-weakness chains only, while the paper describes all
   Reproduced-tier records. `build_macros.py` now counts all of them.
4. **Project aliases (added 2026-11-07, before it is applied).** R9 keeps each codebase in one
   split, but `canonical_project` only folds case, owner prefixes and `.git`, so a second review
   found four codebases under two or more names: `freetype2` (OSS-Fuzz) and `freetype`, `cpython3`
   and `python/cpython`, `libjpeg-turbo` and its OSS-Fuzz branch projects (`.2.0.x`, `.2.1.x`,
   `.dev`, `.main`), and `ggml-org/llama` (a truncated URL) and `llama.cpp`. Three of them span
   folds. `canonical_project` now also strips an OSS-Fuzz branch suffix (`.dev`, `.main`,
   `.master`, or a version ending in `.x`) and maps the other three names, and
   `split_components.py` then moves each spanning codebase wholly into the fold that holds most of
   its records, as it does for kernel subsystems (R9, logged). The projects were found by reading
   the name list before any split was recomputed, and pairs that only share a prefix (`libssh` and
   `libssh2`, `c-blosc` and `c-blosc2`, `re` and `re2`) are distinct projects and stay apart.
   `linux`, the advisory-race catch-all, is left alone as before.

## Release 1.0.5 outcome (recorded after the runs, 2026-11-07)

1. **Kernel reruns.** Run 42369614870 returned results for all 68 cases. In 37 a hunk alone ran
   clean on three boots, giving 37 proofs. The guard rule set a CWE in 9 of them, as 8 CWE-20 and
   1 CWE-416, and the other 28 are site proofs; every boot's log is archived with the proof. In 15
   every hunk alone still crashed, failed to apply or failed to build. One more case,
   6c8215822f35fdb35667, counts as no verdict (item 4 of the supply): its only non-clean boot was a
   user-space segfault of the reproducer, which ended early and which the classifier's "general
   protection fault" pattern read as a kernel crash (OPEN_ISSUES #35). In the other 15 the unmodified
   kernel still did not fire syzbot's bug in three boots: 6 never booted the reproducer, 1 crashed
   with another report and 8 ran clean. All 41 former build failures now built (29 proofs, 10 with
   no sufficient hunk, 2 controls that ran clean); of the 27 former no-fires, 8 gave proofs,
   5 no sufficient hunk, 1 no verdict and 13 still did not fire. Every case without a verdict keeps
   its root untested (R10).
2. **ARVO reruns.** Both cases (42470807, 42524493) gave a proof, and both are site proofs.
3. **Smoke test.** Run 42369627142 rescored the developer's fix on the same 5 records with the new
   script. For 4 the control crashed and the fix passed on both boots. 838eb0878ffd51f27c41, a
   control build failure in 1.0.4, now builds with the era compiler but its control did not fire
   in its one boot, an infrastructure outcome. The tool still counts as working under item 2 of
   the 1.0.4 supply (`data/evidence/kscore_smoke_105/`).
4. **The 38 negatives of 1.0.4, re-read.** With the new classifier, 37 stay cases where no hunk
   sufficed. In 031d0cfd7c362817963f a hunk's run never booted, so it is reported as no verdict,
   with no rerun. No log of the 38 contains the user-space trap of item 1.
5. **A correction to item 1 of the supply.** The supply said the hunk test now uses "the
   differential's build and boot environment unchanged". That is true of the runner's
   `kdiff_kvm.sh`, but 38 of the 68 records' differentials were built on our KVM host with
   kernel.org's gcc 10.5, which the runner replaces with syzbot's era image for kernels older than
   5.16. On GitHub-hosted machines, the unmodified kernel ran the reproducer for 157 of the 163
   ready kernel records tried there and fired syzbot's bug for 147, and the paper reports that
   separately from readiness, which rests on each record's own differential.
6. **Relabels and tiers.** The guard rule relabelled 5 roots to CWE-20: 2 from CWE-1284, 1 from
   CWE-1285, 1 from CWE-190 and 1 from CWE-416. The CWE-416 case (syzbot 8743fca924afed42f93e) is
   another instance of OPEN_ISSUES #33, so it left GOLD for SILVER under PR-8, and PR-17 then mapped
   its root to CWE-1284. The 1.0.5 corrections applied as registered. 22 Candidates rose to GOLD
   and 13 to SILVER, as the dry run showed, 8 records moved split for project aliases, and 6 kernel
   records moved split under R9 because a newly located root put them in another subsystem. GOLD
   holds 1,946 records, Candidates fall to 212, untested GOLD roots fall from 714 to 683 (35%), and
   1,263 GOLD roots have a successful single-hunk test.

## PR-9: the replacement rater's sheet, screened and admitted (2026-11-07, before it is scored)

1. **What arrived.** The replacement rater of the 2026-11-05 entry returned `sheet_AD.csv` on
   2026-11-07: 150 rows, every coded cell filled, every value in the codebook's vocabulary, every
   listed site given a role, and a note on every row.
2. **Screening for AI use.** The rater instructions forbid an AI tool, and a sheet was excluded on
   2026-11-05 because it could not be confirmed to have been made without one, so this sheet was
   screened before scoring. No screen used the dataset's labels or the first rater's sheet. The
   checks and their results (scripts in the session log, numbers below) are these.
   1. *Agreement with the three AI sheets.* On all six coded answers, the sheet matches Claude on
      43% of items, Gemini on 42% and Qwen on 28%, below the 48–67% at which the three models
      match one another. It is not a copy of these model runs. It also matches the excluded sheet
      on only 36%, so it was not copied from that sheet. This is the only agreement ever computed
      with the excluded sheet, and it cannot change that sheet's exclusion.
   2. *Caution.* It answers `causal` with `unclear` 56 times, against 7–18 for the models, as the
      codebook asks ("a guess is worse").
   3. *Grounding.* Of 145 code identifiers in its notes, 144 appear in that item's packet text
      (the other is `libFuzzer`), and it writes `unnamed` where the packet names no function,
      where two models supplied a function name the packet does not show.
   4. *Style.* Its notes reuse a fixed set of stock clauses (55% of clauses are verbatim repeats,
      the most common 37 times) in a nearly fixed order that follows the reading of an item
      (report, fix, sites, causal), and they contain no typing slips. Per-item model output does
      not repeat itself this way (at most 2% of clauses), so this reads as a rater pasting from a
      personal list of phrases. It is also what a templated tool would produce, which no text
      check can rule out.
3. **Decision.** The sheet does not show the marks of model output and is admitted as the second
   sheet under item 3 of the 2026-11-05 entry. As for the excluded sheet, the standard is the
   rater's confirmation, so the rater is asked to confirm in writing that no AI tool was used; if
   the rater cannot, the sheet moves to `data/irr/excluded/` and every figure from it is withdrawn.
   The rater's background is reported as PR-9 requires once the rater states it.
4. **Addendum after scoring (2026-11-07).** The same agreement check, run on the first sheet as a
   control once both sheets were scored, matches Claude and Gemini on all six answers for 59% of
   items each and Qwen for 44%, closer to the models than the second sheet is (43%, 42%, 28%). On
   the items where Claude and Gemini disagree, neither human sheet follows one model: the first
   sheet sides with Claude 26 times and Gemini 27, the second 26 and 23. Agreement with models
   therefore cannot tell a careful human from a model-assisted one, and the screen in item 2 rests
   on its other checks. The paper reports the registered comparison: the three models match a
   rater's root site in 71–89% of items, and the raters match each other in 75%.

## PR-9: the excluded sheet deleted from the repository (2026-11-07)

The sheet excluded unscored on 2026-11-05 has been deleted from the repository together with its
README. It was never scored against the labels or the first sheet; the only computation that ever
used it is the screening comparison recorded in the entry above. The entries above remain as the
record of the exclusion. A sheet withdrawn under item 3 of that entry is deleted the same way,
rather than moved to `data/irr/excluded/`, and every figure from it is withdrawn.

## Figures added after the outcomes, to state what three reported figures measure (2026-11-08)

A read of the paper asked what three passages count. Answering it added the figures below, all
computed after the outcomes were seen. None changes a reported figure, a label or a rule.

1. **Fixes off the stack.** The reported share of Reproduced-tier ARVO records whose fix touches
   no file on the call stack counts every stack in the vulnerable report, including the
   allocation and free stacks ASan adds for heap errors. `root_site_relation` places sites against
   the crash stack alone. The paper now gives both shares (`PctFixOffCrashStackArvo` beside
   `PctFixOffStackArvo`), so the two passages use one stack each and say which.
2. **Site agreement at function level.** The planned agreement between raters on the root site
   (`irr.score`) compares answers as written, so two `unclear` answers agree and a listed number
   and an `other:` answer naming that site's function disagree. `irr.site_detail` also resolves
   each answer that names a function to (file, function), the granularity precision uses. The
   paper keeps the planned figure as its measure and reports the function-level figure as one
   added after scoring.
3. **Completeness.** `irr.site_detail` counts blank answers and listed sites left without a role
   in both sheets. The paper states the result.
4. **Pooled weights and exclusions.** The paper now states the weights PR-9 uses for the pooled
   figure (`data/irr/snapshot_population.json`) and the audit items outside precision by site
   kind. These were fixed before scoring and are only stated, not changed.

## PR-9: rater confirmations received (2026-11-08)

1. Both raters confirmed in writing that they used no AI tool on the audit items. Both sheets
   stay admitted under item 3 of the 2026-11-07 entry, and no figure changes.
2. Both raters agreed that their sheets, initials and self-described backgrounds in
   `data/irr/returned/` be published with the release.

## Release 1.0.7: a witnessed origin with a tested hunk takes the tested site as root (2026-11-09, after the audit, written before it is applied)

1. **Change.** PR-4 kept a witnessed origin (MSan's creation site for CWE-456, the free of a
   CWE-416) as the root's site even when a single-hunk test of the fix succeeded, and stored the
   tested site in `evidence.tested_site`. From release 1.0.7 the tested site becomes the root's
   site (`site_kind: tested-repair-site`) and the origin moves to `evidence.origin_site`. The root
   keeps its CWE and its evidence kind, because the report still names the CWE.
   `infra/verify/move_origin_roots.py` applies this after `locate_tested_sites.py`, and a later
   withdrawal of the test puts the origin back. A root whose tested hunk could not be placed (no
   `tested_site`) keeps its origin.
2. **What was seen first.** This entry was written after both audit sheets were scored. Before it,
   on 2026-11-09, an exploratory comparison found that 30 of the 51 audited GOLD origin roots have
   a tested hunk in release 1.0.6. The raters named that hunk's function as the root in 25 and 21
   of them and the origin's function in 3 and 4, and for the 53 audited tested roots they named
   the root's function in 47 and 46. The rule was chosen with these figures known, so they do not
   test it. The raters judged the snapshot's sites, and they saw the fix, which contains every
   tested site.
3. **Counts before applying.** Counted on a copy of release 1.0.6 before this entry: 392 GOLD and
   34 silver roots move, and 2 GOLD roots keep their origin because their tested hunk could not be
   placed. The GOLD contract (`chainforge.integrity`) does not read site kinds, so no tier should
   change; the release outcome is checked against that.
4. **Reported.** The paper says the rule follows the audit and gives item 2's figures as
   exploratory. The audit's planned figures score the snapshot and do not change. The sensitivity
   figures that score the audit against current root sites read a rater's role only at sites the
   packet listed, so a moved root whose tested site was not listed counts as unjudged. The paper
   therefore does not report those site figures for 1.0.7, and `score_audit.py` still computes
   them.

## Release 1.0.7 outcome (recorded after applying, 2026-11-09)

1. **Moves.** 426 roots moved as counted (392 GOLD, 34 silver), and the 2 GOLD roots whose tested
   hunk could not be placed keep their origin.
2. **Tiers.** Item 3 of the entry above expected no tier change, and that was wrong. Twelve silver
   records became GOLD. Their only gap was I2's rule against a root site in harness or test code:
   each one's MSan origin lay in a fuzz harness, while its tested hunk lies in library code. The
   entry overlooked that I2 reads the root's site. One more record lost the same gap and stays
   silver for I3. No record left GOLD. The contract did not change, so these are its outcomes on
   the moved sites.
3. **Splits.** Four kernel records changed split. A kernel record's split unit is the subsystem
   of its first recorded site, which is now the tested site, and R9 keeps each unit in one fold.
4. **Derived fields.** `root_site_relation` changed for 220 records, the difficulty proxy for 126
   and sampling weights for 2539, all recomputed by `rebuild_derived.sh`.
5. **Audit wording.** `NIrrNowTested` now counts 42 audited roots that are tested sites today:
   9 suggested sites made tested by later single-hunk tests, as before, and 33 origin roots moved
   by this rule.

## Release 1.0.7 corrections from an independent check (2026-11-09, before release)

An independent check of the 1.0.7 data, run before release, found the points below. The release
was regenerated from 1.0.6 with items 1 to 4 applied.

1. **Tested sites outside source code.** A tested site outside C/C++ source no longer becomes a
   root. One silver record, CHAINFORGE-965301729, has its tested hunk in `configure.ac`, so it
   keeps its origin and its I2 gap, and stays silver for I3. 425 roots move (392 GOLD, 33
   silver), not the 426 counted in the outcome entry above.
2. **PR-4 on a moved root.** `apply_pr4.py` now treats a root with `evidence.origin_site` as a
   witnessed origin, so a later run keeps its CWE. Without this, 50 moved GOLD roots whose guard
   class conflicts with their CWE would have been relabelled.
3. **One statistic read the moved site.** The supplement's count of MSan roots whose fix touches
   the origin's file now reads `evidence.origin_site`.
4. **PatchBench comparison rerun.** `compare_patchbench.py` reads PatchBench's metadata and the
   ARVO index, so `rebuild_derived.sh` does not run it. Rerun on 1.0.7, it matches 30 GOLD
   records: 22 tested sites (8 in a function the curated patch edits, 6 more in a file it edits,
   8 elsewhere), 6 origin sites (all outside its files) and 2 suggested sites.
5. **Item 2 of the 1.0.7 entry overstated its figures.** 33 audited GOLD origin roots had a placed
   tested hunk, and all 33 moved. 30 of them name a function at both sites, and in 3 of those the
   two sites share a function, so the counts given there overlap. Where the two functions differ
   (27 items), the raters named the origin's function in 0 and 1. They named the tested hunk's
   function in 25 and 21 of the 30, and 6 of each came from naming the listed crash site, whose
   function is the hunk's. The paper reports these figures.
6. **Known and not changed in 1.0.7.**
   1. The supplement's debugger-probe figures were measured on 1.0.6 root lines, and 144 of the
      774 probed records have since moved their root.
   2. For 4 of the 12 promoted records the MSan origin is a value the fuzz harness itself
      created, which is what I2's harness rule guards against. The contract admits them because
      the root is now the tested site in library code.
   3. 3 of the 12, and 44 GOLD records in all, have an MSan origin created by a heap deallocation
      but a CWE-456 label (OPEN_ISSUES #37).
   4. A moved root keeps `evidence_kind: execution`, which now means that the report names its CWE
      and places its origin. README.md and SPECIFICATION.md say so.
   5. Kernel record CHAINFORGE-0800652 moved from train to test, so a model trained on release
      1.0.6's train split has seen it.

## Release 1.0.7: an MSan origin created by a heap deallocation is a use after free (2026-11-09, written before it is applied)

1. **The defect.** MSan poisons memory when it is freed, so a read of freed memory is reported as
   a use of an uninitialized value whose origin block says "created by a heap deallocation" and
   points at the free. The MSan arm labelled every origin CWE-456 and its sink CWE-457, so these
   records called a use after free a missing initialization (OPEN_ISSUES #37, found by the
   independent check of 2026-11-09, not by the audit).
2. **Change.** A CWE-456 root whose archived vulnerable MSan report has an origin block "created
   by a heap deallocation" becomes CWE-416 (use after free), and its CWE-457 sink becomes CWE-125,
   the read of freed memory, as PR-2 labels a use-after-free read. The root's site does not move:
   the origin it already records is the free, now marked with stage `freed (MSan: heap
   deallocation)` so that `site_kind` reads it as a use-after-free origin. A root already moved to
   its tested site keeps that site, and the stage goes on its `origin_site`.
   `infra/verify/relabel_freed_msan.py` applies this after `move_origin_roots.py`.
3. **Contract.** PR-3 I2 rejects a CWE-416 source unless the report's class is a use-after-free.
   An MSan report whose origin is a heap deallocation witnesses the freed memory, so I2 now also
   accepts a CWE-416 source on such a report (`chainforge.integrity.crash_facts` gains
   `freed_origin`). No other rule changes.
4. **Counts before applying.** Counted on the 1.0.7 working copy before this entry: 48 records
   (44 GOLD, 4 silver), of which 28 roots are origin sites and 20 were moved to tested sites. Two
   are in the audit sample. The audit's planned figures score the snapshot and do not change.
   With I2 amended and (416, 125) admissible, no tier should change; the outcome is checked
   against that.

## Release 1.0.7 heap-deallocation relabel: outcome (recorded after applying, 2026-11-09)

1. 48 records were relabelled CWE-456 -> CWE-457 to CWE-416 -> CWE-125 as counted (44 GOLD, of
   which 24 roots are origin sites and 20 tested sites, and 4 silver). No tier changed.
2. Every relabelled root reads as `cwe_basis: msan-origin`. Two had kept a stale note saying
   their CWE-456 source was not attested, and the note now names the MSan origin block.
3. As a use-after-free read, each chain is now one weakness in two stages (`chain_kind`
   `stage-decomposition`), and its MITRE grounding was recomputed.
4. This cures OPEN_ISSUES #37, so item 6.3 of the corrections entry above no longer holds.

## Release 1.0.8: findings of a second independent check of 1.0.7 (2026-11-09)

A second independent check, of the heap-deallocation relabel and of the corrections above,
confirmed the 48 relabels, the unchanged tiers and the paper's figures. It found the points
below. Release 1.0.7 was published before they were applied, so release 1.0.8 carries items 1 to
3. Items 1 and 2 change no record. For item 3, the relabel step brings the notes of the 48 records
relabelled in 1.0.7 up to date and logs each as `freed-msan-note-rewritten`. Regenerated from
1.0.6 instead, the 48 records and every tier come out the same.

1. **Narrower matching.** The relabel and I2's new allowance read only the log's first
   MemorySanitizer report, which must be a use of an uninitialized value whose origin is a heap
   deallocation (`chainforge.integrity.freed_msan_origin`). A root whose CWE a single-hunk test
   named is left to the guard rule. None of the 48 is affected, since each log holds one report.
2. **Write sinks.** I2-sink now rejects a CWE-787 sink on such a report, since MSan cannot see
   writes. No record has one.
3. **Stale notes.** The relabel now also rewrites the `dataflow_evidence` note of these records,
   which still described CWE-456 and CWE-457, and its `patch_hunk_ref` says the memory was freed
   at the origin site, which for a moved root is `evidence.origin_site`.
4. **"The origin it already records is the free" holds for 45 of the 48.** For 3 the recorded
   frame is libc++'s deallocation routine rather than project code, and one of these hides a free
   in the fuzz harness. Three other relabelled GOLD records free in harness code. These are
   OPEN_ISSUES #38 and are not changed in 1.0.7.
5. **The CWE-125 sink is a convention.** As for ASan, a read of freed memory is CWE-125. MSan
   reports the first use of the freed value, and in 6 of the 48 the bytes were copied before that
   use, so the read happened elsewhere. OPEN_ISSUES #37 and the README say so.
6. **Corrections to entries above.** `root_site_relation` changed for 219 records, not 220, after
   the configure.ac correction. Item 6.4 of the corrections entry should read that every moved
   root keeps its evidence kind, which is `execution` for 356 of the 425. The 144 moved records in
   item 6.1 are counted among the records the debugger probe covered. Of the 12 promotions, 9 are
   logged as `contract-retier` and 3 inside `evidence-kind-restamp` entries, because that step
   re-tiers the records it touches.
7. **Audit wording.** Two audited GOLD records were relabelled, and both raters had answered
   CWE-456 and CWE-457 for them, so the hierarchy agreement against today's labels falls from 73%
   and 80% to 72% and 78% because of this rule, not the CWE-20 mapping. The paper now says "today's
   labels" rather than "today's mapped labels".

## Release 1.0.8: an origin site on a C++ standard-library frame moves to the first project frame (2026-11-09, written before it is applied)

1. **The defect (OPEN_ISSUES #38).** An origin site is the first frame after the sanitizer's
   interceptor in the report's origin stack, ASan's free stack for a use after free and MSan's
   creation stack otherwise. In C++ code that frame is often libc++ code (`operator delete`
   wrappers, `std::allocator::deallocate`, `unique_ptr`, `std::function`), which says nothing
   about the program and hides where it freed or created the memory.
2. **Change.** Such an origin moves to the first frame of the same stack that is neither
   sanitizer runtime nor C++ standard-library code (`infra/verify/fix_library_origins.py`, run
   after `relabel_freed_msan.py`). For a root whose site is the origin, the site moves; for a root
   already moved to its tested site, `evidence.origin_site` moves. Stage, CWE and evidence kind
   stay, and a stack with no such frame is left alone. The new frame can be fuzz-harness code,
   which the contract then judges as it judges any root site.
3. **Counts before applying.** Counted on the 1.0.7 data before this entry: 25 origins move (14
   GOLD root sites, 8 GOLD `origin_site` fields and 3 silver root sites), and 1 silver record has
   no project frame and stays. Four GOLD records are expected to leave GOLD under I2's harness
   rule, because their origin is then in the fuzz harness: CHAINFORGE-969006916, -966097059 and
   -961479512 (BoringSSL, MSan origin in the harness) and CHAINFORGE-0042492862 (wolfMQTT, a free
   in the harness). CHAINFORGE-960034212 also gets a harness origin, but its root is its tested
   site in library code, so its tier should not change. The outcome is checked against these
   expectations.

## Release 1.0.8 outcome (recorded after applying, 2026-11-09)

1. 25 origins moved as counted (14 GOLD root sites, 8 GOLD `origin_site` fields, 3 silver root
   sites), and the silver record with no project frame (CHAINFORGE-0042504315) kept its site.
2. Exactly the four expected GOLD records left GOLD for I2's harness rule, so the Reproduced tier
   falls from 1958 to 1954. CHAINFORGE-960034212 kept its tier. No other tier or gap changed and no
   split moved.
3. `root_site_relation` changed for 4 records and sampling weights for 1517, recomputed by
   `rebuild_derived.sh`.
4. This cures OPEN_ISSUES #38.
5. Built from the published 1.0.7, the relabel step also rewrote the note and hunk reference of
   the 48 records it relabelled in 1.0.7 (item 3 of the second check above) and changed nothing
   else. The records are identical to those of 1.0.8 regenerated from 1.0.6.

## Release 1.0.8 corrections from an independent check (2026-11-09, before release)

An independent check of the 1.0.8 change confirmed the 25 moves, their frames, the four
demotions, the unchanged tiers and the paper's figures, and replayed the release from 1.0.7 byte
for byte. It found the points below. Items 1 to 4 were applied before release; none changes a
site choice, a tier or a figure in the paper other than the dataset hash.

1. **Stale notes.** `fix_library_origins.py` now also rewrites the record's `dataflow_evidence`
   note, which still named the libc++ frame, for 6 MSan records.
2. **Paths.** The moved site's path is now normalised by `chainforge.evidence.normalize_path`,
   as every witnessed path is. Five stored paths change (three skia paths kept `out/Fuzz/../../`,
   one tesseract path a leading `./`, and an ots path kept the build-tree prefix); `same_file`
   matched all of them before, so no derived value changes.
3. **Runtime frames.** The runtime pattern skipped any frame under `llvm-project`, which would have
   skipped LLVM's own code; it now skips compiler-rt, sanitizer-common and libFuzzer frames only.
   No origin is affected.
4. **Debugger probe.** `chain[0].path_observed` (PR-14, 2026-10-21) still described the site the
   probe ran on for roots moved since, in 1.0.7 and 1.0.8. `stamp_probed_site.py` now records that
   site as `path_observed.probed_site` for every probed record, from the probe supply; the DATASHEET
   says so. The PR-14 figures in the paper come from the probe's own results and do not change.
5. **Wording of the entries above.** "First project frame" means the first frame that has a file
   and line and is neither sanitizer runtime nor C++ standard-library code; four new sites are in
   libraries the project builds from source. The stored origin was not always "the first frame
   after the interceptor": for the 8 moved origins on a `/v1/` path it was frame #2, #3 or #4. The
   silver record of outcome item 1 (CHAINFORGE-0042504315) does not lack a project frame: its
   archived log holds no sanitizer report, because 32-bit ASan aborted at startup.
6. **Disclosed, not changed.** Six new sites are compiler-generated destructors at the line
   declaring their class. Two moved records (CHAINFORGE-0042531940, -0042492862) are in the rater
   audit sample, which raters saw with their libc++ origins; the audit scores CWEs and site
   roles, not origin lines, so its figures do not change. Thirteen GOLD roots at tested sites keep
   an origin in harness code, and their CWE may be wrong; this is OPEN_ISSUES #39.

## Release 1.0.9: the kernel counted once (2026-11-09)

A review of the 1.0.8 paper found that the project count counted the Linux kernel twice. Its
syzbot records are named `linux-kernel` and its NVD race advisories `linux` (with `torvalds/linux`
from fix URLs), and `canonical_project` keeps the two apart, because the kernel splits by
subsystem and the advisory races are a catch-all. Release 1.0.9 adds `codebase()` in
`field_policy.py`, which merges them for counting only, and every project count the paper and the
supplement report now uses it. Splits, `canonical_project` and the release gate are unchanged,
and no record changes. The count of projects falls by one, and per-chain and fresh-run project
counts change only where a project appeared under two names. The paper's text was corrected at
the same time; those edits change no number.

## Release 1.0.9: hunk-test notes say what the test shows (2026-11-09)

The same review found that a root whose single-hunk test succeeded carried free-text notes
stronger than the paper and the datasheet: `patch_hunk_ref` began "CAUSALLY PROVEN: ... the
guard it adds establishes CWE-N (PR-4)", and `dataflow_evidence` ended "CAUSAL PROOF: ... so the
source link is demonstrated rather than attested." The site's stage said "from the proven hunk"
or "proven guard site", and a test that named no CWE left "guard site proven by ablation". One
input shows only that the hunk suffices for it, so its site is a tested repair site, not a proven
defect. `reword_hunk_notes.py` rewrites these to "HUNK TEST: ... which marks a tested repair
site; the check it adds names CWE-N (PR-4)", "from the tested hunk", "tested guard site" and
"guard site from a successful hunk test", and every script that writes them now uses that
wording (`chainforge.evidence`). A review before release found the stage labels and the no-CWE
note still unchanged, and they were added to the step then. No label, site, tier or evidence
kind changes. The evidence kind keeps its stored value, `causally-proven`, which the datasheet
maps to the paper's hunk-named.

## Release 1.0.9: the crashing inputs ship with the release (2026-11-09)

Through release 1.0.8 an OSS-Fuzz record's crashing input existed only inside ARVO's vulnerable
image (`/tmp/poc`), hosted in an unarchived personal Docker Hub account. For release 1.0.9 each
input was copied out of the image the record pins, by digest, without pulling the image:
`infra/repro/extract_arvo_inputs.py` reads the image manifest and streams its layers from the top
until `/tmp/poc` appears. It ran sharded on GitHub-hosted runners (chainforge-runner, workflow
`pocs.yml`), and 46 images were also copied from a second machine as a check.

Outcome (recorded after copying):
1. All 2,196 distinct vulnerable images of the 2,241 ARVO records gave an input (1,721 images for
   the 1,763 Reproduced-tier records, 475 for the Partial tier). The 46 checked copies are
   identical to the runners'.
2. Each input is at `data/evidence/arvo/<arvo_id>/poc`, listed with its image digest and sha256 in
   `data/evidence/arvo_inputs.jsonl`; `attach_arvo_inputs.py` points `pov_input` at it only when
   the record pins that digest and the file has that sha256 (op `input-attached`).
3. The inputs total about 32 MB. Seven are empty files, as they are in the images, whose
   two-sided runs reproduced with them.
4. No label, site, tier or split changes. Replay still needs the images.
