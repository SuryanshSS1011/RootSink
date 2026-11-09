# CHAINFORGE specification: what a causality chain is, and what it is not

No prior dataset labels ordered multi-CWE causal chains with per-link execution evidence, so
these conventions are not inherited from anywhere. That is the reason to write them down
hard, and to make the exclusions as explicit as the inclusions: a first dataset's loose
definition becomes everybody's loose definition.

Two neighbouring uses of the word "chain" must not be confused with this one:

- **CrossCommitVuln-Bench** chains *commits* across version history — which change introduced
  the flaw. That is a temporal chain in a repository.
- **MITRE CWE-1000 CanPrecede / Named Chains** define which weakness *classes* may follow
  which. That is a taxonomy of possibility.

CHAINFORGE chains *weaknesses within a single program execution*. MITRE says a pair is
possible; a CHAINFORGE record says this pair actually occurred, here, on this input.

## Terminology: adopted, not invented

CHAINFORGE uses the established vocabulary and maps its schema onto it:

| here (schema) | MITRE CWE | NIST Bugs Framework (SP 800-231) |
|---|---|---|
| chain | **Chain**: "a sequence of two or more separate weaknesses that can be closely linked together" | a vulnerability is "a chain of weaknesses linked by causality" |
| `role: source` | **primary** weakness: "an initial, critical error (root cause)" | the weakness that "relates to the root cause" |
| `role: intermediate` | resultant of the previous link, primary to the next | error → fault propagation (consequence ↷ cause) |
| `role: sink` | **resultant** weakness: "a later link in a chain" | the weakness that "relates to its sink" / final error |
| an admissible edge | **CanPrecede** (its inverse, CanFollow) | — |
| `chain_string` | the `X->Y->Z` syntax of the CWE Top 25 (2022) and Red Hat's cwe-toolkit | — |

Sources: https://cwe.mitre.org/documents/glossary/ ,
https://cwe.mitre.org/data/reports/chains_and_composites.html , NIST SP 800-231.

Two neighbouring terms are deliberately **not** used: a MITRE **Composite** (weaknesses that must
all be present at the same time) is not a causal sequence, and an **exploit chain** (several CVEs
used in one attack) is a chain of vulnerabilities, not of weaknesses within one.

---

## R1. What a chain is

> A **causality chain** is an ordered sequence of two or more CWE instances, observed in one
> program execution on one input, where each weakness causally enables the next.

Four requirements, all mandatory:

1. **Ordered.** `[A, B]` asserts A enabled B. It is not a set. `[B, A]` is a different claim.
2. **Single execution.** Every link must be attributable to the same run on the same input. Two
   weaknesses found by two different inputs are two records, not one chain.
3. **Causal, not co-incidental.** B must occur *because* A did. Co-occurrence in a CVE, in a
   file, or in a function is not causality.
4. **Admissible.** Every consecutive pair must exist in the catalogue (`cwe.py`), which is
   grounded in MITRE CWE-1000 relations.

## R2. What is explicitly NOT a chain

These are the rules that matter most, because each names a mistake that is easy to make and
that we have made:

- **Co-occurrence is not a chain.** Two CWEs on the same CVE may be two analysts describing
  one bug differently, or two unrelated bugs in one advisory. NVD co-occurrence is a
  *prevalence prior*, never a label.
- **Alternative labellings are not a chain.** A use-after-free *read* is CWE-416. Calling it
  `416 -> 125` because the read is out-of-bounds-of-the-freed-object records one weakness as
  two. Where we do this it is declared as a modelling approximation (R7), not passed off as an
  observation.
- **Allocation and free sites are not CWE instances.** A KASAN report's alloc/free/use stages
  are three *stages of one weakness*, not a three-link chain. `malloc` is not a weakness.
- **A default source attribution is not a chain link.** Assigning CWE-20 because the sink was
  an out-of-bounds read asserts a missing input-validation check that nothing demonstrated.
  Such a link must be marked unattested (R4) and must not be counted as evidence for the
  guard-absence claim.
- **A composed chain is not an observed chain.** Joining a validated `A->B` hop to a validated
  `B->C` hop asserts that both occurred on one execution. Unless that execution happened, this
  is a hypothesis. CHAINFORGE ships zero composed chains.

## R3. Evidence is per LINK, not per record

A record does not have "evidence". Each link does, and they routinely differ: the sink is
witnessed by a sanitizer while the source is inferred from a patch. Collapsing these into one
record-level tier is the single easiest way to overstate a dataset.

Evidence kinds, strongest first:

| kind | means | example |
|---|---|---|
| `causally-proven` | applying **only** the guard hunk to the vulnerable revision, rebuilding and replaying the same PoV silences the sanitizer | skia `SkSwizzler.cpp` +9 lines: control crashes, guard-only build runs clean |
| `execution` | a sanitizer report attributes this link to a concrete site (a file, or the function a kernel report names); from 1.0.7 a root moved to its tested site keeps this kind, and the reported site is `evidence.origin_site` | MSan origin block names the allocation or declaration that created the uninitialised value |
| `attested` | the fix demonstrably adds the guard whose absence is the link | patch adds `if (len > MAX) return -1;` for a CWE-190 source |
| `dataflow` | a static path (Joern/CodeQL) supports the ordering; nothing ran | `reachableBy` finds a source-to-sink path |
| `inferred` | derived from crash class or CWE assignment, with nothing observed | CWE-20 assigned because the sink was an OOB read |
| `none` | the link records no evidence at all | — |

`causally-proven` is the only kind that demonstrates causation rather than correlation, and it
is admissible **only** when the unmodified rebuild crashed. Without that control a clean run is
indistinguishable from a build that cannot reproduce at all — the same confusion R10 forbids.

**A chain is only as strong as its weakest link, and that must be visible.** A record with an
execution-witnessed sink and an inferred source is not an execution-witnessed chain.

This is machine-readable rather than prose. Every link carries `evidence_kind` and every
record carries `evidence_floor`, the weakest kind across its links, so the query this rule
implies — *every link at least execution-witnessed* — can actually be written.

The result should be read alongside the tier, because they measure different things and
diverge sharply: GOLD is a reproduction contract about the *sink* (R5) and says nothing about
whether the source link was ever observed, and some SILVER records are better evidenced per link
than most GOLD. Tier and evidence floor are orthogonal axes; a consumer should select on whichever
one their claim depends on. The counts are generated from the release, never typed here — see
`paper_artifacts/tables.md` (T2, floor by tier), rebuilt by `infra/paper/build_artifacts.py`.

## R4. Unattested links must say so

Where a link's evidence is `inferred`, the record must state it in that link's evidence field.
Silence is not permitted, because silence reads as attestation.

This is not cosmetic. Before this rule, 679 records asserted a missing-check source with no
supporting evidence; the rule converted them into 384 records that say so explicitly and 173
that earned an attestation once the patch was actually fetched.

## R5. Tiers are about reproduction, not confidence

The tier names a *reproducibility contract*, not a subjective belief.

- **GOLD** — *we* re-ran it, both sides: the vulnerable revision crashes with the witnessed
  sink, the patched revision runs the same input clean, and both logs are archived here. The
  patch can carry the guard, the source does not contradict the sink's own report, and a
  length-3 chain's intermediate link is execution-witnessed. The full contract is
  PREREGISTRATION PR-3 (I1–I6), enforced by `chainforge.integrity` in both the release
  transform and `conformance.py`. GOLD asserts: *you can re-run this, and we did.*
- **GOLD-UPSTREAM** (`gold-upstream`) — execution-witnessed by the discovering project (a syzbot
  KASAN report we cite), one-sided, and not re-performed by us. Never returned by a filter on
  `gold`, so the obvious query is also the strict one.
- **SILVER** — a dataflow path or partial witness supports the ordering, but the execution
  contract is not met.
- **BRONZE** — ordering rests on co-occurrence or heuristics with no dataflow or execution.

Two hard rules on GOLD:

1. **A patch URL is not a patch.** The patch must be carried as content. A link expresses no
   guard, cannot support a counterfactual, and rots when the forge moves.
2. **GOLD is two-sided.** `differential_complete: true` with a *clean* patched run whose input
   demonstrably executed. Silence is not cleanliness: a patched run that never reached the input
   also prints no sanitizer line (R10). One-sided execution witnesses are `gold-upstream` or
   SILVER, never GOLD.

## R6. Observation provenance must be declared

Every sanitizer report records `observed_by`:

- `self` — we executed it and archived the log in this repository.
- `upstream` — the discovering project observed it and we cite their permanent report.

Both are execution witnesses; they are different claims. A consumer auditing reproducibility
needs to know which runs they can re-perform. Blurring these would let a dataset claim
reproduction it never performed.

## R7. Modelling approximations are declared, never hidden

Where the catalogue deviates from a strict reading, it is stated in the record and the
catalogue:

- `416 -> 125` — a use-after-free read reads freed-but-often-in-bounds memory. CWE-125 is an
  approximation of the sink, adopted deliberately and declared.
- `362 -> 415` — grounded through CWE-364, a child of CWE-362; the classifier reports this as
  `catalog-only`, not `mitre-direct`.

The test for admitting an approximation: could a reader who disagrees with it *subset it out*?
If not, it must not be admitted.

## R8. Localization is what makes a chain supervisable

Each link should carry `file:line` from an execution witness. Without it, the label is
recoverable from record metadata alone — a classifier predicting the chain from
project/provenance/ecosystem/language is right far above baseline (T4) — so a consumer can score well
without reading code. A line number is not predictable from metadata.

Sites derived from an archived upstream report rather than our own run are stamped as such
(`stage: "crash (ARVO archived report)"`).

## R9. Splits must be disjoint on the axis being claimed

- **Project-disjoint** is the default (the Linux kernel is split by subsystem, and the advisory
  race catch-all `linux` is not consolidated); a random split trains and tests on the same
  project.
- **Chain-type-disjoint** and **length-3** are separate protocols, marked in `eval_stratum`,
  because they cannot hold simultaneously with project-disjointness — withholding a whole arm
  puts its projects on both sides.
- **Temporal** control is enabled by shipping `fix_date` / `disclosure_date` rather than a
  precomputed fold, since the cutoff depends on which base model a consumer uses.

## R9b. Fields are typed by who may see them

A dataset for RL has two audiences that must not be confused: the harness that builds splits
and computes rewards, and the **policy** being trained. Fields useful to the first are often
catastrophic to the second, and nothing in a record says which is which.

Leakage is measured **held out**: predict `chain_string` as the majority arm among the *other*
records sharing a field's value (`chainforge.field_policy.measure_leakage`; the numbers are
generated into `paper_artifacts/tables.md`, T4). The identity fields leak most — provenance and
project alone, and their combination with ecosystem and language most of all.

Measuring in-sample is a trap we fell into: a value unique to one record "predicts" that record
perfectly, so `fix_date` (64% of values unique) looked like the worst leak at 69% when, held
out, it barely clears the year-coarsened date. It stays harness-only regardless — a policy given
a near-unique key can still memorise it in training.

The remedy is not deletion — split construction genuinely needs these — but declaration.
`chainforge.field_policy` names every field `MODEL_VISIBLE` or `HARNESS_ONLY`. Task inputs come
from `policy_view` (repair), `localization_view` and `labeling_view`, each withholding its task's
target, and `task_target` gives the answer; `annotation_view` (formerly `model_view`) shows
labels and is never a task input. A field left out of both sets is a
bug, and the classification is asserted to be total.

`chain` and `chain_string` stay model-visible because they are the **target**, not a feature.

## R10. Negative results are recorded, not discarded

A case that failed to reproduce, an arm found unreachable, a candidate rejected for scope — all
are recorded with the reason. This dataset's central claim is reproducibility; a corpus that
silently drops what would not reproduce is selecting for a result.

Corollary, learned repeatedly: **an infrastructure failure must never be recorded as a negative
observation.** An empty console, a binary that exited before `main`, a build that never ran —
none of these are evidence the bug is absent. Every check must distinguish "did not happen"
from "could not be tested".

---

## Conformance checklist

A record conforms if:

- [ ] every consecutive CWE pair is in the admissible catalogue
- [ ] all links are attributable to one execution on one input
- [ ] each link declares its own evidence kind; inferred links say so
- [ ] GOLD carries patch **content** that can carry the guard, and archived logs of a crash at
      the vulnerable revision and a clean executed run at the patched one (PR-3)
- [ ] every sanitizer report declares `observed_by`
- [ ] `differential_complete` is true only with a clean patched-revision run
- [ ] any modelling approximation is declared and subsettable
- [ ] the record is not composed from separately observed hops
