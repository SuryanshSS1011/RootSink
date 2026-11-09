# Datasheet for RootSink (working name CHAINFORGE)

Following *Datasheets for Datasets* (Gebru et al., 2021). Counts are deliberately not typed here:
they are generated from the release into `data/release/dataset.manifest.json` and
`paper_artifacts/` (`infra/verify/build_manifest.py`, `infra/paper/build_artifacts.py`), so this
document cannot drift from the data it describes.

## Paper terms and where they are stored

The paper describes concepts in plain words. This table maps each one to its field and stored
value in `dataset.jsonl`, and each protocol it describes to its entry in `PREREGISTRATION.md`.

| Paper term | Field and stored value |
|---|---|
| instance | element of `chain` (`cwe_id`, `role`, `evidence`, `site_kind`, `evidence_kind`, `cwe_basis`) |
| hunk-named (earlier "tested", "intervention-supported") | `evidence_kind: "causally-proven"` (legacy name); the test is `evidence.causal_proof` |
| sanitizer-witnessed | `evidence_kind: "execution"` |
| fix-suggested (earlier "attested") / dataflow / inferred / no evidence | `evidence_kind: "attested"` / `"dataflow"` / `"inferred"` / `"none"` |
| successful single-hunk test the guard rule cannot classify | `evidence.guard_site_proof` |
| input of the rule that assigned the CWE | `cwe_basis` |
| evidence floor | `evidence_floor` |
| tested repair site / origin site / suggested site (earlier "untested site", "annotated source site") | `site_kind: "tested-repair-site"` / `"origin-site"` / `"annotated-site"` (sinks use `"crash-site"`, UBSan intermediates `"witnessed-site"`); from 1.0.7 a tested root keeps any replaced origin in `evidence.origin_site`; from 1.0.8 no origin is a C++ standard-library frame |
| Reproduced / Upstream / Partial / Candidate tier (earlier GOLD / upstream / silver / bronze) | `label_confidence_tier: "gold"` / `"gold-upstream"` / `"silver"` / `"bronze"` |
| the Reproduced-tier criteria a record failed | `gold_contract_gaps` (criteria are PR-3 in `src/chainforge/integrity.py`) |
| duplicate group, sampling weight | `duplicate_group`, `sampling_weight` |
| the developer's fix commit(s) and repository | `commit_range.fix_commits` (every 40-hex sha, canonical) and `commit_range.repo`; `commit_range.fixed` keeps the value as the source gave it (a sha, a URL, or several shas) |
| fix-attributed (the recorded fix alone removes the crash) | `fix_attribution.status` (`true`/`false`/`null`) with `fix_attribution.basis` |
| where the root site sits against the crash | `root_site_relation`: `crash-line`, `crash-function`, `on-stack`, `off-stack`, `file-only` |
| CWE mapped from the discouraged CWE-20 (PR-17) | `chain[0].cwe_id` is 1284 or 1285; the original is `chain[0].cwe_class` (20), the rule's outcome `chain[0].cwe_mapping` (`quantity`, `index`, `class-level`) and the text read `chain[0].cwe_mapping_input` |
| MITRE edge kinds direct / transitive / inherited / hierarchy / modeling | `mitre_chain.edges[].kind`: `mitre-direct`, `mitre-transitive`, `mitre-inherited`, `mitre-hierarchy`, `catalog-only` |
| ready for reward use | `rl_ready`, details in `rl_scoring` |
| root line or function executed under a debugger | `chain[0].path_observed`; the site probed (2026-10-21) is `path_observed.probed_site`, which for a root moved since (1.0.7, 1.0.8) is its earlier site |
| hunk pair, minimized hunk | `evidence.tested_pair`; `minimal_lines` inside the successful test (`causal_proof` or `guard_site_proof`) |
| hunk that applied only with shifted context | `evidence.fuzzed_test` (withdrawn proofs: `evidence.withdrawn_causal_proof`) |

| Paper description | Rule |
|---|---|
| multi-weakness versus stage-decomposition | PR-5 |
| kernel report matching | PR-6 |
| Reproduced-tier criteria | PR-3 |
| guard rule | PR-4 |
| mining from crashes, first protocol | PR-7 |
| blind label audit | PR-9 |
| length-three chains from UBSan rebuilds | PR-10 |
| mining from crashes, second protocol (MSan, use-after-free, NULL dereference) | PR-11, PR-16 |
| reward readiness and coverage tolerance | PR-12 |
| hunk pairs and minimized hunks | PR-13 |
| debugger path probe | PR-14 |
| mapping roots to MITRE-allowed CWEs | PR-17 |
| rebuild from the projects' own source | PR-15 |

## Motivation

**Why was the dataset created?** To supervise and evaluate models that must reason about
*causal chains* of weaknesses — e.g. `CWE-20 → CWE-190 → CWE-787`, where a missing input check
enables an integer overflow that enables an out-of-bounds write. Function-scope reward signals
for secure-code RL cannot see such chains: the source is the *absence* of a guard, often outside
the function holding the sink. No prior corpus labels ordered multi-CWE chains with per-link
execution evidence; existing reproducible corpora (ARVO, Magma, Vul4J) are single-weakness.

**Who created it, and who funded it?** Suryansh Sijwali, Penn State. Compute: Penn State ROAR
HPC and a CSE KVM workstation.

## Composition

**What does an instance represent?** One observed causal chain in one program execution on one
input: an ordered list of CWE links (source → [intermediate] → sink), each with its own
evidence, plus the fix, the reproduction pointers and the sanitizer logs. Schema:
`src/chainforge/schema.py`; definitions and exclusions: `docs/SPECIFICATION.md`.

**Tiers** (a reproduction contract, not a confidence score — SPECIFICATION R5, PREREGISTRATION
PR-3):

- `gold` (Reproduced in the paper) — we re-ran it both sides: the vulnerable revision crashes with the witnessed sink, the
  patched revision runs the same input clean (the input demonstrably executed), both logs are
  archived here, the patch can carry the guard, and the source does not contradict the crash.
- `gold-upstream` (Upstream) — execution-witnessed by syzbot, one-sided, not re-performed by us.
- `silver` (Partial in the paper) — reproduction or dataflow evidence that falls short of the Reproduced-tier contract.
- `bronze` (Candidate) — ordering from co-occurrence or heuristics only.

**Per-link evidence kinds**, strongest first: `causally-proven` (guard ablation: the fix's hunk
alone silences the sanitizer; the source CWE follows from what the guard checks, PR-4),
`execution`, `attested`, `dataflow`, `inferred`, `none`. Every record carries `evidence_floor`,
its weakest link. Tier and floor are orthogonal: select on the one your claim depends on.

**Is anything missing?** Yes, and it is measured rather than hidden — see
`docs/OPEN_ISSUES.md`. Notably: length-3 chains are rare in the Reproduced tier; most of the Reproduced tier
is ARVO-derived; some links carry no evidence (`floor = none`).

**Does it contain data that could be considered sensitive?** It contains proof-of-vulnerability
inputs and reproducers for *already fixed* public bugs. The only personal data are what the
projects already publish in their commit history: many records' `patch_diff` keeps the commit
header, with the author's name and e-mail address, and some logs and diffs name developers.
Nothing about any person was collected beyond that.

**Are there recommended splits?** `split` keeps each project in one fold, except that the Linux
kernel is split by subsystem and the advisory-race catch-all `linux` is not consolidated; `eval_stratum` marks held-out-arm and length-3 protocols, which cannot coexist with
project-disjointness. `fix_date` / `disclosure_date` support a temporal split chosen per base
model.

## Collection

Sources: OSS-Fuzz crashes via ARVO's reproducible images; syzbot (Linux kernel) reports and C
reproducers; OSV.dev and NVD for fix commits and CVE metadata. Every execution witness was
produced by our own re-run except where `observed_by: "upstream"` says otherwise.

- ARVO cases: replayed in the pinned images (`docker_image_ref`, digest-pinned) under
  Apptainer or Docker, both revisions, patched side twice. The Reproduced tier requires two clean
  patched runs (PR-3 I5); records first assembled with one run were re-run or left the tier.
- Kernel: syzbot reproducer replayed under KASAN with real SMP on KVM, at `fix^` and `fix` built
  from the fix's own tree; the KASAN report at `fix^` must match the syzbot bug.
- Single-hunk intervention: hunks of the developer's fix tried alone on the vulnerable revision,
  smallest first, rebuilt and replayed (a kernel hunk must run clean on two boots, and on three in the
  1.0.5 reruns, which let the control boot up to three times); the unmodified rebuild must crash (control); the first
  hunk that runs clean is kept. It is a sufficient tested hunk on this input, not a minimized or
  unique repair. Optional: the Reproduced tier does not require it.

## Preprocessing, cleaning, labeling

Every rule that decides a label is written down with its date (`PREREGISTRATION.md`), applied by
code, and logged. PR-1..PR-9 were frozen after exploratory development and their dates are
self-reported (history before 2026-10-19 was squashed); selections and amendments since then were
committed before their outcomes, except where a dated entry discloses that it was written after. No language model assigns labels. `data/release/corrections_changelog.jsonl` records each change with its rule id,
`dropped.jsonl` each removed record with the reason. `infra/verify/conformance.py` enforces the
specification and fails the release on any hard violation. Label correctness is the
subject of a blind two-annotator audit (PR-9, `infra/verify/irr.py`; precision with Wilson
intervals, Cohen's κ and Gwet's AC1). Two raters' sheets are scored, with agreement between them. Both
raters are co-authors who did not build the dataset and rated blind to its labels. Three
language models rated the same packet in a registered exploratory check and never count as raters.

## Uses

Intended: training and evaluating vulnerability *chain* reasoning; source localisation from a
sink crash; reward design for secure-code RL (task inputs come from `chainforge.field_policy`'s
`policy_view`, `localization_view` and `labeling_view`, targets from `task_target`; identity
fields such as provenance and project leak the label and are harness-only); studying guard
absence. Not intended: as a benchmark of fuzzer-undiscoverable bugs (the corpus inherits
OSS-Fuzz/syzbot discovery bias), or as an exploit collection.

## Distribution

To be archived on Zenodo with a DOI at release; code on GitHub (MIT, `LICENSE`). **Labels and annotations:
CC-BY-4.0.** Upstream material — fix diffs, sanitizer-log excerpts, PoV inputs, kernel
reproducers — remains under each project's license, recorded per record in `license` (SPDX,
resolved by `infra/verify/fetch_licenses.py`; projects whose license GitHub could not detect were read
by hand from their own license files, each recorded with its source URL and any judgement made in
`infra/verify/license_overrides.json`; `NOASSERTION` where a license could not be determined,
never guessed). For three projects, binutils-gdb, poppler and libspectre, the upstream hosts could not be reached from the checking host, so their licences were read from Debian's copyright files for those packages (2026-11-07, URLs in the overrides file); `apply_license_overrides.py` lists any record still unresolved. Ids taken from GitHub's license detector
keep its legacy spelling for the GPL family (`GPL-2.0`, `GPL-3.0`, `LGPL-2.1`), which records the
license text but not whether the project chose "-only" or "-or-later" (that choice lives in file
headers); hand-checked and kernel records use the explicit forms. Full kernel console logs are in the release
archive under `data/evidence_full/`.

## Maintenance

Maintained by the authors. Errors are corrected by a new dated rule or a changelog entry,
never a silent edit; versions are tagged and archived. Report issues on the GitHub repository.
