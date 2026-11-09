# Open issues and their cures

Every known defect in the release, with the cure, whether it is reachable, and its state. An
issue with no cure is listed as such rather than left implied — a dataset paper is judged partly
on knowing where its own floor is.

Figures are as of the PR-3 release, 2026-10-01: 2,163 chains, 366 GOLD, 622 GOLD-UPSTREAM.
Live figures are in `data/release/dataset.manifest.json` and `paper_artifacts/`, both generated;
where this file and they disagree, they are right.

---

## Cured 2026-10-01 by PREREGISTRATION PR-3

PR-3 restates GOLD as a contract — our own two-sided run, archived, on a patch that can carry the
guard, with a source its own crash does not contradict — and enforces it with one module
(`chainforge.integrity`) used by both the release transform and `conformance.py`. Applying it:

- **I1** 19 byte-identical rows removed; 115 records dropped where one OSS-Fuzz crash carried two
  mutually exclusive source claims (102 were `416→787` and `476→787` on the same log, both GOLD).
- **I2** 169 GOLD demoted: a CWE-416 source on a crash the sanitizer reports as a buffer overflow,
  or a CWE-476 source with no NULL dereference. The sources came from Joern `reachableBy`.
- **I3** 99 GOLD demoted whose patch cannot carry the guard (#18).
- **I4** all 62 length-3 GOLD demoted: none had an execution-witnessed intermediate link.
- **I5** 621 syzbot GOLD moved to `gold-upstream` (PR-2 had said "never GOLD"; that promotion was
  a pre-registration violation, now amended). ARVO GOLD whose patched-run log was never archived
  are SILVER until re-run (in progress on ROAR, logs archived this time).
- **I6** 12 causal proofs withdrawn (#17): the 9 found earlier plus 3 oniguruma proofs on
  `harnesses/base.c` that both path rules missed. One shared rule now serves both.

Every change is in `corrections_changelog.jsonl` with its rule id; every dropped record is in
`dropped.jsonl` with the record it lost to.

---

## Cured

### 1. `which` shell function broke 92% of ablation builds
**Symptom.** 194 of 210 ablation control runs died with `cp: cannot stat 'args'`.
**Cause.** Debian defines `which` as a shell *function* that pipes through
`/usr/bin/which --tty-only --read-alias --read-functions ...`; these images ship a `which` that
rejects those flags, so it prints its usage, and OSS-Fuzz's `cp $(which llvm-symbolizer) /out/`
takes that usage text as filenames. Apptainer sources a profile defining the function; Docker
does not, so the bug is invisible outside our setup.
**Cure.** `unset -f which` before compiling. One line. 208 blocked cases re-running.

### 2. Apptainer ignores the image's Docker `WORKDIR`
**Symptom.** Every in-container rebuild failed on its first relative path; recorded for weeks as
"the UBSan rebuild is Docker-only", which wrongly constrained the CWE-190 plan.
**Cure.** Derive the build directory from where `build.sh`'s first `cd`/`pushd` points. Control
failures fell 35 → 8 on the first batch.
**Reopened and re-cured 2026-09-07.** That rule matched the whole `cd` target against `ls /src`,
so a multi-segment target could never match (jsoncons opens `cd jsoncons/fuzzers`, needs `/src`,
got `/src/jsoncons`), and a `build.sh` opening on a command rather than a `cd` (`./ossfuzz.sh`,
`./configure`) gave no signal at all: 19 of the 39 control build failures in the `ablatefull`
batch. Replaced with a witness probe — take a path out of `build.sh`, test where it resolves.
Verified against the failing shapes with skia and libucl as regression guards; **not yet run
against real containers**, and #12 is the reason to insist on that before a full batch.

### 3. Patch evidence was a URL, not a patch
**Symptom.** 1,277 records stored a link where `patch_diff` should be, satisfying the GOLD
invariant's letter while carrying no guard and rotting when a forge moves.
**Cure.** Host-aware fetch: 1,184 materialised (93%). The 50 that stayed unretrievable were
**demoted to SILVER**, which is the rule working. 419 records still lack patch content, all
either unfetchable or provenances that never had one.

### 4. Label leakage was measured in-sample — **corrected 2026-10-01**
**Symptom.** `fix_date` appeared to predict `chain_string` 69.2% of the time, the worst field.
**What was wrong.** That was in-sample majority accuracy: a value unique to one record "predicts"
that record perfectly, and 64% of `fix_date` values are unique. Held out (leave-one-out) it is
about 35% against a 23% baseline. The real leaks are the identity fields: provenance ≈53%, and
project+provenance+ecosystem+language ≈57%.
**Cure.** `field_policy.measure_leakage` computes held-out leakage from the release; the manifest
and paper tables are generated from it, so the figure cannot go stale again. `fix_date` stays
harness-only, as do the identity fields.

### 5. GOLD claimed re-runnability nothing had tested
**Symptom.** R5 defines GOLD as "you can re-run this", but every witness came from a *single*
run, so a flaky case shipped indistinguishably from a deterministic one.
**Cure.** A determinism gate (5 replays, ASLR addresses normalised out of the signature).
23/23 sampled GOLD records deterministic.

### 6. R3's core rule was prose, not data
**Symptom.** "A chain is only as strong as its weakest link, and that must be visible" — but the
kind had to be recovered by regex over free text; 752 links were unclassifiable.
**Cure.** `evidence_kind` per link, `evidence_floor` per record.

---

## Open, with a known cure

### 7. Evidence quality and arm diversity are anti-correlated
**Symptom.** The strict subset (`floor ≥ execution`, n=313) is **93% one arm**. Training on it
yields a `CWE-456→CWE-457` detector, not a chain detector. Cause is structural: MSan with origin
tracking is the only pipeline witnessing *both* links, so the filter nearly restates "is an MSan
record".
**Cure.** Guard ablation — the only mechanism that witnesses a source link where no sanitizer
can. 140 proofs across 81 projects — 131 valid, see #17 — carry higher arm-entropy than the
412-record attested subset (1.37) at a fraction of its size. The lever has not yet broken the
concentration it exists to break: 87 of the 140 are `CWE-20→CWE-125`.
**State.** The 299-case batch finished 2026-09-03: 138 proven, 90 genuine negatives (control
crashed, every hunk tried), 71 no verdict. **This is the dataset's main outstanding lever.**

### 8. 931 records rest on an inferred weakest link
**Symptom.** Their source is a CWE assigned because of the sink's crash class.
**Cure.** Ablation where the image rebuilds (429 candidates); explicit `NOT attested` marking
otherwise, which 366 now carry. Both are done or in progress; the residue is bounded by how many
images still build.

### 9. ARVO supplies almost all strict GOLD
**Symptom.** After PR-3, 99% of strict GOLD is ARVO-derived: the kernel records that diversified
it were upstream-witnessed and are now `gold-upstream`. Over-reliance on one upstream corpus is the
main external criticism available.
**In progress.** The kernel differential batch (KVM box, `fix^` vs `fix`, positive control
passed) is the direct cure: each success is a non-ARVO strict GOLD.
**Cure.** Non-ARVO sources. `osv-git` proved reachable — one GOLD built from source
(pcapplusplus, `ModbusLayer.cpp:55`) — but at roughly one per twelve hand-fixed cases. syzbot is
the larger pool.
**Cost.** Real and per-project. No shortcut found.

### 10. 622 kernel records are one-sided (`gold-upstream`)
**Symptom.** Each cites an upstream syzbot report with no patched-revision counterpart, so the
counterfactual is undefined. Only 1 is two-sided.
**Cure.** KVM differential replay, which works: `betop_probe` crashed at `fix^` and ran clean at
`fix`. Needs the CSE box; ROAR has no KVM and failed 0/20 twice there.
**State.** Batch was running when the host became unreachable.

### 11. Length-3 has no GOLD after PR-3 (87 records, all SILVER or below)
**Cure.** Ablation reaches these too — one len-3 record is already causally proven. The
UBSan-rebuild route would grow the stratum, but see #12.
**Not the cure.** Composing len-3 from validated len-2 hops. That asserts two independently
observed hops occurred on one execution; the dataset ships zero composed records deliberately.

---

## Open, cure unproven

### 12. UBSan rebuild invalidates the image's prebuilt artifacts
**Symptom.** Switching `SANITIZER` from `address` to `undefined` breaks the link: skia's
`libskia.a` carries ASan sancov constructors into discarded sections; capstone rebuilds AFL
itself under the new flags. 8/8 failed.
**Candidate cure.** Clean-rebuild hygiene — purge prebuilt objects, or pin the engine's
artifacts. Untested. Note the *first* diagnosis here (Docker-only) was wrong, so this one
deserves scepticism until it runs.

### 13. Identity fields leak the label (≈57% held out, four fields combined)
**Partial cure.** The field policy stops a policy *seeing* the leaky fields, and 96 fresh
projects entered via the last ablation batches.
**Full cure.** Structural — more projects per arm and more arms per project — which means
sourcing breadth, not depth. Not achievable by reshaping what we hold.

---

## Open, found 2026-09-07

### 17. Twelve causal proofs rested on a fuzz-harness hunk — **cured 2026-10-01 (PR-3 I6)**
**Symptom.** `CAUSALLY_PROVEN` is the dataset's strongest evidence kind: applying that hunk
alone silences the sanitizer. For 9 of the 140 the hunk is in the fuzz harness — lwan's is
`size = min(sizeof(copy) - 1, size)` in `template_fuzzer.cc`. The crash stops because the
harness no longer feeds the triggering input; the library is unchanged. The ablation cannot
tell the two apart, so the proof is real about the hunk and false about the source.
**Cause.** `split_hunks.py`'s IGNORE list excluded tests and docs but not `fuzz/`, so harness
hunks entered the candidate set and could win.
**Cure.** IGNORE widened to cover `fuzz|fuzzing|fuzzer|fuzzers|harness` directories and
`*_fuzzer.c` / `fuzz_*.c` filenames — shipped, so no future batch can produce one.
`causal_proof_defect` flags the existing 9, and conformance now fails HARD on them.
**State.** The 9 need their proofs withdrawn. Affected: skia ×2, libspdm ×2, libconfig ×2,
botan, libdwarf, boringssl, and (found 2026-10-01) oniguruma ×3 on `harnesses/base.c`. All 12 are withdrawn into `withdrawn_causal_proof`; the honest proof count is **128**.

### 18. 106 GOLD patches could not carry the guard they were cited for — **cured (PR-3 I3)**
**Symptom.** Issue #3 replaced pointers with patch content. Content is necessary, not
sufficient: 91 diffs touch no non-test source file (curl's resolved fix for a
`CWE-416→CWE-787` is a `Makefile.am` change; libgit2's is `ci/test.ps1`; mbedtls's is a
ChangeLog entry), 14 are cut mid-hunk, 1 is a different commit than the record names.
**Cause, split by kind.** For 85 the fix commit ARVO itself recorded is the harness/doc commit,
so this is not a fetch failure — re-fetching from ARVO's own URL returns the same thing.
The truncations were four call sites doing `diff[:200_000]` as a naive slice.
**Cure, partial and shipped.** `clip_patch` cuts on hunk boundaries and is wired into all four
sites; `refetch_defective_patches.py` recovered 8 truncated diffs from their full commits.
`guard_evidence_defect` + a manifest field (`gold_patch_can_carry_guard`, 1,433 of 1,539) make
the residue visible instead of implied.
**Open.** The 85 are a labelling question, not a fetch one: a harness-only fix means either the
bug was in the harness or the harness stopped reaching it. Neither supports GOLD, so they need
demotion or an independently resolved fix commit. **Not done — it changes 85 tiers.**

### 19. The differential oracle is confounded for 82 GOLD
**Symptom.** GOLD asserts crash-at-vulnerable, clean-at-patched. Measured over the fix commits:
1,402 touch source only, **43 touch only the fuzz harness**, 39 touch harness *and* source. For
the 43 the clean patched run is explained by the harness change, so the counterfactual does not
isolate a source guard; for the 39 it cannot be attributed to one.
**Cure.** Unknown for the 43 without re-resolving each fix. For the 39 the guard ablation
already discriminates, since it applies one hunk at a time — running it on those is the cheapest
route and they are in the existing candidate pool.
**Why it matters.** This is a property of building on ARVO, not of our pipeline, and it is the
first measured statement of it we have. It belongs in the paper's limitations either way.

---

## Open, found 2026-10-08

### 20. One codebase under several project names broke the project-disjoint split — **cured 2026-10-08**
39 projects were filed under 2–4 names (`php-src` / `php/php-src`, forks such as `vadz/libtiff`),
and 30 of them had names in different splits. `field_policy.canonical_project` now gives one
identity per codebase; `dedup_groups.py` moves each split-spanning project into the split holding
most of its records (52 records, 1 GOLD; logged as `project-alias-split`) and keys duplicate groups
on the fix commit alone; `split_unit` uses the canonical name; conformance has a HARD rule
`R9 a project (canonical name) spans splits`. linux-kernel (subsystem-split) and the `linux`
catch-all (#21) are exempt. Duplicate rate and per-key counts: `paper_artifacts/duplicate_audit.json`.

### 21. `nvd-race` files every CVE under project `linux`
All 234 `nvd-race` records carry project `linux`. NVD's affected products
(`infra/verify/nvd_products.py` → `data/cache/nvd_products.json`) show ~88 are the kernel,
~55 Android, ~70 closed-source products (Windows, Junos, HarmonyOS, Qualcomm firmware, Comodo,
F5), and the rest Firefox, libvips, GRUB2 and others. 232 ship no patch or PoV.
**Cure.** Set `project` from the NVD product where it names one open-source codebase; decide
whether closed-source CVEs (no code, no reproducer possible) belong in the release at all.
Licenses already follow the NVD product for the kernel cases (`fetch_licenses.py`).

### 22. 141 non-GOLD patches touch no source code
76 `patch_diff`s change only build/CI/docs files (`configure.ac`, `ChangeLog`, release bumps), 44
only fuzz harnesses or tests, and 20 have no file headers. One GOLD (`CHAINFORGE-0800546`, a
kernel MAINTAINERS/defconfig diff) is in the first group. PR-3 D4 demoted harness/doc-only
fixes for GOLD; the non-GOLD tiers were never checked.
**Cure.** Apply the D4 path rule to every tier (or ship a `patch_kind` flag) and re-fetch the
real fix for the GOLD record.

### 32. A checked return value is labelled input validation (found 2026-10-29)

PR-4's guard rule names CWE-252 (unchecked return value) only toward a NULL-dereference sink
(PR-16). Elsewhere a hunk that checks a value a call returned, such as `if (len != -1)` after
`len = u8_u16(...)`, falls to the CWE-20 row. In 27 GOLD CWE-20-family roots the tested hunk adds
such a check (heuristic count, `PREREGISTRATION.md`, corrections for 1.0.2). A reader may call
some of these CWE-252. **Cure:** a new pre-registered rule that names CWE-252 whenever the added
check tests a call's result, applied in a later release, with the blind audit's verdicts on these
roots as the check.

### 31. Half of GOLD's roots used a CWE MITRE discourages (found 2026-10-24)
CWE 4.20 marks CWE-20 and CWE-119 DISCOURAGED for mapping, and 976 GOLD roots were CWE-20. With
those labels the crash class alone predicted the held-out root CWE for 99% of test records.
**Cured 2026-10-24 (PR-17).** CWE-20 roots name the allowed child their check bounds (CWE-1284
quantity, CWE-1285 index/offset/position) from the tested hunk or the fix; 411 GOLD roots whose
check bounds neither keep CWE-20 as `class-level`. The crash-class baseline falls to 62%. UBSan
index sinks are being mapped from CWE-119 to 125/787 by the access at the reported column.

### 30. GOLD's fixed side is ARVO's fixed image, not the recorded fix (found 2026-10-23)
The fix-distance probe found ARVO's fixed image differs from "vulnerable image + recorded fix" in
106 of 109 measured images where the fix alone did not stop the crash, and in 28 of 29 ready ones.
**Cured 2026-10-24.** `fix_attribution` records whether the recorded fix alone removes the crash
(1,418 GOLD: 1,218 ARVO by scorer replay, 200 kernel by construction); the recommended core
requires it. GOLD's definition is unchanged and the paper states what its fixed side is.

### 29. A tested repair site may guard the symptom (found 2026-10-24)
Smallest-first single-hunk tests favour small guards near the crash: of 744 placed tested sites,
191 lie within five lines of the crash in the crashing function. **Measured, not cured.**
`root_site_relation` marks each; the label audit's `crash` role and the PatchBench comparison
(7 of 16 shared tested sites in a function the curated root-cause patch edits, 4 more in its
file) are the checks. A fix that tested hunks by distance from the crash first is future work.

### 27. Kernel `fix^`/`fix` runs fail to build on hosted runners (found 2026-10-22)
The runner's `kdiff` workflow built 56 syzbot cases: 43 vulnerable kernels failed to build
(objtool, x86 thunks, `__read_overflow2` with the runner's newer compiler), 8 had an untestable fix
and 4 reproducers failed to compile. All are infrastructure outcomes (R10) and nothing was
attached. **Partly cured 2026-10-23.** `kdiff_kvm.sh` now builds kernels older than 5.8 inside a
`gcc:8` or `gcc:9` container. The 42 retried cases gave 6 differentials (attached: 4
gold-upstream records became GOLD, 2 became SILVER), 1 vulnerable kernel that did not reproduce
and 35 build failures. Of those, 14 failed in the bpfilter helper, 4 in objtool's `str_error_r`
under gcc 8 (kernels before 4.19 need gcc 7), 15 fell back to the host's gcc 10.5 because the
era container did not build, and 2 are source or Kconfig defects of one revision. The script now
uses gcc 7 before 4.19, retries the container build and stops as infrastructure
(`toolchain_missing`) instead of falling back, and disables bpfilter and the one broken panel
driver under compat. Second retry (2026-10-23, 35 cases): 5 more differentials (all
gold-upstream to GOLD, every one a 4.17 kernel built with gcc 7), 6 vulnerable kernels that did not
reproduce, 7 that crashed with a different bug, 5 stopped as `toolchain_missing` (the gcc 9 image),
10 kernels from 5.8 to 5.11 whose objtool failed under the host's gcc 10.5 and binutils, and 1
source defect. The image build had a second bug, retries reading an empty Dockerfile from a
consumed pipe; it now builds from a file, and a probe confirms the gcc 7, 8, 9 and 10 images build.
Kernels from 5.8 to 5.15 now use the gcc 10 image (binutils 2.35). Third retry
(2026-10-23, 15 cases): every kernel built, giving 5 more differentials (gold-upstream to GOLD), 7
that did not reproduce and 3 that crashed with a different bug. **Build failures cured.** Over the
42 cases, 16 are differential and 1 is a source defect of its revision; the rest built but did not
show syzbot's bug on the vulnerable kernel, which leaves those records gold-upstream.

### 26. Site function names cut at the first space (found 2026-10-22)
227 site function names were stored cut at their first space (`Foo::bar(int,`), and 7 of those
were `(anonymous`, which names no function; 4 tested sites named a statement (`if`) from git's
hunk-header heuristic. **Cured 2026-10-22.** `repair_function_names.py` restores 225 from the
record's own report (2 have no matching frame), `guard_site` no longer reports a keyword, and
`bare_function` sees through `(anonymous namespace)::`. Both run in `rebuild_derived.sh`.

### 25. ARVO images ship the fix in their git history (found 2026-10-21)
A probe of 8 vulnerable images on the runner (`data/validation/env_probe.json`) found the
developer's fix commit reachable in the project repository under `/src` in all 8, so an agent
given the image can run `git show <fix>`. Docker's default network was also reachable from some
images. This does not affect the replay or the scorer, which only applies a given patch, but it
breaks any agent environment built directly on the image.
**Cure.** `infra/repro/agent_env.sh` starts the image with `--network none` and rewrites every
repository under `/src` to one commit holding the vulnerable tree. A runner check
(`agentenv` workflow) confirms the fix becomes unreachable and the project still builds.
**Cured 2026-10-22.** On the 8 probed images the fix is unreachable in all 8. The ffmpeg
build that failed offline needed x265's version from `git describe`, so `agent_env.sh` now keeps
the vulnerable revision's newest tag (it names the past only). A seeded check of 41 images, one
GOLD case per project (`data/validation/agent_check.json`), finished 38: the fix is unreachable
in all 38 and 31 build offline. Of the 7 that do not, 5 fetch dependencies while building (apt,
wget, rsync), so they build online but not offline even unmodified, and 2 fail online too. The
rewrite broke none. An environment that must rebuild those 5 needs a package mirror the agent can
reach, which is not provided.

### 24. Witnessed sites in fuzzing harnesses or test code (found 2026-10-20)
PR-11 stops a mined case when an instance's witnessed site is in a harness or test file (the I6
path rule, after resolving build-tree hops). Applied read-only to the existing release, the same
rule flags execution-witnessed sites on about 41 GOLD records. Most are MSan-arm CWE-456 origins
in harness allocators (`tests/fuzz/custom_memory_manager.c`, `pdf_fuzzer.cc`) and a few sinks
inside harness or libFuzzer code (`FuzzerTracePC.cpp`, `fuzz/Fuzz.h`). The rule also flags
library sources vendored under `oss-fuzz/projects/...`, which are not harness code, so the count
is an upper bound. The GOLD contract does not check site paths today.
**Cured 2026-10-21** by the I2-site amendment (PREREGISTRATION, disclosed as written after the
count): a witnessed root or sink site in harness or test code fails I2, except library sources
vendored under a harness directory. 31 GOLD records became SILVER with `I2-site` named; 54
records carry the gap across tiers.

### 23. Evidence prose claimed 139 withdrawn proofs — **cured 2026-10-08**
`dataflow_evidence` kept "the source link is demonstrated" on 139 records (108 GOLD) after their
proofs were withdrawn, repeated up to 6x. `apply_pr4.py` now writes it from the proof itself.
One GOLD (`CHAINFORGE-0040096184`, skia) held an unlogged proof outside every re-verification
batch; withdrawn (its tier stands on other evidence), then re-ablated on the GitHub runner with logs
kept (2026-10-09): the same `SkSwizzler.cpp` hunk proves it, and the proof is restored.

---

## Previously listed as "no cure" — all three were wrong

Each was asserted rather than investigated. Recorded here in full, because the same mistake
(declaring a route closed after one look) has now happened three times in this project.

### 14. Difficulty is unmeasured — **partial cure, shipped**
**What I claimed.** It cannot be answered from the data; it needs G rollouts against the base
policy.
**What is true.** The *strong* measure does need a policy, and difficulty is genuinely
model- and time-dependent. But rollout-free difficulty estimation is an active area
(*Predicting Task Difficulty Without Rollouts*, arXiv:2608.05797), and the **structural**
component is computable from what we already hold — the corpus has patch content for 1,878
records, sanitizer logs for 1,847, and two localized links for 814.
**Cure.** `chainforge.difficulty` scores locality, cross-file separation of the links, guard
subtlety (a one-line omission is easier to overlook than a nine-line one) and chain length.
Shipped as `difficulty_proxy` / `difficulty_band` — named `_proxy` so it can never be read as a
pass rate. Bands: 1,501 easy / 737 medium / 59 hard, computable for 100% of records.
**Remaining honesty.** It is coarse, driven mostly by locality and chain length, and
uncalibrated — there are no observed pass rates to fit to. It supports stratified sampling so
GRPO groups are not all-solved or all-failed; it does not replace a probe.

### 15. The race arm cannot be witnessed — **cure identified**
**What I claimed.** No reproducers exist anywhere: `nvd-race` ships none, ARVO excludes races,
and no syzbot record is in the arm.
**What is true.** All three facts hold, and the conclusion still does not follow. syzbot cannot
reproduce a bare **KCSAN data-race** — confirmed upstream: *"reproduction of data-races is
currently unsupported"* — but a race that manifests as a **use-after-free is a KASAN bug**, and
those do ship C reproducers (we measured 65% availability).
**Evidence.** 49 of our own syzbot records have fixes that add ≥2 lines of synchronisation
(`spin_lock`, `mutex_lock`, `rcu_read_lock`, `WRITE_ONCE`, …). They are execution-witnessed
KASAN bugs whose root cause is a race, sitting in the corpus labelled `CWE-416→CWE-787`.
**Cure.** Attest a `CWE-362` source from the synchronisation added by the fix — exactly the
standard already used for CWE-190 (fix adds an overflow guard) and CWE-456 (fix adds an
initialisation), and `362→416` is `mitre-direct` in the catalogue. That would give the arm its
first execution-witnessed records against a present 243 with none.
**Caveat.** Relabelling existing records changes their chain and must not be done silently;
this needs the same attest-or-mark discipline as R4, not a bulk rewrite.

### 16. 545 records have an evidence-free link — **partly wrong**
**What I claimed.** `nvd-race` and `osv-git` publish no reproducers, so the `none` floor is
irreducible.
**What is true.** **383 of the 545 `floor=none` records carry a CVE id**, and a CVE id means an
NVD reference list — which is precisely where the osv-git PoCs came from. We measured that
route at **84% usable-reproducer availability** and then applied it to the CWE-190 arm only.
**Cure.** Run the same PoC recovery over the remaining CVE-bearing records. Yield will be lower
than 84% (that sample was one arm), and the `nvd-race` half is weaker still — only 74 of 243
have a fix commit at all — but "no cure" was wrong.

### 33. A guard-rule relabel can drop the CWE-416 link on kernel use-after-free reports — **open, cure known** (found 2026-11-06)

In release 1.0.4, 8 kernel GOLD records left GOLD after their first successful hunk test, and in
1.0.5 a ninth (syzbot 8743fca924afed42f93e). Each has
a KASAN use-after-free report and records no origin site, so PR-4 treated the CWE-416 root as
statically assigned and the guard rule replaced it with CWE-20. The chain became CWE-20 then
CWE-125 or CWE-787, and PR-8 requires a CWE-416 link before such a sink on a use-after-free
report, so I2 failed. ARVO records avoid this because ASan's free site is a recorded origin, which
keeps its CWE. Two cures would keep them, and either needs a dated amendment before it is applied.
One is to record KASAN's "Freed by task" stack as a witnessed origin, as for ASan. The other is to
keep the CWE-416 link when the guard rule relabels a root on a use-after-free report, giving
CWE-20 then CWE-416 then the sink, where that pair is admissible.

### 34. The kernel hunk test did not use the differential's build environment — **cured in 1.0.5, with a caveat** (found 2026-11-07)

In release 1.0.4, 68 of 185 kernel hunk tests on GitHub-hosted runners gave no verdict. All 41
control build failures were kernels older than 5.6 (and one 5.12), which `kdiff_kvm.sh` on the
runner builds inside syzbot's era gcc image; `kablate_kvm.sh` lacked that step. 12 of the 27
controls that did not fire belong to records whose differential matched under PR-6, while the hunk
test matched only a report's first line. `kablate_kvm.sh` now shares the runner differential's era
image, compatibility retry, config lines and classifier (PREREGISTRATION, release 1.0.5 supply).
Caveat: most of these records' differentials were built on our KVM host with kernel.org's gcc
10.5 and the host's gcc 8.5, which a hosted runner cannot reproduce, so on the runner they build
with the era image's compiler instead. Some controls that fire on our host do not fire there,
which is why the paper states hosted reproduction for ready kernel records separately. In 1.0.5 all 41 former build failures built and 37 of the 68 cases gave proofs;
on hosted machines the unmodified kernel ran the reproducer for 157 of 163 ready kernel records
tried and fired syzbot's bug for 147 (PREREGISTRATION, release 1.0.5 outcome).

### 35. The kernel classifier reads a user-space segfault as a kernel crash — **open, cure known** (found 2026-11-07)

`kdiff_kvm.sh` and `kablate_kvm.sh` classify a boot as `crashed_other` when the console matches
`general protection fault`. The kernel also prints that phrase for a user-space trap
(`traps: repro[pid] general protection fault ... in repro[...]`), which is the reproducer itself
crashing. In one 1.0.5 hunk run (6c8215822f35fdb35667, boot 3) the reproducer segfaulted and ended
early, and the case was counted as "no hunk sufficed" instead of no verdict; the outcome entry
reports it as no verdict. The error can only withhold a proof or a GOLD tier, never grant one,
since a `crashed_other` boot is never clean. No archived differential or 1.0.4 hunk log contains
the trap. Cure: ignore `traps:` lines in the pattern, and treat a run whose reproducer ended early
as `not_run`; it needs a dated entry before any rerun uses it.

### 36. Twelve Partial ARVO records name a patched log that was never archived — **open, minor** (found 2026-11-07)

Twelve Partial ARVO records list a patched-side report whose `log_ref` is the bare
name `fix.sanitizer.txt`, with no file behind it, and two Upstream nvd-race records point at
`race_gold_witness/*.log`, which the release does not ship. No tier credits a missing log, since
the contract reads the file itself, so no tier is affected, and every GOLD record's logs exist. The
paper therefore says the release ships "the logs of our runs", not every log a record names. Cure:
drop the dangling references with a changelog entry, or ship the two witness logs.

---

## Genuinely without a cure

Nothing currently qualifies.

Every issue above has at least a partial route. Three were listed as having no cure and all
three were wrong — each had been asserted after a single look rather than investigated. That
pattern (declaring a route closed too early) has now cost real time three times in this project:
the CWE-457 arm, the "Docker-only" UBSan rebuild, and this section. Where a route is genuinely
bounded, the bound is stated with the measurement that establishes it.
