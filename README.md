# RootSink

Reproducible C/C++ crashes, most with a sanitizer-witnessed sink, and a candidate root cause for each whose evidence is stated per record. The Reproduced tier certifies the sink and its two-sided reproduction; the root is a candidate, tested by a single-hunk intervention where the record says so.

RootSink was developed under the working name CHAINFORGE; the Python package (`chainforge`) and
record ids (`CHAINFORGE-...`) keep that name so existing ids stay stable.

Each record is an ordered list of CWE instances observed in one execution on one input
(for example `CWE-20 -> CWE-787`). Every instance carries a role (source, intermediate, sink), a
site (file, line, function) and its own evidence category. A record's tier says how its
**reproduction** was checked, and it is kept separate from how well its **root cause** is
supported:

- **Reproduced** (stored as `label_confidence_tier: "gold"`) means we replayed both revisions. The
  vulnerable build crashes at a sink a sanitizer report attributes to a site, and the fixed build
  runs the same input to completion, with no report, twice. It makes no demand on the root cause's
  evidence. The full rule set is PR-3 in [`PREREGISTRATION.md`](PREREGISTRATION.md);
  `src/chainforge/integrity.py` enforces it.
- **Upstream** (`"gold-upstream"`) means the bug reproduced only in the original reporter's run.
- **Partial** (`"silver"`) means a Reproduced-tier criterion is missed; `gold_contract_gaps` names it.
- **Candidate** (`"bronze"`) means nothing was executed (candidates from advisory co-occurrence or
  heuristics).

The paper uses these names; the stored values keep their earlier names in 1.0.x.

Root-cause evidence, strongest first (`chain[i].evidence_kind`):

| value | meaning |
|---|---|
| `causally-proven` (legacy name; the paper's "hunk-named") | one hunk of the developer's fix, applied alone to the vulnerable revision and rebuilt, stopped the crash on this input. It is a *sufficient tested hunk*: not minimized, not shown to be the only repair, and not a test of intended behaviour. |
| `execution` | a sanitizer report attributes the instance to a site (for `CWE-456`, MSan's origin: the allocation or declaration that created the uninitialised value) |
| `attested` | the fix adds the check the instance lacks; no run shows the check matters |
| `dataflow` | only a static (Joern) path supports it |
| `inferred` | only a labeling rule supports it |

Every CWE is assigned by a rule. `chain[i].cwe_basis` names the strongest input that rule had
(`guard-class` for a tested hunk, `msan-origin`, `sanitizer-class`, `fix-pattern`,
`crash-class-implied`, `dataflow-rank`, `advisory`, `catalogue-default`). An intervention tests the
site; its CWE comes from the guard classifier (PR-4) and is not itself tested.

`chain[i].site_kind` says what the recorded site is, separately from how its CWE was named:
`tested-repair-site` (a hunk of the fix, applied alone, stopped the crash there),
`origin-site` (MSan's creation site for CWE-456, or the free site of a CWE-416),
`crash-site`, `witnessed-site` (an intermediate a sanitizer placed), or `annotated-site` (a static
path, fix pattern or labeling rule put it there). A tested repair site is a sufficient repair
location and an origin site is where the bad state began; neither is a validated defect location
until the PR-9 audit checks it. An instance is `causally-proven` only when the hunk test succeeded
**and** the guard rule (PR-4) named its CWE from that hunk; a successful test whose hunk matches
no guard class is kept as `guard_site_proof` and the instance keeps its other category.

`chain_kind` is `stage-decomposition` when the chain's CWEs describe one defect: two consecutive
CWEs that classify the same faulting operation (`416 -> 125|787`, `843 -> 119`) count once. A first
CWE defined by an earlier, different operation (a missing check, a computation, a missing
initialisation, a race) is a separate weakness (PR-5).

`evidence_floor` is the weakest category over all instances. Edges between instances carry only
their MITRE CWE 4.20 catalogue status (`mitre_chain.edges[].kind`: direct, transitive, inherited,
hierarchy, or a declared modeling edge), never observed evidence. `inherited` means an ancestor of
the source CanPrecede an ancestor of the target (CWE-825, the parent of use-after-free, CanPrecede
CWE-125 and CWE-787).

Root CWEs follow MITRE's mapping guidance (PR-17). CWE 4.20 marks CWE-20 DISCOURAGED, so a CWE-20
root names the allowed child its check bounds, CWE-1285 for an index, offset or position and
CWE-1284 for a quantity; a root whose check bounds neither keeps CWE-20 with
`cwe_mapping: "class-level"`. The original label stays in `cwe_class`.

Two derived fields place each record. `fix_attribution.status` is true when the recorded fix
**alone** removes the crash: for ARVO, the vulnerable image plus that fix, applied with exact
context, replays clean (the Reproduced tier's own patched runs use ARVO's fixed image, which can contain other
commits); for the kernel, the fix's parent and the fix were built in one tree. `root_site_relation`
places the root site against the crash (`crash-line`, `crash-function`, `on-stack`, `off-stack`,
`file-only`); a root at the crash line may guard the symptom rather than repair the defect.

Each record's fix is `commit_range.fix_commits` (every fix sha, canonical) in `commit_range.repo`; `commit_range.fixed` keeps the source's own form.

The recommended core is the Reproduced tier with `evidence_floor == "execution"` and
`fix_attribution.status == true`.

## What is in the repository

```
data/release/dataset.jsonl            the records (one JSON object per line)
data/release/corrections_changelog.jsonl   every change to a record, with the rule that made it
data/release/dropped.jsonl            records removed, and why
data/release/croissant.json           Croissant metadata (sha256 of the dataset)
data/release/dataset.manifest.json    counts and digests of this release
data/release/dataset_full_consolidated.jsonl   historical input the corrections started from (superseded; use dataset.jsonl)
data/release/single_weakness.jsonl    records set aside because they hold one weakness, not a chain
data/evidence/                        sanitizer, intervention and kernel logs referenced by path
data/validation/                      selections, funnels and validation results
docs/SPECIFICATION.md                 what a chain is (R1-R10)
docs/DATASHEET.md                     datasheet
PREREGISTRATION.md                    labeling rules PR-1..PR-10 with dated amendments
src/chainforge/                       schema, evidence categories, integrity (Reproduced-tier) contract, views
infra/repro/score_patch.sh            score a candidate patch by replay (ARVO-backed records)
infra/cse-kvm/github/kablate_kvm.sh   the same for kernel records, in a KVM virtual machine
infra/cse-kvm/kdiff_kvm.sh            two-sided kernel replay (syzbot records)
infra/paper/reconcile_counts.py       every population and unit the paper reports
```

The PR-9 audit is in `data/irr/`: the sampled items (`sample.json`), the packet and codebook the
raters saw (`packet.md`), both scored sheets with the raters' stated backgrounds (`returned/`) and
the exploratory AI raters' sheets (`ai/`). `infra/verify/score_audit.py` and `score_ai_raters.py`
recompute every audit figure in the paper.

## Install

Python 3.11 or later and [uv](https://docs.astral.sh/uv/).

```bash
git clone https://github.com/SuryanshSS1011/RootSink && cd RootSink
uv sync --extra dev                              # --extra dev installs pytest
uv run pytest                                    # offline unit tests
uv run python infra/verify/conformance.py        # re-check every record against the contract
uv run python infra/paper/reconcile_counts.py    # populations, units and their relations
```

Scoring patches needs Docker. Kernel episodes need Linux with KVM (`/dev/kvm`), QEMU and a
kernel build toolchain.

### Docker images

ARVO's images (`n132/arvo:<id>-vul` and `-fix`) are referenced by digest in each record's
`docker_image_ref` and are not part of the archive (they total several terabytes). Pull by digest so
a retagged image cannot change a result. Docker Hub rate-limits anonymous pulls; log in, or pull
through a registry mirror such as `mirror.gcr.io/n132/arvo@sha256:...`, which `score_patch.sh`
falls back to. In October 2026 every image the scorer needed was pulled, and on 7 November 2026 every
pinned digest still resolved on Docker Hub with its tag unmoved (`infra/verify/check_image_digests.py`,
which sends registry HEAD requests and pulls nothing; counts in `infra/repro/image_availability.json`). The images
were produced by ARVO's open-source pipeline (github.com/n132/arvo, BSD-2-Clause), which is the
route to regenerate one. Our own rebuild from the projects' source, without ARVO's images,
succeeded at both revisions for 13 of 60 sampled records (PR-15), so the images are a real
dependency.

## Worked example

```python
import json
from chainforge.field_policy import (
    labeling_view, localization_eligible, localization_view, policy_view, task_target,
)

rows = [json.loads(line) for line in open("data/release/dataset.jsonl")]
reproduced = [r for r in rows if r["label_confidence_tier"] == "gold"]  # the Reproduced tier

# The recommended core: every instance hunk-named or sanitizer-reported, and the fix alone removes
# the crash (fix-attributed).
core = [
    r for r in reproduced
    if r["evidence_floor"] in ("causally-proven", "execution")
    and (r.get("fix_attribution") or {}).get("status") is True
]

r = core[0]
x = localization_view(r)          # input: vulnerable image, input, sink report, sink CWE and site
y = task_target(r, "localize")    # target: the root site (file, line, function) and its site_kind
# Score localization on tested repair sites by default (localization_eligible); origin sites are
# printed in the input's own sanitizer report, and suggested (annotated) sites are a rule's answer.
x_label = labeling_view(r)        # input: every instance's site, no CWE ids
y_label = task_target(r, "label") # target: the ordered CWE ids
x_repair = policy_view(r)         # input for repair; the fix, chain and fixed image are withheld
```

Each task's input withholds its target (`tests/test_field_policy.py` checks this).
`annotation_view` returns everything, labels included, and is for reading or auditing only.
Use the `split` field for training, validation and test, `duplicate_group` to count bugs rather
than inputs, and `sampling_weight` to even out projects when sampling.

### Scoring a candidate patch

```bash
# the record's OSS-Fuzz id is in its aliases ("OSS-Fuzz-<id>"); project is the record's project
bash infra/repro/score_patch.sh <arvo_id> <project> my.patch out/   # pass | crash | build_fail | patch_fail | not_run
bash infra/repro/score_patch.sh <arvo_id> <project> - out/nopatch   # the unmodified build: crash
```

It applies the patch to the record's vulnerable image, rebuilds once, and replays the input twice.
`pass` means every replay read the input to completion with no sanitizer report. It does not mean
the root cause was fixed or behaviour kept: a patch that rejects the input early also passes.
`not_run` is an environment failure, never a negative score. Pin images by the digest in
`docker_image_ref` for training.

Kernel records are scored the same way in a KVM virtual machine:
`infra/cse-kvm/github/kablate_kvm.sh <syzbot extid> <fix sha> my.patch` builds `fix^` with
syzbot's configuration, confirms that the reproducer fires syzbot's bug, applies the patch whole,
rebuilds and boots twice. It needs `/dev/kvm` and Docker; `infra/cse-kvm/github/kablate.yml` is a
GitHub Actions setup that runs it on hosted runners. `inconclusive` is no verdict, never a
negative score.

**Agent environments.** ARVO's vulnerable images keep the project's git history, and the fix
commit is reachable in every image we probed. Start agents with `infra/repro/agent_env.sh <arvo_id>`,
which disables networking and rewrites each repository under `/src` to a single vulnerable
commit. Do not hand an agent the raw image.

Resources per episode (measured by the scorer on GitHub-hosted runners, 4 vCPU, 16 GB):
see [`docs/RESOURCES.md`](docs/RESOURCES.md).

### Kernel records

For each kernel record in the Reproduced tier, `data/evidence/kernel/<syzbot extid>/` holds syzbot's
`kernel.config`, the C reproducer `repro.c`, the vulnerable-side KASAN report and excerpts of the
fixed-side consoles. Full consoles are too large for git and are archived with the frozen release. No kernel image or root file
system is shipped. `infra/cse-kvm/kdiff_kvm.sh <extid> <fix sha>` fetches the fix commit, builds
its parent `fix^` with syzbot's configuration, rebuilds the same tree at the fix, builds a
minimal root file system around the reproducer (`build_rootfs.sh`) and boots both under KASAN on
KVM. Expect a full kernel build (tens of minutes on 4 cores), an incremental rebuild, and up to
10 minutes per boot. Set `CF_BASE` to a scratch directory first, because the scripts otherwise
default to the authors' cluster path.

## Splits, duplicates and weights

Splits keep each project in one fold, except that kernel records are split by subsystem
(`linux-kernel/<subsystem>`) and the advisory-race catch-all project `linux` is not
consolidated. Units are assigned whole, largest first, to the fold furthest below its quota
(`infra/verify/fix_p0_metadata.py`, targets 70/15/15 over all records). Later mined records join
their project's fold; a new project goes to the fold furthest below the same targets (mined
records admitted before 2026-10-20 used 70/10/20 for new projects and keep their folds). `infra/verify/dedup_groups.py` keeps every record sharing a fix
commit in one fold. `sampling_weight` is `1 / (inputs in the duplicate group x sqrt(bugs in the
project))`, within tier, rescaled to mean 1 per tier and split.

## Rules and history

Labeling rules were developed while the corpus was built and then written down as PR-1..PR-9.
Their dates are self-reported, because the repository history before 2026-10-19 was squashed.
Selections and amendments committed since then precede their outcomes in the git history.
Every change to a record is in `corrections_changelog.jsonl` with its rule id.

## Regenerating derived files

```bash
bash infra/verify/rebuild_derived.sh   # evidence kinds, difficulty, duplicate groups, weights,
                                       # manifest, paper numbers, Croissant, then the release gate
```

## Licenses

Code: MIT ([`LICENSE`](LICENSE)). Labels and annotations: CC-BY-4.0. Each record's `license`
field gives the upstream project's SPDX license where known; logs and diffs remain under their
projects' licenses.

## Citation

See [`CITATION.cff`](CITATION.cff).
