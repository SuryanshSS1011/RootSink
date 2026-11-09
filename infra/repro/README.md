# ChainForge Reproduction Bundles (CRB)

A CRB is a self-contained, executable recipe for reproducing one chain record end-to-end:
pinned environment → replay the PoV → observe the witness → compare against what the record
claims. If a record ships a CRB, a third party can confirm the chain rather than trust it.

```bash
python3 infra/repro/facts_from_logs.py --out infra/repro/facts_by_id.json  # expected witnesses
python3 infra/repro/bundle.py data/release/dataset.jsonl --out infra/repro/bundles \
        --facts infra/repro/facts_by_id.json  # generate
infra/repro/verify.sh infra/repro/bundles/<record-id>.json          # verify sink
infra/repro/verify.sh infra/repro/bundles/<record-id>.json --links  # + intermediate link
```

## Why not just use ARVO

ARVO solved the hard part, and CRB inherits it: freeze the **whole build environment**, not a
binary — source at the vulnerable commit, the project's own `build.sh`, the era-correct toolchain
(e.g. clang 10 for a 2019 bug), and the crashing input, all in one image. Modern toolchains cannot
build historical revisions, so nothing less actually reproduces.

CRB adds three things ARVO leaves open, each of which we hit in practice:

**1. Digests, not tags.** ARVO references `n132/arvo:<id>-vul`. Tags are mutable — they can be
retagged, deleted, or rebuilt, and a dataset that pins tags rots silently. A CRB records the
registry **content digest**, so a bundle either resolves to bit-identical content or fails loudly.
Digests are resolved over the registry API, so generating and auditing bundles needs **no Docker
daemon**.

**2. A declared witness, not "it crashed".** ARVO records reproduction as a boolean. A chain
dataset needs more: *which* weakness fired, and in which direction. A CRB declares the expected
`bug_class`, `direction` (READ/WRITE) and crash site, and the verifier **compares** — so a case
whose crash silently changed fails instead of passing as "still crashes". This matters: an
out-of-bounds READ is CWE-125 and a WRITE is CWE-787, and conflating them was a real labeling bug
in this dataset.

**3. Per-link witnesses, including alternate sanitizers.** ARVO is single-weakness. A chain needs
evidence for *each* link, and the intermediate link is usually invisible in the shipped image: an
ARVO case built `SANITIZER=address` carries no UBSan instrumentation, so a CWE-190 integer overflow
can never be observed by replaying it. A CRB therefore records a **rebuild recipe** for such links
(`SANITIZER=undefined compile && <target> /tmp/poc`), which re-instruments the same pinned source.
Validated on ARVO 42477544, where it recovers the middle link:
`ihevcd_nal.c:304 unsigned integer overflow in ihevcd_nal_unit_header`.

One trap worth stating: the in-image `arvo` helper exports
`UBSAN_OPTIONS=...silence_unsigned_overflow=1`, which suppresses exactly that finding. The link
check invokes the target binary directly.

## Bundle shape

```jsonc
{
  "crb_version": "1.0",
  "record_id": "CHAINFORGE-...", "chain": "CWE-20->CWE-190->CWE-125",
  "repro_kind": "oss-fuzz-container",
  "source":  { "local_id": "42477544", "commit_range": {...}, "patch": "https://..." },
  "images":  { "vulnerable": {"ref": "n132/arvo:42477544-vul", "digest": "sha256:8f4925..."},
               "patched":    {"ref": "n132/arvo:42477544-fix", "digest": "sha256:bbe5e7..."} },
  "entrypoint": { "command": ["arvo"], "pov_path": "/tmp/poc" },
  "expected": { "vulnerable": {"crashes": true,
                               "witness": {"bug_class": "heap-buffer-overflow",
                                           "direction": "READ",
                                           "crash_site": "...ihevcd_parse_slice.c:3151",
                                           "implies_sink_cwe": 125}},
                "patched":    {"crashes": false} },
  "links": [ {"cwe_id": 20,  "role": "source",       "witnessed": false},
             {"cwe_id": 190, "role": "intermediate", "witness": {"method": "ubsan-rebuild", ...}},
             {"cwe_id": 125, "role": "sink",         "witness": {"method": "asan-replay", ...},
              "witnessed": true} ]
}
```

`verify.sh` pulls **by digest** when one is pinned, runs both revisions, and `check.py` asserts:
vulnerable crashes, patched is clean, and the observed witness matches the declared `bug_class`,
`direction` and sink CWE. Any mismatch is a `FAIL` with the specific check named. An
alternate-sanitizer rebuild that fails to build is reported **INCONCLUSIVE**, never as "link
absent" — an OOM-killed build must not read as evidence of absence.

## Coverage — what is reproducible, honestly

| provenance | records | repro_kind | status |
|---|---:|---|---|
| `arvo`, `arvo-len3`, `arvo-newarm` | **824** | `oss-fuzz-container` | **bundles generated** |
| `syzbot` | 672 | `kernel-vm` (planned) | syzbot publishes a C reproducer, kernel commit and config; needs a kernel build + VM boot under KASan. Feasible, not yet wired. |
| `nvd-race` | 234 | — | NVD co-occurrence only. No PoC, no harness. Not reproducible without authoring one. |
| `osv-git`, `osv-git-len3` | 159 | — | Bare CVEs: no fuzz harness and no crashing input. Requires hand-authored harnesses. |

So **824 / 1889 (44%)** are reproducible end-to-end today, and the ceiling with a kernel-VM
pipeline is **1496 / 1889 (79%)**. The remaining 393 are honestly *not* reproducible from public
artifacts, and the release should say so rather than imply uniform rigor. Note the 824 includes 93
`arvo-len3`/`arvo-newarm` records whose `docker_image_ref` was empty but which are ARVO-backed via
their `OSS-Fuzz-<id>` alias — the generator recovers those.

## Roadmap

1. **Backfill `docker_image_ref`** on the 93 alias-only ARVO records so the dataset itself states
   what the bundles already prove.
2. **`kernel-vm` bundles for syzbot** — the single largest coverage win (672 records, 39% → 79%).
3. **Carry the witness into the record.** Bundles hold `crash_site` and per-link `file:line`; the
   records still do not. Promoting that into `ChainLink.location` is what makes the labels
   code-grounded instead of metadata-predictable.
4. **CI audit.** Re-resolve every pinned digest on a schedule; a moved or deleted tag is a
   detectable regression rather than a silent one.
