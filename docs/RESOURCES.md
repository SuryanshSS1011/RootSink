# Resources per episode

Measured by `infra/repro/score_patch.sh` on GitHub-hosted runners (4 vCPU, 16 GB), from its smoke test
(`data/validation/score_smoke.json`, runner run 39388993898). One episode = pull the record's vulnerable
image, apply a patch, rebuild once, replay the input twice. Five ARVO cases ran, each scored twice
(unmodified and with the developer's fix); a sixth case's image could not be pulled. Five cases give
ranges, not a distribution: treat them as orders of magnitude.

| quantity | value |
|---|---|
| image size (uncompressed, on disk) | median 2.7 GB, range 2.4 to 3.4 GB |
| rebuild time | median 190 s, range 23 to 333 s |
| replay time per run | at most 1 s |
| peak container memory | median 1.6 GB, range 0.5 to 7.5 GB |

Per case:

| ARVO id | scored | image GB | rebuild s | peak memory GB |
|---|---|---:|---:|---:|
| 373610438 | nopatch | 2.6 | 191 | 0.5 |
| 373610438 | devfix | 2.6 | 190 | 0.5 |
| 418349489 | nopatch | 2.7 | 198 | 0.5 |
| 418349489 | devfix | 2.7 | 194 | 0.5 |
| 42474837 | nopatch | 2.4 | 23 | 1.6 |
| 42474837 | devfix | 2.4 | 23 | 1.6 |
| 42475782 | nopatch | 3.4 | 154 | 3.7 |
| 42475782 | devfix | 3.4 | 153 | 3.7 |
| 42484909 | nopatch | 3.0 | 333 | 7.5 |
| 42484909 | devfix | 3.0 | 331 | 7.5 |

Disk: one image plus a build tree; plan for about twice the image size per concurrent episode.
Kernel episodes are not covered here; each needs a full kernel build (tens of minutes on 4 cores) and
KVM boots of up to 10 minutes (`infra/cse-kvm/kdiff_kvm.sh`).
