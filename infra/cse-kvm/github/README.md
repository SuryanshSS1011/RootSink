# Kernel runs on GitHub-hosted runners

Copies of the scripts the public runner (github.com/SuryanshSS1011/chainforge-runner) uses for
kernel records, kept here so the release holds them. `kablate.yml` is that repository's workflow.

- `kablate_kvm.sh <extid> <fix_sha>` runs the single-hunk test of a kernel record on KVM.
- `kablate_kvm.sh <extid> <fix_sha> <candidate>` is the kernel patch scorer: `devfix` (the
  developer's fix) or a patch file is applied whole to `fix^`, and the result is pass, crash,
  apply_failed, buildfail or inconclusive (no verdict).
- `kdiff_kvm.sh` is the two-sided `fix^`/`fix` run. Kernels before 5.16 build inside syzbot's
  era gcc image (`kimg_apt.sh`), so these scripts need Docker; the copies one directory up are the
  KVM-host versions, which build with kernel.org's crosstool compilers and no Docker.
