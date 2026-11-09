#!/usr/bin/env bash
# race_replay_kvm.sh — EARN GOLD for a CWE-362 race chain by replaying OUR OWN KASAN
# crash-trigger (derived from a public PoC, privesc stripped) under real SMP on a KVM host.
#
# Unlike kernel_replay_kvm.sh (keyed on a syzbot extid + its C reproducer), this takes a
# CHAINFORGE-authored repro.c and a cause commit, because these CVE races are human-found and
# have NO syzbot reproducer (0/24 mapped). The GOLD witness is a KASAN use-after-free splat we
# observe ourselves. Races need REAL parallelism, so -enable-kvm -smp (not TCG) is essential.
#
# Usage: race_replay_kvm.sh <cve> <cause_commit> <repro.c> [outdir]
set -u
CVE="${1:?usage: race_replay_kvm.sh <cve> <cause_commit> <repro.c> [outdir]}"
CAUSE="${2:?need cause commit}"
REPRO_SRC="${3:?need repro.c path}"
CF="${CF_HOME:?set CF_HOME to the chainforge working directory}"
OUTDIR="${4:-$CF/race_gold/$CVE}"
KSRC="${KSRC:-$CF/linux}"          # a linux git worktree/clone (reused across cases)
JOBS="${JOBS:-$(nproc)}"
mkdir -p "$OUTDIR"
# make paths ABSOLUTE: `make -C $KSRC O=<rel>` resolves O= relative to $KSRC, so a relative
# OUTDIR would put the build tree under $KSRC and qemu (run from cwd) wouldn't find bzImage.
OUTDIR="$(cd "$OUTDIR" && pwd)"
REPRO_SRC="$(cd "$(dirname "$REPRO_SRC")" && pwd)/$(basename "$REPRO_SRC")"
WORK="$OUTDIR/work"; mkdir -p "$WORK"
log() { echo "[race $CVE] $*"; }

witness() {  # status detail
  cat > "$OUTDIR/witness.json" <<JSON
{"cve": "$CVE", "status": "$1", "detail": "$2", "cause_commit": "$CAUSE",
 "kasan_type": "${KTYPE:-}", "gold_eligible": $([ "$1" = kasan_fired ] && echo true || echo false)}
JSON
  log "WITNESS: $1 ($2)"
  [ "$1" = kasan_fired ] && exit 0 || exit 1
}

# never clobber an earned GOLD
if grep -q '"status": "kasan_fired"' "$OUTDIR/witness.json" 2>/dev/null; then
  log "already kasan_fired (GOLD) — skipping"; exit 0
fi

# 1. Checkout kernel @ cause (a tag like v4.8 or a commit). Full clone has all tags already;
#    only fetch if the ref is unknown locally.
log "checkout $KSRC @ $CAUSE"
[ -d "$KSRC/.git" ] || witness no_ksrc "no linux clone at $KSRC (clone torvalds/linux first)"
git -C "$KSRC" rev-parse -q --verify "${CAUSE}^{commit}" >/dev/null 2>&1 \
  || git -C "$KSRC" fetch --tags --depth 1 origin "$CAUSE" 2>/dev/null || true
git -C "$KSRC" checkout -q -f "$CAUSE" 2>"$WORK/checkout.log" \
  || witness checkout_failed "cannot checkout $CAUSE"

# 1b. gcc-new vs kernel-old compat: on pre-~4.9 trees, gcc's changed const/noreturn handling
# breaks the compile-time ilog2 trap, leaving an undefined reference to the never-called
# ____ilog2_NaN / ____roundup_pow_of_two link-traps. These are ONLY meant to fail compilation
# on non-constant misuse; a stub definition is a safe, documented workaround (they are never
# invoked at runtime). Inject stubs into an always-built object so LINK vmlinux succeeds.
if ! grep -q "cf_ilog2_stub" "$KSRC/init/version.c" 2>/dev/null; then
  cat >> "$KSRC/init/version.c" <<'STUB'

/* cf_ilog2_stub: satisfy the log2.h link-trap when building an old kernel with a newer gcc.
 * ____ilog2_NaN is only meant to fail compilation on non-constant ilog2(); never called. */
int ____ilog2_NaN(void);
int ____ilog2_NaN(void) { return 0; }
STUB
  log "injected ilog2 link-trap stubs (gcc-$(gcc -dumpversion) vs old kernel)"
fi

# Optional older-gcc for building an old kernel (v4.8-era predates gcc-8's ASAN ABI). Set KCC to
# a gcc path (e.g. the conda gcc-7). MAKE_CC is spliced into every kernel `make` so config, build,
# and the compile-time ilog2 folding all use the SAME compiler (mismatch reintroduces the trap).
MAKE_CC=""
if [ -n "${KCC:-}" ] && [ -x "${KCC:-/nonexistent}" ]; then
  # conda gccs default to PIE/PIC; the kernel's 'code model kernel' needs -fno-pic -no-pie.
  # Wrap KCC so every kernel compile gets these (a plain CC=path fails: "code model kernel
  # does not support PIC mode", which also makes the -fsanitize=kernel-address probe fail).
  KCC_WRAP="$WORK/kcc-wrap"
  printf '#!/bin/sh\nexec %s -fno-pie -no-pie -fno-PIC "$@"\n' "$KCC" > "$KCC_WRAP"
  chmod +x "$KCC_WRAP"
  MAKE_CC="CC=$KCC_WRAP HOSTCC=$KCC"
  # Use the MATCHING conda binutils: the host ld (2.30) cannot decompress conda-gcc's
  # compressed .debug sections ("unable to initialize decompress status"). conda ships
  # binutils 2.36 alongside the gcc. Splice in ld/ar/nm/objcopy/objdump when present.
  KBIN="$(dirname "$KCC")"; PFX="$KBIN/x86_64-conda-linux-gnu-"
  for tool in ld ar nm objcopy objdump strip; do
    [ -x "${PFX}${tool}" ] && MAKE_CC="$MAKE_CC $(echo "$tool" | tr a-z A-Z)=${PFX}${tool}"
  done
  log "kernel build compiler override: $KCC ($($KCC -dumpversion)) + conda binutils"
fi

# 2. Config: minimal x86_64 defconfig + KASAN + the drivers to boot virtio + run the repro.
log "configuring (KASAN + SMP + virtio + net + userns)"
make -C "$KSRC" O="$WORK/build" $MAKE_CC x86_64_defconfig >/dev/null 2>&1 || witness config_failed "defconfig"
cat >> "$WORK/build/.config" <<'CFG'
CONFIG_KASAN=y
CONFIG_KASAN_GENERIC=y
# OUTLINE (not INLINE): on old kernels + newer gcc, KASAN_INLINE emits ASAN global-registration
# constructors that run before the shadow is ready -> memset over unmapped shadow -> early panic.
# Outline mode routes checks through __asan_* calls that tolerate early-init ordering.
CONFIG_KASAN_OUTLINE=y
# CONFIG_KASAN_INLINE is not set
CONFIG_DEBUG_INFO_NONE=y
CONFIG_SMP=y
CONFIG_PACKET=y
CONFIG_UNIX=y
CONFIG_USER_NS=y
CONFIG_NET_NS=y
CONFIG_BLK_DEV_INITRD=y
CONFIG_DEVTMPFS=y
CONFIG_DEVTMPFS_MOUNT=y
CONFIG_VIRTIO=y
CONFIG_VIRTIO_PCI=y
CONFIG_VIRTIO_BLK=y
CONFIG_SERIAL_8250=y
CONFIG_SERIAL_8250_CONSOLE=y
CFG
make -C "$KSRC" O="$WORK/build" $MAKE_CC olddefconfig >/dev/null 2>&1

# 3. Build the KASAN kernel.
log "building bzImage (KASAN) -j$JOBS ${KCC:-gcc-$(gcc -dumpversion)}"
make -C "$KSRC" O="$WORK/build" $MAKE_CC -j"$JOBS" bzImage >"$WORK/kbuild.log" 2>&1 \
  || witness build_failed "bzImage build failed (see kbuild.log)"
BZ="$WORK/build/arch/x86/boot/bzImage"

# 4. Compile the repro and build a busybox initramfs that runs it as init.
#    No static glibc on this host -> build DYNAMIC and bundle the shared libs + loader.
log "compiling repro (dynamic) + initramfs"
gcc -O1 -o "$WORK/repro" "$REPRO_SRC" -lpthread 2>"$WORK/cc.log" \
  || gcc -O1 -o "$WORK/repro" "$REPRO_SRC" 2>>"$WORK/cc.log" \
  || witness repro_cc_failed "repro compile failed (see cc.log)"
BB="${CF_BUSYBOX:-$CF/imgbuild/busybox}"
[ -x "$BB" ] || BB="$(command -v busybox)"
[ -x "$BB" ] || witness no_busybox "no busybox (set CF_BUSYBOX)"
ROOT="$WORK/root"; rm -rf "$ROOT"; mkdir -p "$ROOT"/{bin,proc,sys,dev,tmp,lib,lib64}
cp "$BB" "$ROOT/bin/busybox"; ln -sf busybox "$ROOT/bin/sh"
cp "$WORK/repro" "$ROOT/repro"
# bundle the dynamic loader + every shared lib the repro needs
for so in $(ldd "$WORK/repro" 2>/dev/null | grep -oE "/[^ ]+\.so[^ ]*"); do
  d="$ROOT$(dirname "$so")"; mkdir -p "$d"; cp -L "$so" "$d/" 2>/dev/null || true
done
cat > "$ROOT/init" <<'INIT'
#!/bin/sh
/bin/busybox mount -t proc none /proc
/bin/busybox mount -t sysfs none /sys
/bin/busybox mount -t devtmpfs none /dev 2>/dev/null
echo "[cf] guest up, running repro"
/repro
echo "[cf] repro returned; halting"
/bin/busybox poweroff -f
INIT
chmod +x "$ROOT/init"
( cd "$ROOT" && find . | cpio -o -H newc 2>/dev/null | gzip > "$WORK/initramfs.cpio.gz" )

# 5. Boot qemu-kvm with REAL SMP (races need parallelism), capture serial log.
log "booting qemu-kvm -smp $JOBS (real parallelism)"
QEMU="$(command -v qemu-system-x86_64 || echo /usr/libexec/qemu-kvm)"
SMP=4; [ "$JOBS" -lt 4 ] && SMP="$JOBS"
timeout 420 "$QEMU" -enable-kvm -cpu host -smp "$SMP" -m 2G \
  -kernel "$BZ" -initrd "$WORK/initramfs.cpio.gz" \
  -append "console=ttyS0 panic=1 oops=panic kasan_multi_shot" \
  -nographic -no-reboot > "$WORK/serial.log" 2>&1 || true

# 6. Verdict: did KASAN fire on a use-after-free in the packet/net path?
if grep -qE "KASAN: (use-after-free|slab-use-after-free)" "$WORK/serial.log"; then
  KTYPE="$(grep -oE "KASAN: [a-z-]+" "$WORK/serial.log" | head -1)"
  cp "$WORK/serial.log" "$OUTDIR/kasan_report.log"
  witness kasan_fired "observed $KTYPE under SMP=$SMP"
elif grep -q "\[cf\] guest up" "$WORK/serial.log"; then
  witness no_fire "guest booted + repro ran, no KASAN splat (race not won this run)"
else
  witness no_boot "guest did not reach repro (see work/serial.log)"
fi
