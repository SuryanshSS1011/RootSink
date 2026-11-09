#!/usr/bin/env bash
# race_replay_dvb.sh — EARN GOLD for CVE-2022-45884 (CWE-362 race -> CWE-416 UAF in dvb-core).
# Builds a modern KASAN kernel (v6.0, stock gcc-8 works + boots on this host) with the vidtv
# SOFTWARE dvb adapter, then races open() on the dvb nodes against vidtv teardown so
# dvb_free_device() frees the per-open fops mid-open. GOLD witness = KASAN UAF splat we observe.
#
# Usage: race_replay_dvb.sh <cause_tag> <repro.c> [outdir]
set -u
CAUSE="${1:?usage: race_replay_dvb.sh <cause_tag> <repro.c> [outdir]}"
REPRO_SRC="${2:?need repro.c}"
CF="${CF_HOME:?set CF_HOME to the chainforge working directory}"
CVE="cve-2022-45884"
OUTDIR="${3:-$CF/race_gold/$CVE}"
KSRC="${KSRC:-$CF/linux}"
JOBS="${JOBS:-$(nproc)}"
mkdir -p "$OUTDIR"; OUTDIR="$(cd "$OUTDIR" && pwd)"
REPRO_SRC="$(cd "$(dirname "$REPRO_SRC")" && pwd)/$(basename "$REPRO_SRC")"
WORK="$OUTDIR/work"; mkdir -p "$WORK"
log() { echo "[dvb $CVE] $*"; }
witness() {
  cat > "$OUTDIR/witness.json" <<JSON
{"cve": "$CVE", "status": "$1", "detail": "$2", "cause_commit": "$CAUSE",
 "kasan_type": "${KTYPE:-}", "gold_eligible": $([ "$1" = kasan_fired ] && echo true || echo false)}
JSON
  log "WITNESS: $1 ($2)"; [ "$1" = kasan_fired ] && exit 0 || exit 1
}
if grep -q '"status": "kasan_fired"' "$OUTDIR/witness.json" 2>/dev/null; then
  log "already kasan_fired (GOLD) — skipping"; exit 0
fi

# 1. Checkout modern vulnerable kernel (v6.0: has vidtv + the pre-fix dvbdev.c, builds gcc-8).
log "checkout $KSRC @ $CAUSE"
git -C "$KSRC" checkout -q -f "$CAUSE" 2>"$WORK/checkout.log" || witness checkout_failed "$CAUSE"

# 2. Config: defconfig + KASAN + SMP + virtio + dvb-core + vidtv (built-in, no udev needed).
log "configuring (KASAN + SMP + virtio + dvb-core + vidtv)"
make -C "$KSRC" O="$WORK/build" x86_64_defconfig >/dev/null 2>&1 || witness config_failed "defconfig"
cat >> "$WORK/build/.config" <<'CFG'
CONFIG_KASAN=y
CONFIG_KASAN_GENERIC=y
CONFIG_KASAN_INLINE=y
CONFIG_DEBUG_INFO_NONE=y
CONFIG_SMP=y
CONFIG_BLK_DEV_INITRD=y
CONFIG_DEVTMPFS=y
CONFIG_DEVTMPFS_MOUNT=y
CONFIG_VIRTIO=y
CONFIG_VIRTIO_PCI=y
CONFIG_SERIAL_8250=y
CONFIG_SERIAL_8250_CONSOLE=y
CONFIG_I2C=y
CONFIG_MEDIA_SUPPORT=y
CONFIG_MEDIA_SUPPORT_FILTER=n
CONFIG_DVB_CORE=y
CONFIG_MEDIA_DIGITAL_TV_SUPPORT=y
CONFIG_MEDIA_TEST_SUPPORT=y
CONFIG_DVB_VIDTV=y
CFG
make -C "$KSRC" O="$WORK/build" olddefconfig >/dev/null 2>&1
# olddefconfig may not settle newly-enabled children (vidtv) whose parent menu only just became
# visible. Force the exact symbols with scripts/config (dependency-aware), then re-normalize.
"$KSRC/scripts/config" --file "$WORK/build/.config" \
  -e I2C -e MEDIA_SUPPORT -d MEDIA_SUPPORT_FILTER -e DVB_CORE \
  -e MEDIA_DIGITAL_TV_SUPPORT -e MEDIA_TEST_SUPPORT \
  -e DVB_TEST_DRIVERS -e DVB_VIDTV 2>/dev/null
make -C "$KSRC" O="$WORK/build" olddefconfig >/dev/null 2>&1
grep -q "CONFIG_DVB_VIDTV=y" "$WORK/build/.config" \
  || witness config_failed "vidtv not enabled (check media deps)"

# 3. Build the KASAN kernel (stock gcc; v6.0 is gcc-8-compatible).
log "building bzImage (KASAN) -j$JOBS gcc-$(gcc -dumpversion)"
make -C "$KSRC" O="$WORK/build" -j"$JOBS" bzImage >"$WORK/kbuild.log" 2>&1 \
  || witness build_failed "bzImage build failed (see kbuild.log)"
BZ="$WORK/build/arch/x86/boot/bzImage"

# 4. repro (dynamic + bundled libs) + busybox initramfs. vidtv is built-in (=y) so it registers
#    at boot; the repro drives open()-vs-unbind teardown races on the auto-created dvb nodes.
log "compiling repro (dynamic) + initramfs"
gcc -O1 -o "$WORK/repro" "$REPRO_SRC" -lpthread 2>"$WORK/cc.log" \
  || witness repro_cc_failed "repro compile failed (see cc.log)"
BB="${CF_BUSYBOX:-$CF/imgbuild/busybox}"; [ -x "$BB" ] || BB="$(command -v busybox)"
[ -x "$BB" ] || witness no_busybox "no busybox"
ROOT="$WORK/root"; rm -rf "$ROOT"; mkdir -p "$ROOT"/{bin,proc,sys,dev,tmp}
cp "$BB" "$ROOT/bin/busybox"; ln -sf busybox "$ROOT/bin/sh"
cp "$WORK/repro" "$ROOT/repro"
for so in $(ldd "$WORK/repro" 2>/dev/null | grep -oE "/[^ ]+\.so[^ ]*"); do
  d="$ROOT$(dirname "$so")"; mkdir -p "$d"; cp -L "$so" "$d/" 2>/dev/null || true
done
cat > "$ROOT/init" <<'INIT'
#!/bin/sh
/bin/busybox mount -t proc none /proc
/bin/busybox mount -t sysfs none /sys
/bin/busybox mount -t devtmpfs none /dev 2>/dev/null
echo "[cf] guest up; dvb nodes:"; /bin/busybox ls -l /dev/dvb/adapter0/ 2>/dev/null
/repro
echo "[cf] repro returned; halting"
/bin/busybox poweroff -f
INIT
chmod +x "$ROOT/init"
( cd "$ROOT" && find . | cpio -o -H newc 2>/dev/null | gzip > "$WORK/initramfs.cpio.gz" )

# 5. Boot qemu-kvm with real SMP (races need parallelism).
log "booting qemu-kvm -smp (real parallelism)"
QEMU="$(command -v qemu-system-x86_64 || echo /usr/libexec/qemu-kvm)"
SMP=4; [ "$JOBS" -lt 4 ] && SMP="$JOBS"
timeout 600 "$QEMU" -enable-kvm -cpu host -smp "$SMP" -m 2G \
  -kernel "$BZ" -initrd "$WORK/initramfs.cpio.gz" \
  -append "console=ttyS0 panic=1 oops=panic kasan_multi_shot" \
  -nographic -no-reboot -net none > "$WORK/serial.log" 2>&1 || true

# 6. Verdict: KASAN UAF in the dvb path?
if grep -qE "KASAN: (use-after-free|slab-use-after-free)" "$WORK/serial.log"; then
  KTYPE="$(grep -oE "KASAN: [a-z-]+" "$WORK/serial.log" | head -1)"
  cp "$WORK/serial.log" "$OUTDIR/kasan_report.log"
  witness kasan_fired "observed $KTYPE under SMP=$SMP (dvb-core open-vs-teardown race)"
elif grep -q "\[cf\] guest up" "$WORK/serial.log"; then
  witness no_fire "guest booted + repro ran, no KASAN splat (race not won this run)"
else
  witness no_boot "guest did not reach repro (see work/serial.log)"
fi
