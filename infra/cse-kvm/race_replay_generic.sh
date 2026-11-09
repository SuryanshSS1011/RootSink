#!/usr/bin/env bash
# race_replay_generic.sh — EARN GOLD for a CWE-362 race->UAF CVE by building a KASAN kernel at a
# vulnerable revision and racing a stripped reproducer under real SMP. Generic over CVE/kernel/
# config: a CVE whose driver is reachable from userspace (pty/ldisc/loopback/pure-fd) needs no
# hardware. Attributes GOLD by a CVE-specific KASAN backtrace signature.
#
# Usage: race_replay_generic.sh <cve> <cause_tag> <repro.c> <sig-regex> [config_fragment] [nboots]
set -u
CVE="${1:?usage: <cve> <cause> <repro.c> <sig> [cfg] [nboots]}"
CAUSE="${2:?need cause tag}"
REPRO_SRC="${3:?need repro.c}"
SIG="${4:?need KASAN signature regex}"
CFGFRAG="${5:-}"
NBOOT="${6:-8}"
CF="${CF_HOME:?set CF_HOME to the chainforge working directory}"
OUT="$CF/race_gold/$CVE"; mkdir -p "$OUT"; OUT="$(cd "$OUT" && pwd)"
KSRC="${KSRC:-$CF/linux}"; JOBS="${JOBS:-$(nproc)}"
WORK="$OUT/work"; mkdir -p "$WORK"
REPRO_SRC="$(cd "$(dirname "$REPRO_SRC")" && pwd)/$(basename "$REPRO_SRC")"
[ -n "$CFGFRAG" ] && CFGFRAG="$(cd "$(dirname "$CFGFRAG")" && pwd)/$(basename "$CFGFRAG")"
log() { echo "[race $CVE] $*"; }
witness() {
  cat > "$OUT/witness.json" <<JSON
{"cve": "$CVE", "status": "$1", "detail": "$2", "cause_commit": "$CAUSE",
 "kasan_type": "${KTYPE:-}", "gold_eligible": $([ "$1" = kasan_fired ] && echo true || echo false)}
JSON
  log "WITNESS: $1 ($2)"; [ "$1" = kasan_fired ] && exit 0 || true
}
if grep -q '"status": "kasan_fired"' "$OUT/witness.json" 2>/dev/null; then
  log "already kasan_fired — skipping"; exit 0; fi

# 1. Checkout + config (defconfig + KASAN + SMP + virtio + userns + optional CVE fragment).
log "checkout $KSRC @ $CAUSE"
git -C "$KSRC" checkout -q -f "$CAUSE" 2>"$WORK/checkout.log" || witness checkout_failed "$CAUSE"
log "configuring (KASAN + SMP + virtio + userns)"
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
CONFIG_USER_NS=y
CONFIG_NET_NS=y
CONFIG_UNIX98_PTYS=y
CFG
[ -n "$CFGFRAG" ] && [ -f "$CFGFRAG" ] && cat "$CFGFRAG" >> "$WORK/build/.config"
make -C "$KSRC" O="$WORK/build" olddefconfig >/dev/null 2>&1

# 2. Build KASAN kernel.
log "building bzImage (KASAN) -j$JOBS gcc-$(gcc -dumpversion)"
make -C "$KSRC" O="$WORK/build" -j"$JOBS" bzImage >"$WORK/kbuild.log" 2>&1 \
  || witness build_failed "bzImage build failed (see kbuild.log)"
BZ="$WORK/build/arch/x86/boot/bzImage"

# 3. repro (dynamic + bundled libs) + busybox initramfs.
log "compiling repro + initramfs"
gcc -O1 -o "$WORK/repro" "$REPRO_SRC" -lpthread 2>"$WORK/cc.log" \
  || witness repro_cc_failed "repro compile failed"
BB="${CF_BUSYBOX:-$CF/imgbuild/busybox}"; [ -x "$BB" ] || BB="$(command -v busybox)"
ROOT="$WORK/root"; rm -rf "$ROOT"; mkdir -p "$ROOT"/{bin,proc,sys,dev,tmp}
cp "$BB" "$ROOT/bin/busybox"; ln -sf busybox "$ROOT/bin/sh"; cp "$WORK/repro" "$ROOT/repro"
for so in $(ldd "$WORK/repro" 2>/dev/null | grep -oE "/[^ ]+\.so[^ ]*"); do
  d="$ROOT$(dirname "$so")"; mkdir -p "$d"; cp -L "$so" "$d/" 2>/dev/null || true; done
cat > "$ROOT/init" <<'INIT'
#!/bin/sh
/bin/busybox mount -t proc none /proc
/bin/busybox mount -t sysfs none /sys
/bin/busybox mount -t devtmpfs none /dev 2>/dev/null
echo "[cf] guest up"; /repro
echo "[cf] repro returned; halting"; /bin/busybox poweroff -f
INIT
chmod +x "$ROOT/init"
( cd "$ROOT" && find . | cpio -o -H newc 2>/dev/null | gzip > "$WORK/initramfs.cpio.gz" )

# 4. Boot N times (races are probabilistic); stop early on the CVE-specific signature.
QEMU="$(command -v qemu-system-x86_64 || echo /usr/libexec/qemu-kvm)"
SMP=4; [ "$JOBS" -lt 4 ] && SMP="$JOBS"
: > "$WORK/all_sites.txt"
for i in $(seq 1 "$NBOOT"); do
  log "boot $i/$NBOOT"
  timeout 260 "$QEMU" -enable-kvm -cpu host -smp "$SMP" -m 2G \
    -kernel "$BZ" -initrd "$WORK/initramfs.cpio.gz" \
    -append "console=ttyS0 panic=1 oops=panic kasan_multi_shot" \
    -nographic -no-reboot -net none > "$WORK/serial_$i.log" 2>&1 || true
  grep -oE "use-after-free in [a-z_]+" "$WORK/serial_$i.log" 2>/dev/null | sort -u >> "$WORK/all_sites.txt"
  if grep -qE "use-after-free in ($SIG)" "$WORK/serial_$i.log"; then
    KTYPE="$(grep -oE "use-after-free in ($SIG)[a-z_]*" "$WORK/serial_$i.log" | head -1)"
    cp "$WORK/serial_$i.log" "$OUT/kasan_report.log"
    witness kasan_fired "observed KASAN: $KTYPE under SMP=$SMP"
    echo "=== sites ==="; sort "$WORK/all_sites.txt" | uniq -c | sort -rn; exit 0
  fi
done
echo "=== sites across $NBOOT boots (sig '$SIG' NOT seen) ==="
sort "$WORK/all_sites.txt" | uniq -c | sort -rn
witness no_target_fire "$NBOOT boots; CVE signature '$SIG' not observed"
exit 1
