#!/usr/bin/env bash
# race_replay_dvb_node.sh — reuse the CACHED v6.0+vidtv KASAN kernel to witness a node-specific
# dvb-core race UAF. Rebuilds ONLY the initramfs (with the given targeted reproducer) and reboots
# a few times. Attributes GOLD by a CVE-specific KASAN backtrace signature (e.g. dvb_net_,
# dvb_frontend_) so a sibling CVE isn't credited off the shared dvr/demux splat.
#
# Usage: race_replay_dvb_node.sh <cve> <repro.c> <sig-regex> [nboots]
set -u
CVE="${1:?usage: <cve> <repro.c> <sig-regex> [nboots]}"
REPRO_SRC="${2:?need repro.c}"
SIG="${3:?need KASAN signature regex, e.g. dvb_net_|dvb_frontend_}"
NBOOT="${4:-6}"
CF="${CF_HOME:?set CF_HOME to the chainforge working directory}"
BASE="$CF/race_gold/cve-2022-45884/work"   # cached kernel build
BZ="$BASE/build/arch/x86/boot/bzImage"
OUT="$CF/race_gold/$CVE"; mkdir -p "$OUT"; OUT="$(cd "$OUT" && pwd)"
WORK="$OUT/work"; mkdir -p "$WORK"
REPRO_SRC="$(cd "$(dirname "$REPRO_SRC")" && pwd)/$(basename "$REPRO_SRC")"
log() { echo "[dvb-node $CVE] $*"; }
witness() {
  cat > "$OUT/witness.json" <<JSON
{"cve": "$CVE", "status": "$1", "detail": "$2", "cause_commit": "v6.0",
 "kasan_type": "${KTYPE:-}", "gold_eligible": $([ "$1" = kasan_fired ] && echo true || echo false)}
JSON
  log "WITNESS: $1 ($2)"; [ "$1" = kasan_fired ] && exit 0 || true
}
[ -f "$BZ" ] || { log "no cached bzImage ($BZ) — run race_replay_dvb.sh first"; exit 1; }
if grep -q '"status": "kasan_fired"' "$OUT/witness.json" 2>/dev/null; then
  log "already kasan_fired (GOLD) — skipping"; exit 0; fi

# build initramfs with the targeted reproducer (dynamic + bundled libs + busybox)
log "building initramfs with $REPRO_SRC"
gcc -O1 -o "$WORK/repro" "$REPRO_SRC" -lpthread 2>"$WORK/cc.log" || { log "repro cc failed"; cat "$WORK/cc.log"; exit 1; }
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

QEMU="$(command -v qemu-system-x86_64 || echo /usr/libexec/qemu-kvm)"
: > "$WORK/all_sites.txt"
for i in $(seq 1 "$NBOOT"); do
  log "boot $i/$NBOOT"
  timeout 260 "$QEMU" -enable-kvm -cpu host -smp 4 -m 2G \
    -kernel "$BZ" -initrd "$WORK/initramfs.cpio.gz" \
    -append "console=ttyS0 panic=1 oops=panic kasan_multi_shot" \
    -nographic -no-reboot -net none > "$WORK/serial_$i.log" 2>&1 || true
  grep -oE "use-after-free in [a-z_]+" "$WORK/serial_$i.log" 2>/dev/null | sort -u >> "$WORK/all_sites.txt"
  # CVE-specific signature hit this boot?
  if grep -qE "use-after-free in ($SIG)" "$WORK/serial_$i.log"; then
    KTYPE="$(grep -oE "use-after-free in ($SIG)[a-z_]*" "$WORK/serial_$i.log" | head -1)"
    cp "$WORK/serial_$i.log" "$OUT/kasan_report.log"
    witness kasan_fired "observed KASAN: $KTYPE (node-specific, SMP=4)"
    echo "=== sites across boots ==="; sort "$WORK/all_sites.txt" | uniq -c | sort -rn
    exit 0
  fi
done
echo "=== sites across $NBOOT boots (CVE sig '$SIG' NOT seen) ==="
sort "$WORK/all_sites.txt" | uniq -c | sort -rn
witness no_target_fire "ran $NBOOT boots; CVE-specific signature '$SIG' not observed"
exit 1
