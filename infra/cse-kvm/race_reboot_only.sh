#!/usr/bin/env bash
# race_reboot_only.sh — reuse an ALREADY-BUILT v6.0 KASAN kernel + initramfs and just reboot
# to collect KASAN splats (races are probabilistic; more boots = more distinct UAF sites). No
# rebuild. Appends each run's distinct "use-after-free in <fn>" sites to sites.txt.
set -u
CF="${CF_HOME:?set CF_HOME to the chainforge working directory}"
BASE="$CF/race_gold/cve-2022-45884/work"
BZ="$BASE/build/arch/x86/boot/bzImage"
INITRD="$BASE/initramfs.cpio.gz"
N="${1:-5}"   # number of boots
OUT="$CF/race_gold/dvb_multi"; mkdir -p "$OUT"
QEMU="$(command -v qemu-system-x86_64 || echo /usr/libexec/qemu-kvm)"
[ -f "$BZ" ] || { echo "no cached bzImage at $BZ"; exit 1; }
: > "$OUT/sites.txt"
for i in $(seq 1 "$N"); do
  echo "[reboot $i/$N] booting..."
  timeout 240 "$QEMU" -enable-kvm -cpu host -smp 4 -m 2G \
    -kernel "$BZ" -initrd "$INITRD" \
    -append "console=ttyS0 panic=1 oops=panic kasan_multi_shot" \
    -nographic -no-reboot -net none > "$OUT/serial_$i.log" 2>&1 || true
  # collect distinct UAF sites this boot
  grep -oE "use-after-free in [a-z_]+" "$OUT/serial_$i.log" 2>/dev/null | sort -u >> "$OUT/sites.txt"
  nsites=$(grep -c "use-after-free" "$OUT/serial_$i.log" 2>/dev/null)
  echo "[reboot $i/$N] KASAN hits: $nsites"
done
echo "=== distinct UAF sites across $N boots ==="
sort "$OUT/sites.txt" | uniq -c | sort -rn
