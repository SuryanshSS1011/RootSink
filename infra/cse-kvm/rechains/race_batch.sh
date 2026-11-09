#!/usr/bin/env bash
# race_batch.sh — autonomously attempt GOLD for the userspace-reachable race CVE batch.
# Each CVE: build KASAN kernel @ a vulnerable tag, race a stripped reproducer, attribute by a
# CVE-specific KASAN backtrace signature. Sequential (KVM/build contention). v5.4 is vulnerable to
# all four (vt/slcan/6pack/hci), so their kernels build fresh per-CVE but from the same tag.
set -u
CF="${CF_HOME:?set CF_HOME to the chainforge working directory}"
cd "$CF"; export CF_HOME="$CF"
GEN="$CF/race_replay_generic.sh"
LOG="$CF/race_gold/batch.log"
mkdir -p "$CF/race_gold"
echo "=== race batch start $(date) ===" | tee -a "$LOG"

# per-CVE config fragments
printf '%s\n' "CONFIG_VT=y" "CONFIG_VT_CONSOLE=y" "CONFIG_TTY=y" > "$CF/cfg_vt.txt"
printf '%s\n' "CONFIG_CAN=y" "CONFIG_CAN_SLCAN=y" "CONFIG_UNIX98_PTYS=y" > "$CF/cfg_slcan.txt"
printf '%s\n' "CONFIG_HAMRADIO=y" "CONFIG_AX25=y" "CONFIG_6PACK=y" "CONFIG_UNIX98_PTYS=y" > "$CF/cfg_6pack.txt"
printf '%s\n' "CONFIG_BT=y" "CONFIG_BT_HCIUART=y" "CONFIG_BT_HCIUART_H4=y" "CONFIG_UNIX98_PTYS=y" > "$CF/cfg_hci.txt"

run_one() {  # cve cause repro sig cfg
  echo "--- $1 @ $2 (repro=$(basename "$3")) $(date) ---" | tee -a "$LOG"
  bash "$GEN" "$1" "$2" "$3" "$4" "$5" 6 >> "$LOG" 2>&1 || true
  local st; st=$(grep -oE '"status": "[a-z_]+"' "$CF/race_gold/$1/witness.json" 2>/dev/null)
  echo "  => $1: $st" | tee -a "$LOG"
}

run_one "CVE-2020-36558" "v5.4" "$CF/repro_cve_2020_36558.c" "vc_|vt_|con_|consw|vc_resize" "$CF/cfg_vt.txt"
run_one "CVE-2020-14416" "v5.4" "$CF/repro_slcan.c" "slcan|slc_|can_" "$CF/cfg_slcan.txt"
run_one "CVE-2022-1195"  "v5.4" "$CF/repro_6pack.c" "sixpack|6pack|ax_|ax25|sp_" "$CF/cfg_6pack.txt"
run_one "CVE-2023-31083" "v5.4" "$CF/repro_hci.c"   "hci_uart|hci_|hu_" "$CF/cfg_hci.txt"

echo "=== race batch done $(date) ===" | tee -a "$LOG"
grep -hoE '"cve": "[^"]+", "status": "[a-z_]+"' "$CF"/race_gold/*/witness.json 2>/dev/null | sort -u | tee -a "$LOG"
