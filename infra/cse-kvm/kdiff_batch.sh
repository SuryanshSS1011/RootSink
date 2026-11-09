#!/usr/bin/env bash
# Resumable batch over <extid>\t<fix_sha> lines; N concurrent kdiff_kvm.sh runs. A case with a
# differential.json is done and skipped, so a rerun after a reboot or kill picks up where it left.
# Launch detached so an SSH drop cannot SIGHUP the builds:
#   setsid nohup bash kdiff_batch.sh cases.tsv 2 </dev/null >batch.log 2>&1 &
BASE="${CF_BASE:?set CF_BASE to the kernel work directory}"
CASES="${1:?usage: kdiff_batch.sh <cases.tsv> [concurrency]}"
N="${2:-2}"
export CF_BASE="$BASE"
mkdir -p "$BASE/logs"
while IFS=$'\t' read -r extid fix _; do
  [[ -z "$extid" || -f "$BASE/out/$extid/differential.json" ]] && continue
  pgrep -f "kdiff_kvm.sh $extid" >/dev/null && continue   # already running (e.g. before a restart)
  # Count our own background jobs: pgrep would also count each case's subshells.
  while (( $(jobs -rp | wc -l) >= N )); do sleep 20; done
  setsid bash "$BASE/kdiff_kvm.sh" "$extid" "$fix" >"$BASE/logs/$extid.log" 2>&1 </dev/null &
  echo "$(date +%T) launched $extid"
  sleep 5
done < "$CASES"
wait
echo "$(date) batch done"
