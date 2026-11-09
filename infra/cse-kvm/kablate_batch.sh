#!/usr/bin/env bash
# Resumable kernel guard-ablation batch over <extid>\t<fix_sha> lines (see kdiff_batch.sh).
#   setsid nohup bash kablate_batch.sh kablate_targets.tsv 1 </dev/null >logs/kablate.log 2>&1 &
BASE="${CF_BASE:?set CF_BASE to the kernel work directory}"
CASES="${1:?usage: kablate_batch.sh <cases.tsv> [concurrency]}"
N="${2:-1}"
export CF_BASE="$BASE"
while IFS=$'\t' read -r extid fix _; do
  [[ -z "$extid" || -f "$BASE/ablate/$extid/result.json" ]] && continue
  pgrep -f "kablate_kvm.sh $extid" >/dev/null && continue
  while (( $(jobs -rp | wc -l) >= N )); do sleep 20; done
  setsid bash "$BASE/kablate_kvm.sh" "$extid" "$fix" >"$BASE/logs/kablate_$extid.log" 2>&1 </dev/null &
  echo "$(date +%T) launched $extid"
  sleep 5
done < "$CASES"
wait
echo "$(date) kablate batch done"
