#!/usr/bin/env bash
# Robust kernel-GOLD batch: census C-reproducer cases, then replay them, 3 concurrent.
# Launch DETACHED so SSH disconnect can't SIGHUP the builds:
#   setsid nohup bash kgold_batch2.sh <n_cases> </dev/null >batch2.log 2>&1 &
BASE="${CF_HOME:?set CF_HOME to the chainforge working directory}"
NCASES="${1:-12}"
export CF_BOOT_TIMEOUT=900
mkdir -p "$BASE/batchlogs"

echo "[batch] $(date) censusing C-reproducer cases..."
python3 - "$BASE/kernel_extids.txt" "$BASE/crepro_ids.txt" "$NCASES" <<'PY'
import json, sys, urllib.request
ids = [x.strip() for x in open(sys.argv[1]) if x.strip()]
out, want = [], int(sys.argv[3])
for e in ids:
    if len(out) >= want:
        break
    try:
        d = json.load(urllib.request.urlopen(
            f"https://syzkaller.appspot.com/bug?extid={e}&json=1", timeout=25))
        if any(x.get("c-reproducer") for x in (d.get("crashes") or [])):
            out.append(e)
    except Exception:
        pass
open(sys.argv[2], "w").write("\n".join(out) + "\n")
print(f"[census] found {len(out)} C-reproducer cases")
PY

echo "[batch] replaying $(wc -l < "$BASE/crepro_ids.txt") cases, 3 concurrent"
i=0
while read -r extid; do
  [ -z "$extid" ] && continue
  i=$((i+1))
  while [ "$(pgrep -f 'kernel_replay_kvm.sh' | wc -l)" -ge 3 ]; do sleep 15; done
  setsid bash "$BASE/kernel_replay_kvm.sh" "$extid" > "$BASE/batchlogs/$extid.log" 2>&1 < /dev/null &
  echo "[batch] [$i] launched $extid"
  sleep 3
done < "$BASE/crepro_ids.txt"
echo "[batch] all launched, waiting..."
wait
echo "[batch] $(date) DONE"
