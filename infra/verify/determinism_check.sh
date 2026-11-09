#!/usr/bin/env bash
# Does this reproduction actually reproduce, repeatedly?
#
# SPECIFICATION R5 says GOLD means "you can re-run this", but nothing ever verified that a
# reproduction is STABLE. Every witness in the corpus comes from a single run, so a flaky
# case - one that fires on some executions and not others - currently ships as GOLD
# indistinguishably from a deterministic one. Exhibit A (SuryanshSS1011/Exhibit-A) treats this
# as admission-blocking: its determinism gate quarantines unstable candidates rather than
# scoring them, on the principle that an unavailable measurement must not become a zero. That
# is the same rule as R10, applied to a dimension we had not measured.
#
# Cheap, because it needs no rebuild: the ARVO image already carries the built binary and the
# baked-in PoV, so a run is seconds.
#
# Usage: determinism_check.sh <arvo_id> <outdir> [runs]
set -uo pipefail
ID="$1"; OUT="$2"; RUNS="${3:-5}"
mkdir -p "$OUT"
NL="${TMPDIR:-/tmp}/det_${ID}_$$"; mkdir -p "$NL"
export APPTAINER_TMPDIR="$NL/at" APPTAINER_CACHEDIR="$NL/ac"
mkdir -p "$APPTAINER_TMPDIR" "$APPTAINER_CACHEDIR"
trap 'rm -rf "$NL"' EXIT
emit(){ printf '%s\n' "$1" > "$OUT/result.json"; cat "$OUT/result.json"; exit 0; }

SIF="$NL/arvo_${ID}-vul.sif"
apptainer pull --force "$SIF" "docker://n132/arvo:${ID}-vul" >/dev/null 2>&1 \
  || emit "{\"arvo_id\":\"$ID\",\"status\":\"image_pull_failed\"}"

CRASH=0; CLEAN=0; INFRA=0
SIGS=""
for i in $(seq 1 "$RUNS"); do
  apptainer exec --no-mount tmp "$SIF" arvo > "$OUT/run$i.log" 2>&1
  if grep -qE "^FATAL:|container creation failed" "$OUT/run$i.log"; then
    INFRA=$((INFRA+1)); continue
  fi
  if grep -qE "ERROR: (Address|Memory|Leak)Sanitizer|WARNING: MemorySanitizer|runtime error:|SUMMARY: .*Sanitizer" "$OUT/run$i.log"; then
    CRASH=$((CRASH+1))
    # keep the crash class so a case that fires DIFFERENT bugs across runs is not called stable
    # Normalise addresses out: ASLR makes every pointer differ between runs, so comparing raw
    # report text would call a perfectly deterministic case flaky. The first pass did exactly
    # that on 42496486, which crashed 5/5 with the same UBSan downcast at five addresses.
    s=$(grep -oE "(ERROR: [A-Za-z]+Sanitizer: [a-z-]+|runtime error: [^,]{0,40})" "$OUT/run$i.log" \
        | head -1 | sed -E "s/0x[0-9a-fA-F]+/0xADDR/g; s/[0-9]{5,}/N/g")
    SIGS="$SIGS|$s"
  else
    CLEAN=$((CLEAN+1))
  fi
done

python3 - <<PY > "$OUT/result.json"
import json
crash, clean, infra, runs = $CRASH, $CLEAN, $INFRA, $RUNS
sigs = [s for s in """$SIGS""".split("|") if s.strip()]
tested = crash + clean
distinct = sorted(set(sigs))
# Stable means every TESTED run agreed, and agreed on the same crash class. Infrastructure
# failures are excluded from the denominator rather than counted as non-reproduction.
stable = tested > 0 and (crash == tested or clean == tested) and len(distinct) <= 1
print(json.dumps({
    "arvo_id": "$ID", "runs": runs, "crashed": crash, "clean": clean,
    "infra_failed": infra, "tested": tested,
    "distinct_crash_signatures": distinct,
    "stability": (max(crash, clean) / tested) if tested else None,
    "deterministic": stable,
    "verdict": ("deterministic" if stable else
                ("untested" if tested == 0 else "FLAKY")),
}, indent=1))
PY
cat "$OUT/result.json"
