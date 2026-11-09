#!/usr/bin/env bash
# Rebuild an ARVO case with integer-overflow checks and see whether an overflow precedes the
# known sink.
#
# Purpose is not scale for its own sake. 741 records in the corpus carry a CWE-20 source with
# ZERO attestation - CWE-20 was written in the source slot because the sink happened to be an
# out-of-bounds access, and nothing demonstrates a missing input-validation check. If a rebuild
# with -fsanitize=signed-integer-overflow,unsigned-integer-overflow reports an overflow on the
# same PoV, the source is no longer assumed: it is CWE-190, execution-witnessed and localized.
# That converts an unevidenced label into a witnessed one AND grows the arm the composition
# study ranks first.
#
# Why this was thought impossible: the earlier attempt set UBSAN_OPTIONS on the stock binary,
# which is built with SANITIZER=address and carries no UBSan instrumentation, so it could only
# ever report nothing. A real rebuild is required, and that failed on ROAR because Apptainer
# ignores the image's Docker WORKDIR (see infra/verify/ablate.sh).
#
# Usage: ubsan_rebuild.sh <arvo_id> <project> <outdir>
set -uo pipefail
ID="$1"; PROJECT="$2"; OUT="$3"
mkdir -p "$OUT"
NL="${TMPDIR:-/tmp}/ubr_${ID}_$$"; mkdir -p "$NL"
export APPTAINER_TMPDIR="$NL/at" APPTAINER_CACHEDIR="$NL/ac"
mkdir -p "$APPTAINER_TMPDIR" "$APPTAINER_CACHEDIR"
trap 'rm -rf "$NL"' EXIT
log(){ echo "[$ID] $*" >&2; }
emit(){ printf '%s\n' "$1" > "$OUT/result.json"; cat "$OUT/result.json"; exit 0; }

SIF="$NL/arvo_${ID}-vul.sif"
apptainer pull --force "$SIF" "docker://n132/arvo:${ID}-vul" >/dev/null 2>&1 \
  || emit '{"status":"image_pull_failed"}'

OV="$NL/ov"; mkdir -p "$OV/upper" "$OV/work"

# OSS-Fuzz's stock undefined-sanitizer flags omit unsigned-integer-overflow and use
# -fno-sanitize-recover, which halts at the FIRST finding. Both are wrong here: an unsigned
# wrap is the classic CWE-190 precursor to a short allocation, and halting early would hide
# whether the overflow actually precedes the sink on the same run.
UBFLAGS="-fsanitize=array-bounds,bool,builtin,enum,float-divide-by-zero,function,integer-divide-by-zero,null,object-size,return,returns-nonnull-attribute,shift,signed-integer-overflow,unsigned-integer-overflow,unreachable,vla-bound,vptr -fsanitize-recover=all -fsanitize=fuzzer-no-link"

log "rebuilding $PROJECT with integer-overflow checks"
# Debian defines `which` as a shell FUNCTION that pipes through
#   /usr/bin/which --tty-only --read-alias --read-functions --show-tilde --show-dot
# and these images ship a /usr/bin/which that rejects those flags. It answers with its usage
# text, which OSS-Fuzz's `cp $(which llvm-symbolizer) /out/` then takes as filenames:
#   cp: cannot stat 'Usage:' / '[-a]' / 'args'
# Apptainer sources a profile that defines the function; Docker does not, which is why this
# only ever appeared here. It accounted for 194 of 210 control failures - 92% of everything
# the ablation could not test.
# APPTAINERENV_ prefix, not --env: this Apptainer build rejects --env and answers with its
# usage text, which contains no FATAL and no CF_ marker, so a status check looking for those
# reads a container that never started as a successful run with zero findings.
APPTAINERENV_SANITIZER=undefined \
APPTAINERENV_SANITIZER_FLAGS_undefined="$UBFLAGS" \
APPTAINERENV_FUZZING_ENGINE=afl \
APPTAINERENV_ARCHITECTURE=x86_64 \
APPTAINERENV_UBSAN_OPTIONS='print_stacktrace=1:halt_on_error=0:silence_unsigned_overflow=0:symbolize=1' \
timeout 10800 apptainer exec --overlay "$OV" --no-mount tmp \
  "$SIF" bash -c "
    unset -f which 2>/dev/null; unalias which 2>/dev/null
    cd /src/$PROJECT 2>/dev/null || { echo CF_NO_SRCDIR; exit 7; }
    compile > /tmp/b.log 2>&1 || { echo CF_BUILD_FAIL; tail -20 /tmp/b.log; exit 8; }
    T=\$(ls /out | grep -vE '\.(so|a|txt|json|options|dict)$' | head -1)
    [ -n \"\$T\" ] || { echo CF_NO_TARGET; exit 6; }
    echo \"CF_TARGET=\$T\"
    /out/\$T /tmp/poc 2>&1 | head -200
  " > "$OUT/ubsan.log" 2>&1

for marker in CF_NO_SRCDIR:no_src_dir CF_BUILD_FAIL:build_failed CF_NO_TARGET:no_target; do
  if grep -q "${marker%%:*}" "$OUT/ubsan.log"; then
    emit "{\"arvo_id\":\"$ID\",\"project\":\"$PROJECT\",\"status\":\"${marker##*:}\"}"
  fi
done
# Any container-level failure, including an apptainer CLI usage error, must not be read as a
# run that found nothing. This is the fifth time a tool-level failure has masqueraded as a
# negative observation; the check is deliberately broad.
if grep -qE "^FATAL:|container creation failed|Run 'apptainer --help'|^Usage:|unknown flag|invalid option" "$OUT/ubsan.log"; then
  emit "{\"arvo_id\":\"$ID\",\"status\":\"container_failed\"}"
fi
# A build that genuinely ran prints the toolchain banner; its absence means compile never ran.
grep -q "CF_TARGET=" "$OUT/ubsan.log" \
  || emit "{\"arvo_id\":\"$ID\",\"status\":\"build_never_ran\"}"
[ -s "$OUT/ubsan.log" ] || emit "{\"arvo_id\":\"$ID\",\"status\":\"no_output\"}"

python3 - <<PY > "$OUT/result.json"
import json, re
t = open("$OUT/ubsan.log", errors="replace").read()
NOISE = re.compile(r"(compiler-rt|/usr/include/|libfuzzer|/src/(afl|honggfuzz|libfuzzer)/)")
kinds = []
for m in re.finditer(r"runtime error:\s*([^\n]{0,90})", t):
    k = m.group(1).strip()
    if k not in kinds:
        kinds.append(k)
# The site of the FIRST integer overflow: the candidate CWE-190 source.
site = None
for m in re.finditer(r"([A-Za-z0-9_./+-]+\.(?:c|cc|cpp|cxx|h|hpp)):(\d+):(\d+)?", t):
    if not NOISE.search(m.group(1)):
        site = {"file": m.group(1), "line": int(m.group(2))}
        break
overflow = [k for k in kinds if "overflow" in k or "cannot be represented" in k]
print(json.dumps({
    "arvo_id": "$ID", "project": "$PROJECT", "status": "ok",
    "ubsan_findings": len(kinds), "kinds": kinds[:8],
    "integer_overflow_witnessed": bool(overflow),
    "overflow_kinds": overflow[:4],
    "candidate_cwe190_site": site if overflow else None,
}, indent=1))
PY
cat "$OUT/result.json"
