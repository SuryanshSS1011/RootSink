#!/usr/bin/env bash
# Causal ablation: does THIS hunk of the developer's fix stop the crash?
#
# The corpus can say a fix adds a guard near the bug (attested). It cannot say the guard's
# ABSENCE caused the sink. This answers that directly: rebuild the vulnerable revision with one
# hunk applied and nothing else, replay the PoV, and see whether the sanitizer still fires. A
# hunk that alone silences the crash is a CAUSALLY PROVEN source, stronger than any evidence
# kind currently in the dataset.
#
# Nothing is invented: hunks come from the developer's own patch. A model would only ever
# choose an ORDER to try them in, and for the 102 single-hunk fixes not even that.
#
# Three container facts, each of which cost a failed run to learn:
#   * Apptainer IGNORES the image's Docker WORKDIR. OSS-Fuzz build.sh scripts are written
#     relative to $SRC/$PROJECT (skia's opens with "pushd third_party/externals/swiftshader/"),
#     so without an explicit cd every build dies on its first relative path. This is almost
#     certainly why the UBSan rebuild was believed to be Docker-only.
#   * Use `arvo compile` / `arvo run`, not bare `compile`. The wrapper exports SANITIZER,
#     FUZZING_ENGINE and the *SAN_OPTIONS the build expects, and knows the target binary name.
#   * --writable-tmpfs is a small RAM-backed overlay; a real OSS-Fuzz build exhausts it partway
#     through LLVM. A file-backed overlay on node-local scratch is required.
#
# Usage: ablate.sh <arvo_id> <project> <fix.diff> <outdir>
set -uo pipefail
ID="$1"; PROJECT="$2"; DIFF="$3"; OUT="$4"
CF=/scratch/$USER/chainforge
mkdir -p "$OUT"
NL="${TMPDIR:-/tmp}/ablate_${ID}_$$"; mkdir -p "$NL"
export APPTAINER_TMPDIR="$NL/at" APPTAINER_CACHEDIR="$NL/ac"
mkdir -p "$APPTAINER_TMPDIR" "$APPTAINER_CACHEDIR"
trap 'rm -rf "$NL"' EXIT
log(){ echo "[$ID] $*" >&2; }   # stderr: stdout is the caller's result channel

emit(){ printf '%s\n' "$1" > "$OUT/result.json"; cat "$OUT/result.json"; exit 0; }

SIF="$NL/arvo_${ID}-vul.sif"
apptainer pull --force "$SIF" "docker://n132/arvo:${ID}-vul" >/dev/null 2>&1 \
  || emit '{"status":"image_pull_failed"}'

python3 "$CF/repo/infra/verify/split_hunks.py" "$DIFF" "$OUT/hunks" > "$OUT/split.log" 2>&1 \
  || emit '{"status":"hunk_split_failed"}'
N=$(python3 -c "import json;print(json.load(open('$OUT/hunks/index.json'))['written'])" 2>/dev/null || echo 0)
[ "$N" -gt 0 ] || emit '{"status":"no_code_hunks"}'
log "$N candidate hunks, project=$PROJECT"


# Which directory does build.sh expect to start in? It is NOT uniform, and Apptainer records
# the image's Docker WORKDIR nowhere, so it has to be derived. Rather than infer it from a
# directory listing, take a WITNESS path out of build.sh and test where that path resolves:
#   skia      "pushd third_party/externals/swiftshader/" -> resolves under /src/skia
#   libucl    "cd libucl"                                -> resolves under /src
#   jsoncons  "cd jsoncons/fuzzers"                      -> resolves under /src
#   bitcoin   "./ossfuzz.sh"      (no cd at all)         -> wherever that script lives
# The previous rule grepped the whole cd target against `ls /src`, so a MULTI-SEGMENT target
# like jsoncons's could never match a listing entry and the build silently ran from the wrong
# directory; and a build.sh opening on a command rather than a cd got no signal at all. Between
# them those two gaps account for 19 of the 39 control build failures in the ablatefull batch,
# every one recorded as "unmodified rebuild does not reproduce" rather than as a wrong cwd.
incheck(){ apptainer exec --no-mount tmp "$SIF" sh -c "$1" >/dev/null 2>&1; }
probe(){ apptainer exec --no-mount tmp "$SIF" sh -c "$1" 2>/dev/null; }

FIRSTCD=$(probe "grep -oE '^[[:space:]]*(cd|pushd)[[:space:]]+[^ ;&|)]+' /src/build.sh | head -1" \
  | awk '{print $2}' | tr -d "\"'")
WITNESS=${FIRSTCD%%[\$*]*}   # drop from the first $ or * : the rest is not a literal path
if [ -z "$WITNESS" ]; then   # no cd -> the first relative path the script runs
  WITNESS=$(probe "grep -oE '(^|[[:space:]])\./[A-Za-z0-9_./-]+' /src/build.sh | head -1" | tr -d ' ')
fi
if [ -z "$WITNESS" ]; then   # ... or a bare multi-segment relative path (hbfa-fl/oss-fuzz/build.sh)
  WITNESS=$(probe "grep -oE '^[[:space:]]*[A-Za-z0-9_-]+(/[A-Za-z0-9_.-]+)+' /src/build.sh | head -1" | tr -d ' ')
fi
WITNESS=${WITNESS#./}; WITNESS=${WITNESS%/}
SRCDIR=""
if [ -n "$WITNESS" ]; then
  for CAND in "/src/$PROJECT" /src; do
    incheck "test -e '$CAND/$WITNESS'" && { SRCDIR=$CAND; break; }
  done
fi
[ -n "$SRCDIR" ] || SRCDIR="/src/$PROJECT"
incheck "test -d '$SRCDIR'" || SRCDIR=/src
log "build cwd: $SRCDIR (witness: ${WITNESS:-none}, first cd: ${FIRSTCD:-none})"

# One long-lived overlay: build once, then apply / rebuild / revert per hunk. A fresh overlay
# per hunk would mean a full rebuild each time (~25 min for skia); incremental rebuilds after a
# one-line patch take a fraction of that.
# A FRESH overlay per variant. Reusing one and rebuilding incrementally was cheaper but
# wrong: OSS-Fuzz build.sh scripts are not idempotent, so a second `compile` in the same tree
# dies on work the first one already did (opus: "tar xzf nasm-2.13.01" -> "Is a directory").
# That cost 8 of 17 settled cases, every one recorded as a build failure rather than a guard.
# Debian defines `which` as a shell FUNCTION that pipes through
#   /usr/bin/which --tty-only --read-alias --read-functions --show-tilde --show-dot
# and these images ship a /usr/bin/which that rejects those flags. It answers with its usage
# text, which OSS-Fuzz's `cp $(which llvm-symbolizer) /out/` then takes as filenames:
#   cp: cannot stat 'Usage:' / '[-a]' / 'args'
# Apptainer sources a profile that defines the function; Docker does not, which is why this
# only ever appeared here. It accounted for 194 of 210 control failures - 92% of everything
# the ablation could not test.
incontainer(){   # <script> -> runs in the container against a clean overlay
  rm -rf "$NL/ov"; mkdir -p "$NL/ov/upper" "$NL/ov/work"
  apptainer exec --overlay "$NL/ov" --no-mount tmp \
    ${PATCHBIND:+--bind "$NL/p.patch:/tmp/cf_p.patch"} \
    "$SIF" bash -c "unset -f which 2>/dev/null; unalias which 2>/dev/null; cd $SRCDIR 2>/dev/null || { echo CF_NO_SRCDIR; exit 7; }; $1"
}

verdict(){   # <logfile> -> crashed|clean|infrafail|patchfail|buildfail
  local f="$1"
  grep -q CF_NO_SRCDIR   "$f" && { echo infrafail; return; }
  grep -q CF_PATCH_FAIL  "$f" && { echo patchfail; return; }
  grep -q CF_BUILD_FAIL  "$f" && { echo buildfail; return; }
  # A container that never started is not a clean run. Its FATAL text makes the log non-empty,
  # so testing "is the log non-empty" would score an infrastructure fault as no-crash - the
  # mistake SPECIFICATION R10 exists to forbid.
  grep -qE "^FATAL:|container creation failed" "$f" && { echo infrafail; return; }
  grep -qE "ERROR: (Address|Memory|Leak)Sanitizer|WARNING: MemorySanitizer|runtime error:|SUMMARY: .*Sanitizer" "$f" \
    && { echo crashed; return; }
  # Clean only if the input demonstrably ran: any log without a crash line used to score clean,
  # so a binary that never reached the input could stop the search at a false guard.
  grep -qE "Executed /tmp/poc|Execution successful" "$f" \
    || { grep -q "Accepting input from '/tmp/poc'" "$f" && grep -q "Usage for fuzzing" "$f"; } \
    && echo clean || echo infrafail
}

# ---- CONTROL: full rebuild, unmodified. If this does not crash, nothing after it means
# anything - a "clean" would then be indistinguishable from a build that simply cannot
# reproduce, and the case must be discarded rather than reported as a proven guard.
log "control: full rebuild, no patch"
PATCHBIND=""
incontainer 'arvo compile > /tmp/b.log 2>&1 || { echo CF_BUILD_FAIL; tail -40 /tmp/b.log; exit 8; }
             arvo run 2>&1 | head -60' > "$OUT/control.log" 2>&1
CTRL=$(verdict "$OUT/control.log")
log "control -> $CTRL"
[ "$CTRL" = "crashed" ] || emit "$(python3 -c "
import json; print(json.dumps({'arvo_id':'$ID','project':'$PROJECT','status':'control_'+('infrastructure_failed' if '$CTRL' in ('infrafail','buildfail') else 'did_not_crash'),'control':'$CTRL','note':'unmodified rebuild does not reproduce; ablation cannot be interpreted'}))")"

# ---- ABLATE each hunk against that built tree, reverting after every attempt.
RESULTS="[]"
for i in $(seq 0 $((N-1))); do
  H=$(printf "hunk%02d.patch" "$i")
  cp "$OUT/hunks/$H" "$NL/p.patch"; PATCHBIND=1
  incontainer 'for L in 1 0 2; do patch -p$L --fuzz=0 --forward --batch --dry-run < /tmp/cf_p.patch >/dev/null 2>&1 && break; done
               patch -p$L --fuzz=0 --forward --batch < /tmp/cf_p.patch > /tmp/p.log 2>&1 || { echo CF_PATCH_FAIL; cat /tmp/p.log; exit 9; }
               arvo compile > /tmp/b.log 2>&1 || { echo CF_BUILD_FAIL; tail -40 /tmp/b.log; exit 8; }
               arvo run 2>&1 | head -60
               true  # fresh overlay next round; no revert needed' \
    > "$OUT/$H.log" 2>&1
  R=$(verdict "$OUT/$H.log")
  log "  $H -> $R"
  RESULTS=$(python3 -c "
import json
r=json.loads('''$RESULTS''')
idx={h['name']:h for h in json.load(open('$OUT/hunks/index.json'))['hunks']}
h=idx.get('$H',{})
r.append({'hunk':'$H','file':h.get('file'),'added':h.get('added'),'removed':h.get('removed'),'outcome':'$R'})
print(json.dumps(r))")
  # A dirty tree invalidates every later result, so stop rather than report from one.
  if grep -q CF_REVERT_FAIL "$OUT/$H.log"; then log "  revert failed - stopping"; break; fi
  [ "$R" = "clean" ] && { log "  GUARD FOUND: $H"; break; }
done

emit "$(python3 - <<PY
import json
res = json.loads('''$RESULTS''')
guard = next((r for r in res if r["outcome"] == "clean"), None)
print(json.dumps({"arvo_id":"$ID","project":"$PROJECT","status":"ok","control":"$CTRL",
                  "n_hunks":$N,"n_tried":len(res),"results":res,"guard_hunk":guard,
                  "source_causally_proven":bool(guard)}, indent=1))
PY
)"
