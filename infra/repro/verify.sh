#!/usr/bin/env bash
# Verify a ChainForge Reproduction Bundle end-to-end.
#
# Runs the pinned vulnerable image, replays the baked-in PoV, and compares the observed
# sanitizer witness against what the bundle DECLARES. Then runs the patched image and
# requires it to be clean. That differential is the reproduction claim; anything else is
# a FAIL, so a bundle cannot quietly rot.
#
# With --links, also performs the alternate-sanitizer rebuild needed to witness an
# intermediate CWE-190 link (the part a single-sanitizer image cannot show).
#
# Usage: verify.sh <bundle.json> [--links] [--keep]
# Exit:  0 = all declared expectations met, 1 = mismatch, 2 = infrastructure failure.
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PLATFORM="${ARVO_PLATFORM:-linux/amd64}"
BUILD_CPUS="${CF_BUILD_CPUS:-4}"
BUILD_MEM="${CF_BUILD_MEM:-6g}"

bundle=""; do_links=0; keep=0
for a in "$@"; do
  case "$a" in
    --links) do_links=1 ;;
    --keep)  keep=1 ;;
    *) [ -z "$bundle" ] && bundle="$a" ;;
  esac
done
[ -n "$bundle" ] && [ -f "$bundle" ] || { echo "usage: verify.sh <bundle.json> [--links] [--keep]" >&2; exit 2; }

jqf(){ python3 -c "import json,sys;d=json.load(open(sys.argv[1]));print(eval(sys.argv[2],{'d':d}) if True else '')" "$bundle" "$1" 2>/dev/null; }

rid=$(jqf "d['record_id']")
chain=$(jqf "d['chain']")
vul=$(jqf "d['images']['vulnerable']['ref']")
vul_dig=$(jqf "d['images']['vulnerable'].get('digest') or ''")
fix=$(jqf "d['images']['patched']['ref']")
fix_dig=$(jqf "d['images']['patched'].get('digest') or ''")
echo "[verify] $rid  chain=$chain"

# Pull BY DIGEST when the bundle pins one: that is the reproducibility guarantee.
# A tag can be moved or deleted; a digest either matches bit-for-bit or fails.
pull(){ # ref digest -> echoes the reference actually used
  local ref="$1" dig="$2" target="$1"
  if [ -n "$dig" ]; then target="${ref%%:*}@${dig}"; fi
  if ! docker pull --platform "$PLATFORM" "$target" >/dev/null 2>&1; then
    echo "[verify] FATAL: cannot pull $target" >&2; return 1
  fi
  echo "$target"
}

vul_target=$(pull "$vul" "$vul_dig") || exit 2
fix_target=$(pull "$fix" "$fix_dig") || exit 2
[ -n "$vul_dig" ] && echo "[verify] vulnerable pinned @ ${vul_dig:0:19}..." || echo "[verify] WARNING: no digest pin (tag only)"

tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT
docker run --rm --platform "$PLATFORM" "$vul_target" arvo >"$tmp/vul.txt" 2>&1 || true
docker run --rm --platform "$PLATFORM" "$fix_target" arvo >"$tmp/fix.txt" 2>&1 || true

if [ "$do_links" -eq 1 ]; then
  target_bin=$(docker run --rm --platform "$PLATFORM" "$vul_target" \
    sh -c 'grep -oE "/out/[a-zA-Z0-9_.-]+" /bin/arvo | head -1 | sed "s|/out/||"' 2>/dev/null)
  if [ -n "$target_bin" ]; then
    echo "[verify] intermediate-link check: UBSan rebuild ($target_bin)"
    docker run --rm --platform "$PLATFORM" \
      --cpuset-cpus="0-$((BUILD_CPUS-1))" --memory="$BUILD_MEM" --memory-swap="$BUILD_MEM" \
      -e SANITIZER=undefined \
      -e UBSAN_OPTIONS='print_stacktrace=1:halt_on_error=0:silence_unsigned_overflow=0:symbolize=1' \
      "$vul_target" \
      bash -c "compile >/dev/null 2>&1; echo BUILD_EXIT=\$?; /out/$target_bin /tmp/poc 2>&1" \
      >"$tmp/ubsan.txt" 2>&1 || true
  fi
fi

[ "$keep" -eq 1 ] || { docker rmi "$vul_target" "$fix_target" >/dev/null 2>&1 || true; }

python3 "$HERE/check.py" "$bundle" "$tmp/vul.txt" "$tmp/fix.txt" "$tmp/ubsan.txt"
