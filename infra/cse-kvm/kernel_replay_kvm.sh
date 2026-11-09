#!/usr/bin/env bash
# kernel_replay_kvm.sh — EARN kernel GOLD by replaying a syzbot C reproducer under KASAN on a
# REAL KVM host (e5-cse, /dev/kvm present). Self-contained: fetches artifacts via curl (no
# httpx/pydantic), builds with the host gcc, boots qemu-kvm with -enable-kvm -smp (real SMP, so
# race UAFs actually trip — the thing ROAR's TCG could not do).
#
# Usage: kernel_replay_kvm.sh <extid> [outdir]
set -uo pipefail

EXTID="${1:?usage: kernel_replay_kvm.sh <extid>}"
# Work on /scratch (1.8T), NOT $HOME — home has a 1GB quota that a kernel tree instantly blows.
BASE="${CF_BASE:?set CF_BASE to the chainforge working directory}"
OUTDIR="${2:-$BASE/kernel_gold/$EXTID}"
WORK="$BASE/kbuild/$EXTID"
QEMU="${CF_QEMU:-/usr/libexec/qemu-kvm}"
SYZ="https://syzkaller.appspot.com"
mkdir -p "$OUTDIR" "$WORK"

log() { echo "[kgold $EXTID] $*"; }
witness() {  # $1=status $2=detail
  cat > "$OUTDIR/witness.json" <<EOF
{"extid": "$EXTID", "status": "$1", "detail": "$2", "cause_commit": "${CAUSE:-}",
 "kasan_type": "${KTYPE:-}", "gold_eligible": $([ "$1" = kasan_fired ] && echo true || echo false)}
EOF
  log "witness -> $1 ($2)"
  [[ "${CF_KEEP:-0}" != "1" ]] && rm -rf "$WORK"
  exit 0
}

# 1. Fetch bug_json, pick a crash with a C reproducer, download {repro.c, config, cause commit}.
log "fetching syzbot artifacts"
curl -sS "$SYZ/bug?extid=$EXTID&json=1" -o "$WORK/bug.json" 2>/dev/null || witness no_artifacts "bug.json fetch failed"
# Parse with python3 stdlib (json module always present).
read -r CAUSE KGIT CRE CFG < <(python3 - "$WORK/bug.json" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
crashes = d.get("crashes") or []
c = next((x for x in crashes if x.get("c-reproducer")), None)
if not c:
    print("NONE NONE NONE NONE"); sys.exit(0)
print(c.get("kernel-source-commit","") or "-", c.get("kernel-source-git","") or "-",
      c.get("c-reproducer","") or "-", c.get("kernel-config","") or "-")
PY
)
[[ "$CRE" == "-" || "$CRE" == "NONE" ]] && witness no_crepro "no C reproducer"
[[ "$CAUSE" == "-" || -z "$CAUSE" ]] && witness no_commit "no kernel-source-commit"
curl -sS "$SYZ$CRE" -o "$WORK/repro.c" 2>/dev/null || witness no_crepro "repro download failed"
curl -sS "$SYZ$CFG" -o "$WORK/kernel.config" 2>/dev/null || witness no_config "config download failed"
log "cause ${KGIT##*/} @ ${CAUSE:0:12}"

# 2. Clone kernel @ cause (blobless), apply config + KASAN.
KSRC="$WORK/linux"
# git:// (port 9418) is firewalled on CSE -> https. And --filter=blob:none fails over kernel.org's
# http backend ("invalid index-pack output"); instead SHALLOW-FETCH just the cause commit into an
# init repo (git 2.43 + kernel.org allow fetching a specific SHA at --depth 1). Fast + reliable.
KGIT_HTTPS="${KGIT/git:\/\//https://}"
log "fetching kernel @ ${CAUSE:0:12} (shallow) from $KGIT_HTTPS"
mkdir -p "$KSRC"; git -C "$KSRC" init -q
git -C "$KSRC" remote add origin "$KGIT_HTTPS" 2>/dev/null
git -C "$KSRC" fetch -q --depth 1 origin "$CAUSE" 2>>"$WORK/clone.log" \
  || witness clone_failed "fetch $CAUSE ($(tail -1 "$WORK/clone.log" 2>/dev/null))"
git -C "$KSRC" checkout -q FETCH_HEAD 2>/dev/null || witness checkout_failed "checkout $CAUSE"
cp "$WORK/kernel.config" "$KSRC/.config"
# KASAN on, debug off (build speed), and the drivers needed to boot from the virtio rootfs disk
# + run the busybox init (devtmpfs/mdev for /dev, loop for syz_mount_image). syzbot configs
# usually have most of these, but force them so the boot never fails on a missing disk driver.
cat >> "$KSRC/.config" <<'CFG'
CONFIG_KASAN=y
CONFIG_KASAN_GENERIC=y
CONFIG_DEBUG_INFO=n
CONFIG_DEBUG_INFO_NONE=y
CONFIG_VIRTIO=y
CONFIG_VIRTIO_PCI=y
CONFIG_VIRTIO_BLK=y
CONFIG_EXT4_FS=y
CONFIG_DEVTMPFS=y
CONFIG_DEVTMPFS_MOUNT=y
CONFIG_BLK_DEV_LOOP=y
CONFIG_BLK_DEV_INITRD=y
CONFIG_BINFMT_ELF=y
CONFIG_BINFMT_SCRIPT=y
CFG

# 3. Build bzImage (host gcc 8.5 + ld 2.30 are a matched pair -> no compressed-debug issue).
log "building kernel (KASAN) with gcc $(gcc -dumpversion) — real host, $(nproc) cores"
( cd "$KSRC" && make -j"$(nproc)" olddefconfig >/dev/null 2>&1 && make -j"$(nproc)" bzImage ) \
  > "$WORK/build.log" 2>&1
BZ="$KSRC/arch/x86/boot/bzImage"
if [[ ! -f "$BZ" ]]; then
  cp "$WORK/build.log" "$OUTDIR/build.log" 2>/dev/null
  witness build_failed "bzImage not produced: $(grep -iE 'error:|Error [0-9]' "$WORK/build.log" | tail -1)"
fi
log "kernel built $(du -h "$BZ" | cut -f1)"

# 4. Compile reproducer, then build a PROPER busybox rootfs disk image (not a bare initramfs).
#    syzbot reproducers need a real environment (proc/sys/dev, loop devices via mdev, loopback
#    up, a shell) to set up their preconditions (syz_mount_image, netns, ...). build_rootfs.sh
#    makes that root-free via `mke2fs -d`. Reproducer is /repro, run by /init after env is up.
log "compiling reproducer + building rootfs disk image"
gcc -O1 -static -o "$WORK/repro" "$WORK/repro.c" -lpthread 2>"$WORK/cc.log" \
  || gcc -O1 -static -o "$WORK/repro" "$WORK/repro.c" 2>>"$WORK/cc.log" \
  || gcc -O1 -o "$WORK/repro" "$WORK/repro.c" -lpthread 2>>"$WORK/cc.log" \
  || gcc -O1 -o "$WORK/repro" "$WORK/repro.c" 2>>"$WORK/cc.log" \
  || witness repro_cc_failed "reproducer did not compile"
bash "$BASE/build_rootfs.sh" "$WORK/repro" "$WORK/rootfs.ext4" > "$WORK/rootfs.log" 2>&1 \
  || witness rootfs_failed "rootfs image build failed ($(tail -1 "$WORK/rootfs.log" 2>/dev/null))"

# 5. Boot under qemu-kvm with REAL SMP (KVM) + the rootfs as a disk (root=/dev/sda, rw).
log "booting qemu-KVM (real SMP, full rootfs) + running reproducer"
CONSOLE="$OUTDIR/console.log"
timeout "${CF_BOOT_TIMEOUT:-600}" "$QEMU" -enable-kvm -cpu host \
  -M pc -smp 4 -m 4G -no-reboot -nographic \
  -kernel "$BZ" -drive file="$WORK/rootfs.ext4",format=raw,if=virtio \
  -append "console=ttyS0 root=/dev/vda rw panic=1 kasan_multi_shot=1 init=/init" \
  > "$CONSOLE" 2>&1 || true

# 6. Witness.
if grep -qE "KASAN: (use-after-free|slab-out-of-bounds|global-out-of-bounds|out-of-bounds)" "$CONSOLE" 2>/dev/null; then
  KTYPE=$(grep -oE "KASAN: [a-z-]+" "$CONSOLE" | head -1)
  log "*** KASAN FIRED: $KTYPE -> GOLD ***"
  witness kasan_fired "$KTYPE"
else
  RAN=$(grep -c "executing program" "$CONSOLE" 2>/dev/null || echo 0)
  if grep -q "environment up" "$CONSOLE" 2>/dev/null; then
    ENV="env-up"; grep -q "REPRO_FINISHED" "$CONSOLE" 2>/dev/null && ENV="repro-finished"
    witness no_kasan "booted+rootfs ($ENV), reproducer ran ${RAN}x, no KASAN"
  else
    witness no_boot "kernel did not reach the rootfs init (see console.log)"
  fi
fi
