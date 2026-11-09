"""syzbot KASAN-report chain decomposition (plan sections 2, 3c).

syzbot's archived crash report IS a real execution witness of the sink — captured by Google's
kernel-fuzzing infrastructure. It contains the KASAN diagnosis (the sink CWE) and the ordered
call trace from the syscall entry down to the faulting operation, which the plan calls out as
the way a single reproducer's call sequence decomposes into ordered chain links (section 48).
This module parses that report into a structured, chain-labelable form WITHOUT re-running
(kernel reproduction needs qemu/KVM, unavailable on ROAR — see FINDINGS.md).

What it extracts:
- sink CWE, from the KASAN bug type + access kind (Write/Read):
    slab/stack/global-out-of-bounds Write -> CWE-787, Read -> CWE-125
    use-after-free (Write or Read)         -> CWE-416
    null-ptr-deref                          -> CWE-476
    (UBSAN integer overflow report)         -> CWE-190 (as a witnessed intermediate/source)
- the faulting site (function + file:line), the write/read size, and the ordered call trace
  (each frame's function + file:line), including the syscall entry (`__x64_sys_*` / `__se_sys_*`)
  which is the cross-scope input source.

This is pure parsing (no network); the scraper (chainforge.mining.syzbot) fetches the report.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

# KASAN access-type -> sink CWE. Order matters: check use-after-free / null before OOB.
# The tuple is (regex over the report, access-kind-sensitive?, {kind: cwe} or cwe).
_UAF_RE = re.compile(r"KASAN:\s*(slab-|global-|stack-)?use-after-free", re.IGNORECASE)
_NULL_RE = re.compile(r"KASAN:\s*null-ptr-deref|general protection fault.*0x0", re.IGNORECASE)
_OOB_RE = re.compile(r"KASAN:\s*(slab|global|stack|heap)-out-of-bounds", re.IGNORECASE)
_UBSAN_OVF_RE = re.compile(
    r"UBSAN:.*(signed-integer-overflow|unsigned-integer-overflow|"
    r"integer overflow|cannot be represented)",
    re.IGNORECASE,
)
# Access kind: "Write of size N" / "Read of size N".
_ACCESS_RE = re.compile(r"\b(Write|Read)\s+of\s+size\s+(\d+)", re.IGNORECASE)
# A call-trace frame: " func+0x.../0x... file/path.c:123" (file:line optional).
_FRAME_RE = re.compile(
    r"^\s+([A-Za-z_][\w.]*)\+0x[0-9a-f]+/0x[0-9a-f]+(?:\s+([\w./-]+\.[ch]):(\d+))?"
)
# The faulting function on the BUG: line, e.g. "in bch2_dirent_init_name+0x396/0x8b0 fs/..:273".
_BUG_SITE_RE = re.compile(
    r"BUG:\s*KASAN:[^\n]*?\bin\s+([A-Za-z_][\w.]*)(?:\+0x[0-9a-f]+/0x[0-9a-f]+)?"
    r"(?:\s+([\w./-]+\.[ch]):(\d+))?"
)
# Syscall entry frames mark the cross-scope (userspace input) boundary.
_SYSCALL_RE = re.compile(r"^(?:__x64_sys_|__se_sys_|__do_sys_|__sys_)(\w+)")

# KASAN/report instrumentation frames — the sanitizer's own machinery, not the bug's call
# chain. Stripped so the ordered links reflect the genuine code path (the fault site and its
# callers), not how KASAN prints. Prefix-matched.
_KASAN_PROLOGUE = (
    "dump_stack",
    "print_report",
    "print_address_description",
    "kasan_report",
    "__kasan_report",
    "kasan_check_range",
    "__kasan_check",
    "check_region_inline",
    "check_memory_region",
    "__asan_",
    "__hwasan_",
    "instrument_atomic",
    "instrument_",
    "__write_once_size",
    "__read_once_size",
    # generic syscall-dispatch plumbing — keep the NAMED __x64_sys_<name> (identifies the
    # syscall) but drop trampoline/dispatcher frames that carry no bug information.
    "entry_SYSCALL",
    "do_syscall_",
    "ret_from_fork",
    "kthread",
)


def _is_prologue(func: str) -> bool:
    return any(func.startswith(p) for p in _KASAN_PROLOGUE)


@dataclass
class CallFrame:
    """One frame of the KASAN call trace."""

    func: str
    file: str | None = None
    line: int | None = None

    @property
    def is_syscall_entry(self) -> bool:
        return bool(_SYSCALL_RE.match(self.func))


@dataclass
class KasanChain:
    """Structured decomposition of a syzbot KASAN report into chain evidence."""

    sink_cwe: int | None
    # Lifecycle SOURCE CWE inferred from the KASAN type (e.g. 416 for use-after-free); None
    # when the source must come from the fix diff instead (out-of-bounds / ubsan-overflow).
    source_cwe: int | None
    kasan_type: str  # 'out-of-bounds' | 'use-after-free' | 'null-ptr-deref' | 'ubsan-overflow'
    access_kind: str | None  # 'Write' | 'Read'
    access_size: int | None
    fault_func: str | None
    fault_file: str | None
    fault_line: int | None
    call_trace: list[CallFrame] = field(default_factory=list)

    @property
    def bug_path(self) -> list[CallFrame]:
        """The genuine bug call path — call_trace with KASAN instrumentation frames removed.

        Presented syscall-first (the natural cross-scope input -> fault reading order): KASAN
        prints innermost-first, so the raw trace is reversed relative to control flow.
        """
        real = [f for f in self.call_trace if not _is_prologue(f.func)]
        return list(reversed(real))

    @property
    def syscall_entry(self) -> CallFrame | None:
        """The syscall-entry frame (cross-scope input source), if the trace reaches one."""
        for f in self.call_trace:
            if f.is_syscall_entry:
                return f
        return None

    @property
    def ordered_link_summary(self) -> str:
        """Ordered links syscall -> ... -> fault site, KASAN machinery stripped."""
        names = [f.func for f in self.bug_path]
        return " -> ".join(names) if names else (self.fault_func or "")


def _access_sink(access_kind: str | None) -> int | None:
    """Memory-access sink CWE from the KASAN access kind: Write->787, Read->125."""
    if access_kind and access_kind.lower() == "write":
        return 787
    if access_kind and access_kind.lower() == "read":
        return 125
    return None


def classify_chain(kasan_type: str, access_kind: str | None) -> tuple[int | None, int | None]:
    """Map a KASAN report to (source_cwe, sink_cwe) per PREREGISTRATION PR-2.

    - use-after-free: source = CWE-416 (freed-pointer reuse), sink = access kind
      (Write->787, Read->125 as a documented convention).
    - out-of-bounds: this IS the sink (Write->787, Read->125); the source is determined
      elsewhere (patch-gated 190/20). Returned as (None, sink) so the assembler resolves
      the source from the fix diff.
    - ubsan-overflow: sink CWE-190 witnessed (source resolved from patch); (None, 190).
    - null-ptr-deref: EXCLUDED — a plain null deref does not decompose into an admissible
      source->sink chain (PR-2). Returns (None, None) -> the assembler drops it.
    """
    if kasan_type == "use-after-free":
        return 416, _access_sink(access_kind)
    if kasan_type == "out-of-bounds":
        return None, _access_sink(access_kind)
    if kasan_type == "ubsan-overflow":
        return None, 190
    # null-ptr-deref and unknown -> not a chain.
    return None, None


def parse_kasan_report(report: str) -> KasanChain:
    """Parse a syzbot CrashReport (KASAN/UBSAN text) into a KasanChain.

    Robust to the several report shapes seen in practice; returns a KasanChain with
    sink_cwe=None if no recognizable KASAN/UBSAN diagnosis is present.
    """
    # 1. KASAN/UBSAN type (order: uaf, null, ubsan-overflow, oob).
    if _UAF_RE.search(report):
        kasan_type = "use-after-free"
    elif _NULL_RE.search(report):
        kasan_type = "null-ptr-deref"
    elif _UBSAN_OVF_RE.search(report):
        kasan_type = "ubsan-overflow"
    elif _OOB_RE.search(report):
        kasan_type = "out-of-bounds"
    else:
        kasan_type = "unknown"

    # 2. access kind + size.
    access_kind = access_size = None
    am = _ACCESS_RE.search(report)
    if am:
        access_kind = am.group(1).capitalize()
        access_size = int(am.group(2))

    # 3. faulting site (from the BUG: line).
    fault_func = fault_file = None
    fault_line = None
    bm = _BUG_SITE_RE.search(report)
    if bm:
        fault_func = bm.group(1)
        fault_file = bm.group(2)
        fault_line = int(bm.group(3)) if bm.group(3) else None

    # 4. ordered call trace (frames after "Call Trace:").
    frames: list[CallFrame] = []
    in_trace = False
    for line in report.splitlines():
        if "Call Trace:" in line:
            in_trace = True
            continue
        if in_trace:
            if line.strip().startswith(
                ("RIP:", "RSP:", "RAX:", "Code:", "---[", "===")
            ) or line.strip() in ("</TASK>", ""):
                if line.strip().startswith(("RIP:", "Code:")):
                    break
                continue
            fm = _FRAME_RE.match(line)
            if fm:
                frames.append(
                    CallFrame(
                        func=fm.group(1),
                        file=fm.group(2),
                        line=int(fm.group(3)) if fm.group(3) else None,
                    )
                )

    source_cwe, sink_cwe = classify_chain(kasan_type, access_kind)
    return KasanChain(
        sink_cwe=sink_cwe,
        source_cwe=source_cwe,
        kasan_type=kasan_type,
        access_kind=access_kind,
        access_size=access_size,
        fault_func=fault_func,
        fault_file=fault_file,
        fault_line=fault_line,
        call_trace=frames,
    )
