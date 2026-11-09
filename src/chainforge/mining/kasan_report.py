"""Parse a syzbot/KASAN report into an ORDERED, LOCALIZED causal chain.

A KASAN use-after-free report is natively a three-stage causal chain, and syzbot publishes
it already symbolized, so each stage carries file:line:

    Allocated by task 96:   <stack>   -> where the object came from
    Freed by task 96:       <stack>   -> the state change that makes the use invalid
    BUG: KASAN: ... in f()  <stack>   -> the sink that actually faults

That is exactly the per-link supervision causality-aware RL needs, and it is available
WITHOUT rebuilding the kernel with debug info (which fails linking tools/objtool anyway).

The frame chosen for a stage is the first one in KERNEL SOURCE, skipping the instrumentation
and reporting machinery (mm/kasan/*, lib/dump_stack.c, include/linux/instrumented.h, the
atomic wrappers) that appears at the top of every stack and localizes nothing.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

# Frames that appear in every report and describe the REPORTER, the ALLOCATOR, or generic
# locking/instrumentation wrappers - never the bug. Without filtering these, alloc/free
# localize to include/linux/kasan.h or slab.h, which is useless as RL supervision: the
# informative frame is the subsystem caller (e.g. drivers/hid/hid-steam.c), not the hook.
_NOISE = re.compile(
    r"^("
    r"mm/kasan/|mm/slub\.c|mm/slab\w*\.c|mm/page_alloc\.c|mm/kmsan/|mm/util\.c|"
    r"lib/dump_stack\.c|lib/stackdepot\.c|kernel/stacktrace\.c|kernel/kcov\.c|"
    r"kernel/locking/|kernel/sched/core\.c|"
    r"include/linux/kasan\.h|include/linux/slab\.h|include/linux/instrumented\.h|"
    r"include/linux/spinlock|include/linux/atomic|include/linux/rcu|"
    r"include/asm-generic/atomic|arch/\w+/include/asm/atomic|arch/\w+/include/asm/spinlock"
    r")",
)
_LOC = re.compile(r"([a-zA-Z0-9_][a-zA-Z0-9_/.\-]*\.[ch]):(\d+)")
_FRAME = re.compile(r"^\s*(?:\[[^\]]*\]\s*)?([A-Za-z_][A-Za-z0-9_.]*)\+0x[0-9a-f]+")
_BUG = re.compile(r"BUG: KASAN: ([a-z\-]+) in ([A-Za-z_][A-Za-z0-9_.]*)")
_ACCESS = re.compile(r"(Read|Write) of size (\d+)")

_STAGE_HEADERS = (
    ("allocated", re.compile(r"^Allocated by task \d+:")),
    ("freed", re.compile(r"^Freed by task \d+:")),
)


@dataclass
class Stage:
    """One causal stage with its localization."""

    kind: str  # allocated | freed | use
    function: str | None = None
    file: str | None = None
    line: int | None = None
    frames: list[str] = field(default_factory=list)

    def located(self) -> bool:
        return bool(self.file and self.line)


@dataclass
class KasanChain:
    bug_class: str | None = None
    direction: str | None = None  # READ | WRITE
    access_size: int | None = None
    stages: list[Stage] = field(default_factory=list)

    @property
    def localized_stages(self) -> list[Stage]:
        return [s for s in self.stages if s.located()]

    def is_ordered_chain(self) -> bool:
        """True when alloc -> free -> use are all present and localized."""
        kinds = {s.kind for s in self.localized_stages}
        return {"allocated", "freed", "use"}.issubset(kinds)


def _first_source_frame(block: list[str]) -> tuple[str | None, str | None, int | None, list[str]]:
    """Pick the first frame that is real kernel source, not reporting machinery."""
    frames: list[str] = []
    best: tuple[str | None, str | None, int | None] = (None, None, None)
    for raw in block:
        fn = _FRAME.search(raw)
        loc = _LOC.search(raw)
        if fn:
            frames.append(fn.group(1))
        if loc and best[1] is None and not _NOISE.match(loc.group(1)):
            best = (fn.group(1) if fn else None, loc.group(1), int(loc.group(2)))
    return best[0], best[1], best[2], frames


def parse_kasan_report(text: str) -> KasanChain:
    """Extract the ordered alloc/free/use chain from a KASAN report."""
    lines = text.splitlines()
    chain = KasanChain()

    m = _BUG.search(text)
    if m:
        chain.bug_class = m.group(1).lower()
    a = _ACCESS.search(text)
    if a:
        chain.direction = a.group(1).upper()
        chain.access_size = int(a.group(2))

    # The USE stage is the block after the BUG line (its "Call Trace:").
    for i, ln in enumerate(lines):
        if _BUG.search(ln):
            block = []
            for nxt in lines[i : i + 60]:
                if re.match(r"^(Allocated by task|Freed by task|The buggy address)", nxt.strip()):
                    break
                block.append(nxt)
            fn, src, ln_no, frames = _first_source_frame(block)
            chain.stages.append(Stage("use", fn or (m.group(2) if m else None), src, ln_no, frames))
            break

    # Alloc/free blocks run until a blank line or the next section header.
    for kind, header in _STAGE_HEADERS:
        for i, ln in enumerate(lines):
            if header.match(ln.strip()):
                block = []
                for nxt in lines[i + 1 : i + 40]:
                    s = nxt.strip()
                    if not s or re.match(
                        r"^(Allocated by task|Freed by task|The buggy address|BUG:)", s
                    ):
                        break
                    block.append(nxt)
                fn, src, ln_no, frames = _first_source_frame(block)
                chain.stages.append(Stage(kind, fn, src, ln_no, frames))
                break

    # Causal order: allocated -> freed -> use.
    order = {"allocated": 0, "freed": 1, "use": 2}
    chain.stages.sort(key=lambda s: order.get(s.kind, 9))
    return chain
