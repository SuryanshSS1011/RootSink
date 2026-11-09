"""CWE-190 candidate triage (adviser-recommended gating).

The length-2 CWE-190 dataflow query (`sink.reachableBy(size-context-arithmetic)`) is
expensive (>15 min/case on large projects) and real 190-mediated paths are rare — the
empirical signature of a structure that isn't densely present in the corpus (the cross-scope
"guard-absence" locality ceiling that motivates the whole project). So the expensive query is
gated by a CHEAP, high-prior signal: does this case's PATCH or SANITIZER already indicate an
integer overflow was the fixed weakness? Only triage-positive cases get the costly dataflow
pass. This inverts the cost problem (pay the query only where the prior is high) and yields a
reportable real-mining denominator ("N real 190 chains from M triaged candidates, yield X%")
that earns the synthetic fallback for the rest.

Primary signal = patch-diff (direct evidence someone added an overflow guard upstream —
strongest evidence the overflow was the enabling weakness). Secondary = sanitizer/crash-type
(UBSan integer-overflow). Patch diffs live in ARVO-Meta at archive_data/patches/<localId>.diff.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

# Patch-diff patterns that signal an integer-overflow guard was ADDED (high precision).
# Matched against added ('+') lines of the diff, case-insensitively.
_PATCH_OVERFLOW_PATTERNS: tuple[str, ...] = (
    r"__builtin_[a-z]*_?overflow",  # __builtin_mul_overflow etc.
    r"\bSIZE_MAX\b",  # if (n > SIZE_MAX / size)
    r"\b(INT|UINT|LONG|SSIZE)_MAX\b",
    r"integer[ _-]?overflow",
    r"\boverflow\b.*\b(check|guard|detect)",
    r"\b(check|guard|detect)\b.*\boverflow\b",
    r"/\s*\bsize\b|\bsize\b\s*>\s*[A-Z_]+MAX",  # division-based overflow check
    r"(check|__builtin)_(mul|add|sub)_overflow",  # kernel/gcc overflow-checked arithmetic helpers
)

# Sanitizer / crash_type signals of an integer overflow (secondary).
_SANITIZER_OVERFLOW = re.compile(
    r"integer[- ]overflow|unsigned-integer-overflow|shift", re.IGNORECASE
)

# Patch-diff patterns signaling an added CWE-20 INPUT-VALIDATION guard: a bounds/length/range
# check on an (untrusted) value before it is used. Matched against ADDED ('+') lines. These are
# deliberately kernel-flavored (copy_from_user, nla_*, sizeof bounds, -EINVAL returns on a
# range check) since syzbot is the primary consumer, but generic length/bounds checks also match.
_PATCH_INPUT_VALIDATION_PATTERNS: tuple[str, ...] = (
    r"\breturn\s+-E(INVAL|OVERFLOW|MSGSIZE|2BIG|FAULT)\b",  # reject on failed validation
    r"\bif\s*\(.*\b(len|size|count|n|idx|index|offset)\b.*[<>]=?.*\)",  # bounds check on a size
    r"\b(len|size|count)\b\s*[<>]=?\s*(sizeof|ARRAY_SIZE|\w+_MAX|[0-9])",
    r"\bcopy_from_user\b|\bget_user\b|\bnla_(get|len|ok)\b",  # user-input readers (guarded)
    r"\bif\s*\(!\s*\w+\)\s*return",  # null/empty-input guard added
    r"\barray_index_nospec\b",  # speculative bounds mask (input-index validation)
    # NOTE: check_add_overflow/check_mul_overflow are OVERFLOW guards, not input-validation —
    # they live only in _PATCH_OVERFLOW_PATTERNS. Double-listing them made the length-3
    # co-signal fire on a bare overflow check (no distinct input guard), over-claiming chains.
    r"\bclamp\b|\bmin_t?\b\s*\(|\bmax_t?\b\s*\(",  # clamping an input to a valid range
)

# Patch-diff patterns signaling an added CWE-362 SYNCHRONIZATION guard: a locking/atomic/
# refcount primitive introduced to close a data race. Matched against ADDED ('+') lines. A
# fix that INTRODUCES synchronization on shared state that was previously raced is the author's
# own witness that the race (CWE-362) was the enabling weakness upstream of the UAF/null-deref
# sink — the race-arm analogue of the overflow/input-validation co-signals above.
# Real race fixes use a WIDE synchronization vocabulary (verified against kernel fixes:
# lock_sock/release_sock, task_lock, mutex_*, spin_*, rcu, refcounts) — not just mutex_lock.
# Match the generic *_lock / *_unlock / *_trylock family plus RCU, semaphores, refcounts,
# memory barriers, and the READ/WRITE/WARN_ONCE guards, so the co-signal isn't silently
# under-narrow. (A minority of race fixes add no primitive at all — a bare reorder or a
# defensive check; those legitimately do not get the SILVER patch-witness upgrade.)
_PATCH_LOCK_PATTERNS: tuple[str, ...] = (
    r"\b\w*_?(lock|unlock|trylock)(_irqsave|_irqrestore|_bh|_irq|_sock|_interruptible)?\b\s*\(",
    r"\b(release_sock|lock_sock)\b",  # socket lock (very common in net/ race fixes)
    r"\brcu_read_(lock|unlock)\b|\bsynchronize_rcu\b|\bcall_rcu\b|\brcu_dereference\b",
    r"\bdown(_read|_write|_interruptible)?\b\s*\(|\bup(_read|_write)?\b\s*\(",  # semaphores
    r"\b(atomic|refcount)_(inc|dec|add|sub|cmpxchg|read|set)(_return|_and_test)?\b",
    r"\bkref_(get|put|init)\b|\b(get|put)_(task_struct|device|page)\b",  # refcount lifecycle
    r"\b(cancel|flush)_(delayed_)?work(_sync)?\b|\bcancel_work_sync\b",  # workqueue teardown races
    r"\b(del_timer_sync|timer_shutdown_sync)\b",  # timer teardown races (UAF on free)
    r"\bWRITE_ONCE\b|\bREAD_ONCE\b|\bWARN_ON_ONCE\b|\bsmp_(mb|wmb|rmb|store_release|load_acquire)\b",
    r"\bpthread_mutex_(lock|unlock|init)\b|\bpthread_(rwlock|spin)_\w+\b",
    r"\bstd::(lock_guard|unique_lock|scoped_lock|mutex|shared_mutex|atomic)\b",  # C++ sync
)

# Patch signals for the NEW ARVO arms (source witness; the SINK is ARVO-execution-witnessed).
# Each: a fix INTRODUCING the guard whose absence was the enabling weakness. Added ('+') lines.
# CWE-129 improper array index -> a bounds/range check on an INDEX (not a size) added before use.
_PATCH_ARRAY_INDEX_PATTERNS: tuple[str, ...] = (
    r"\bif\s*\(.*\b(idx|index|i|pos|off|offset|n)\b\s*[<>]=?.*\)",  # index bounds check
    r"\b(idx|index|pos|n)\b\s*[<>]=?\s*(ARRAY_SIZE|sizeof|\w+_(MAX|COUNT|NUM|LEN)|[0-9])",
    r"\barray_index_nospec\b",  # speculative array-index mask
    r"\bif\s*\(.*\b\w+\s*>=?\s*\w*(count|size|len|num|max)\w*\b.*\)\s*return",  # reject OOB index
)
# CWE-843 type confusion -> a type/tag check or safe cast introduced before the (mis)use.
_PATCH_TYPE_CHECK_PATTERNS: tuple[str, ...] = (
    r"\b(dyn_cast|isa|is_a|typecheck|type_check|check_type)\b",
    r"\bif\s*\(.*\b(type|tag|kind|klass|class|vtable|magic)\b\s*[!=]=.*\)",  # tag/type compare
    r"\bBUG_ON\s*\(.*\btype\b.*\)|\bWARN_ON\s*\(.*\btype\b.*\)",
    r"\b->type\b\s*[!=]=|\b->tag\b\s*[!=]=",  # discriminant check on a tagged union
)
# CWE-252 unchecked return value -> a check on a previously-ignored call result added.
_PATCH_RETURN_CHECK_PATTERNS: tuple[str, ...] = (
    r"\bif\s*\(\s*!\s*\w+\s*\)\s*(return|goto|break)",  # if (!ret) return  (null/false result)
    r"\b\w+\s*=\s*\w+\([^)]*\)\s*;\s*\n?\s*if\s*\(",  # assign result then check it
    r"\bif\s*\(\s*\w+\s*(==|!=|<)\s*(NULL|0|-1)\s*\)",  # explicit result compare added
    r"\bIS_ERR(_OR_NULL)?\s*\(|\bPTR_ERR\s*\(",  # kernel error-pointer check on a return
)

_ADDED_LINE = re.compile(r"^\+(?!\+)", re.MULTILINE)  # diff '+' lines, not '+++' headers


@dataclass
class TriageResult:
    """Whether a case is a CWE-190 candidate, and why."""

    local_id: int
    patch_signal: bool
    sanitizer_signal: bool
    matched_patterns: tuple[str, ...] = ()

    @property
    def is_candidate(self) -> bool:
        """A 190 candidate if EITHER the patch or the sanitizer signals an overflow."""
        return self.patch_signal or self.sanitizer_signal

    @property
    def confidence(self) -> str:
        """'high' if patch-backed (direct guard-added evidence), 'low' if sanitizer-only."""
        if self.patch_signal:
            return "high"
        return "low" if self.sanitizer_signal else "none"


def patch_signals_overflow(diff_text: str) -> tuple[bool, tuple[str, ...]]:
    """True if the patch's ADDED lines add an integer-overflow guard, with matched patterns.

    Only added ('+') lines are considered — the guard being INTRODUCED is the signal, not
    overflow-related code that was already present or removed.
    """
    added = "\n".join(m_line for m_line in _added_lines(diff_text))
    matched: list[str] = []
    for pat in _PATCH_OVERFLOW_PATTERNS:
        if re.search(pat, added, re.IGNORECASE):
            matched.append(pat)
    return bool(matched), tuple(matched)


def patch_signals_input_validation(diff_text: str) -> tuple[bool, tuple[str, ...]]:
    """True if the patch's ADDED lines add a CWE-20 input-validation guard.

    Signals a bounds/length/range/null check being INTRODUCED on an (untrusted) value —
    the cleanest real-world evidence that improper input validation was the enabling weakness.
    Added ('+') lines only.
    """
    added = "\n".join(_added_lines(diff_text))
    matched: list[str] = []
    for pat in _PATCH_INPUT_VALIDATION_PATTERNS:
        if re.search(pat, added, re.IGNORECASE):
            matched.append(pat)
    return bool(matched), tuple(matched)


def patch_signals_race(diff_text: str) -> tuple[bool, tuple[str, ...]]:
    """True if the patch's ADDED lines introduce a CWE-362 synchronization guard.

    Signals a locking/atomic/refcount primitive being INTRODUCED to close a data race —
    author-witnessed evidence that a race (CWE-362) was the enabling weakness upstream of a
    UAF (416) or null-deref (476) sink. Upgrades an NVD race-arm co-occurrence seed from
    BRONZE (co-occurrence only) to SILVER (patch-witnessed). Added ('+') lines only.
    """
    added = "\n".join(_added_lines(diff_text))
    matched: list[str] = []
    for pat in _PATCH_LOCK_PATTERNS:
        if re.search(pat, added, re.IGNORECASE):
            matched.append(pat)
    return bool(matched), tuple(matched)


def _added_lines(diff_text: str) -> list[str]:
    out = []
    for line in diff_text.splitlines():
        if line.startswith("+") and not line.startswith("+++"):
            out.append(line[1:])
    return out


def _match_added(diff_text: str, patterns: tuple[str, ...]) -> tuple[bool, tuple[str, ...]]:
    """Shared helper: which of `patterns` appear in the diff's ADDED lines."""
    added = "\n".join(_added_lines(diff_text))
    matched = [p for p in patterns if re.search(p, added, re.IGNORECASE)]
    return bool(matched), tuple(matched)


def patch_signals_array_index(diff_text: str) -> tuple[bool, tuple[str, ...]]:
    """True if the fix adds a CWE-129 array-INDEX bounds/range guard (source of 129->119)."""
    return _match_added(diff_text, _PATCH_ARRAY_INDEX_PATTERNS)


def patch_signals_type_check(diff_text: str) -> tuple[bool, tuple[str, ...]]:
    """True if the fix adds a CWE-843 type/tag check or safe cast (source of 843->119)."""
    return _match_added(diff_text, _PATCH_TYPE_CHECK_PATTERNS)


def patch_signals_return_check(diff_text: str) -> tuple[bool, tuple[str, ...]]:
    """True if the fix adds a CWE-252 check on a previously-unchecked return (252->476 source)."""
    return _match_added(diff_text, _PATCH_RETURN_CHECK_PATTERNS)


# CWE-20->CWE-190->sink LENGTH-3 patch co-signal (Strategy C for real length-3 mining).
# A single fix that INTRODUCES BOTH an input-validation guard AND an integer-overflow guard is
# strong ground-truth evidence that the author recognized a 20->190 chain: untrusted input was
# insufficiently checked, flowed into arithmetic that could wrap, and the fix hardened both. The
# sink (787/125/119) is inferred from the memory op the guarded arithmetic feeds (memcpy/alloc/
# index). This is a PATCH-witnessed length-3 signal, complementary to static dataflow (which gave
# a rigorous negative) — the author's own fix is the witness that the ordered chain was real.
_SINK_HINT_PATTERNS = {
    787: r"\b(memcpy|memmove|strcpy|strcat|sprintf|memset)\b",
    125: r"\b(memcmp|strncmp|read|memchr)\b",
    119: r"\b(malloc|calloc|realloc|kmalloc|kzalloc|vmalloc|alloca)\b",
}


def patch_signals_length3(diff_text: str) -> dict:
    """Detect a CWE-20->CWE-190->sink length-3 chain from a fix diff (Strategy C).

    Returns {"is_len3": bool, "sink_cwe": int|None, "input_patterns", "overflow_patterns"}.
    is_len3 requires the patch to add BOTH an input-validation guard AND an overflow guard; the
    sink is inferred from which memory-op family the added guards sit near.
    """
    ovf_ok, ovf_pats = patch_signals_overflow(diff_text)
    inp_ok, inp_pats = patch_signals_input_validation(diff_text)
    is_len3 = ovf_ok and inp_ok
    sink_cwe = None
    if is_len3:
        added = "\n".join(_added_lines(diff_text))
        # prefer the most specific sink present; write > read > generic-alloc-bounds
        for cwe in (787, 125, 119):
            if re.search(_SINK_HINT_PATTERNS[cwe], added, re.IGNORECASE):
                sink_cwe = cwe
                break
        if sink_cwe is None:
            sink_cwe = 119  # an overflow-guarded allocation size defaults to buffer-bounds
    return {
        "is_len3": is_len3,
        "sink_cwe": sink_cwe,
        "input_patterns": inp_pats,
        "overflow_patterns": ovf_pats,
    }


def sanitizer_signals_overflow(crash_type: str | None, sanitizer: str | None) -> bool:
    """True if the crash_type or sanitizer indicates an integer overflow."""
    text = f"{crash_type or ''} {sanitizer or ''}"
    return bool(_SANITIZER_OVERFLOW.search(text))


def triage_case(
    local_id: int,
    diff_text: str | None = None,
    crash_type: str | None = None,
    sanitizer: str | None = None,
) -> TriageResult:
    """Triage one case as a CWE-190 candidate from its patch diff + sanitizer metadata."""
    patch_ok, matched = (False, ())
    if diff_text:
        patch_ok, matched = patch_signals_overflow(diff_text)
    san_ok = sanitizer_signals_overflow(crash_type, sanitizer)
    return TriageResult(
        local_id=local_id,
        patch_signal=patch_ok,
        sanitizer_signal=san_ok,
        matched_patterns=matched,
    )
