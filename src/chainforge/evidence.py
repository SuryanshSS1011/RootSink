"""Classify what actually backs each chain link, as structure rather than prose.

SPECIFICATION R3 says a chain is only as strong as its weakest link and that this must be
VISIBLE. Until now it was visible only to a human: the evidence kind had to be recovered by
regex over free text in `patch_hunk_ref`, which left 752 links unclassifiable and 620 with
nothing to read at all. A consumer selecting training records - "every link at least
execution-witnessed" - could not express that query.

The ordering is the one R3 fixes, strongest first. It is deliberately ordinal and NOT a
weighted score: each kind is a distinct verifiable claim, and collapsing them into one number
would hide exactly the weak link R3 exists to surface.
"""

from __future__ import annotations

import re
from enum import StrEnum

# Prose written by earlier pipeline stages, kept as a fallback for links whose evidence
# predates the structured fields.
_ATTESTED = re.compile(
    r"attested by the patch|adds an? (integer-overflow )?guard|origin block|patch co-signal",
    re.I,
)
_UNATTESTED = re.compile(r"NOT attested", re.I)
_INFERRED = re.compile(
    r"crash-class-implied|from the NVD CWE assignment|modelling approximation|no guard signal",
    re.I,
)


class EvidenceKind(StrEnum):
    """What a single link is backed by. Ordered strongest to weakest (see ORDER)."""

    CAUSALLY_PROVEN = "causally-proven"  # guard ablation: only this hunk, crash stops
    EXECUTION = "execution"  # a sanitizer report attributes the link to a site
    ATTESTED = "attested"  # the fix demonstrably adds the missing guard
    DATAFLOW = "dataflow"  # a static path supports the ordering, nothing ran
    INFERRED = "inferred"  # crash class or CWE assignment, nothing observed
    NONE = "none"  # no evidence recorded at all


ORDER = [
    EvidenceKind.CAUSALLY_PROVEN,
    EvidenceKind.EXECUTION,
    EvidenceKind.ATTESTED,
    EvidenceKind.DATAFLOW,
    EvidenceKind.INFERRED,
    EvidenceKind.NONE,
]
_RANK = {k: i for i, k in enumerate(ORDER)}


# A unified-diff hunk header. Patch evidence must contain at least one: a bare reference -
# an https URL, a `git://` remote, a `fix:<sha>` string - names where a fix lives without
# carrying the guard it added, so it cannot support the counterfactual GOLD asserts. Checking
# only for an "http" prefix let 176 GOLD records through on `git://` and `fix:` strings.
_HUNK_HDR = re.compile(r"^@@ -\d+(?:,\d+)? \+\d+(?:,\d+)? @@", re.M)


def patch_is_content(patch_diff: str | None) -> bool:
    """True if this is an actual patch rather than a pointer to one."""
    return bool(_HUNK_HDR.search(patch_diff or ""))


# Paths whose changes cannot be the guard for a memory-safety sink, however real the diff is:
# tests, docs, examples, and the fuzz harness in any of its layouts. One rule, shared with the
# ablation's hunk splitter, because the two disagreeing is how three oniguruma proofs on
# `harnesses/base.c` passed both: the splitter knew `harness/`, the checker knew neither.
_NON_GUARD_PATH = re.compile(
    r"(^|/)(\w+[_-])?(test|tests|testing|fuzz|fuzzing|fuzzer|fuzzers|fuzztest|harness|harnesses"
    r"|corpus|oss-fuzz|docs?|Documentation|examples?)/"
    r"|(^|/)[^/]*fuzz[^/]*\.(c|cc|cpp|cxx|h|hpp)$",
    re.I,
)


def is_non_guard_path(path: str) -> bool:
    """True if a change to this file cannot be the guard a source link is credited with."""
    return bool(_NON_GUARD_PATH.search(path or ""))


_HARNESS_DIR = re.compile(
    r"(^|/)(\w+[_-])?(test|tests|testing|fuzz|fuzzing|fuzzer|fuzzers|fuzztest|harness|harnesses"
    r"|corpus|oss-fuzz)/(.*)$",
    re.I,
)


def harness_site(path: str) -> bool:
    """I2-site (2026-10-21): a witnessed site in harness, test or libFuzzer code, after build-tree
    hops are resolved. Library source vendored under a harness-looking directory (a `src/` tree
    follows it and the file name has no `fuzz`) is not harness code."""
    p = normalize_path(path or "")
    if not p or not is_non_guard_path(p):
        return False
    m = _HARNESS_DIR.search(p)
    vendored = (
        bool(m) and "/src/" in "/" + m.group(4) and "fuzz" not in p.rsplit("/", 1)[-1].lower()
    )
    return not vendored


_SOURCE_EXT = re.compile(r"\.(c|cc|cpp|cxx|h|hpp|inc|S)$", re.I)
_FILE_HDR = re.compile(r"^diff --git a/\S+ b/(\S+)", re.M)
_COMMIT_HDR = re.compile(r"^From ([0-9a-f]{40})", re.M)


def guard_evidence_defect(patch_diff: str | None, fixed_sha: str = "") -> str | None:
    """Why this diff cannot back a guard claim, or None if it can.

    `patch_is_content` asks only whether the field holds a patch rather than a pointer to one.
    That is necessary and not sufficient: a diff can be real, well-formed, and still be unable
    to support the counterfactual GOLD asserts - curl's resolved fix for a use-after-free
    touches only `Makefile.am`, skia's touches only its fuzz harness. Checking content alone
    moved the original defect down one level rather than closing it.
    """
    d = patch_diff or ""
    if not patch_is_content(d):
        return "not a patch"
    if len(d) > 1000 and not d.endswith("\n"):
        return "truncated mid-line"
    m = _COMMIT_HDR.search(d)
    if fixed_sha and m and m.group(1) != fixed_sha:
        return f"sha mismatch (diff is {m.group(1)[:12]}, record names {fixed_sha[:12]})"
    files = _FILE_HDR.findall(d)
    if not files:
        return "no file headers"
    if not any(_SOURCE_EXT.search(f) and not is_non_guard_path(f) for f in files):
        return "touches no non-test source file"
    return None


def causal_proof_defect(evidence: dict | None) -> str | None:
    """Why this link's guard-ablation proof does not establish a SOURCE guard, or None.

    The ablation shows that applying one hunk alone silences the sanitizer. That is a causal
    claim about the hunk, not about the library: when the hunk lives in the fuzz harness, what
    it demonstrates is that the harness stopped feeding the triggering input - lwan's guard is
    `size = min(sizeof(copy) - 1, size)` in `template_fuzzer.cc`. The crash stops and nothing
    is fixed, so the record cannot claim a causally-proven source.
    """
    cp = (evidence or {}).get("causal_proof") or {}
    if not cp:
        return None
    if is_non_guard_path(cp.get("file") or ""):
        return "guard hunk is in a fuzz harness or test file"
    return None


# PR-4: what a proven guard checks decides the source CWE. Matched on the hunk's ADDED lines with
# comments stripped (a "// avoid overflow" comment is not an overflow check), tried in precedence
# order; the first class that matches decides, and an inadmissible one credits nothing. Patterns
# favour precision: an unmatched guard is "undetermined" and credits no CWE, the safe failure.
_COMMENT = re.compile(r"//.*$|/\*.*?\*/", re.M)
_FREEISH = re.compile(r"\b(?:\w*free|delete|release|destroy|close)\w*\s*\(|\bdelete\b", re.I)
_GUARD_CLASSES = [
    (
        190,
        re.compile(
            r"\b(?:SIZE|INT|UINT|LONG|ULONG|SSIZE|INT\d+|UINT\d+|U?INT_LEAST\d+)_MAX\b"
            r"|__builtin_\w+_overflow|\bcheck_\w+_overflow\b|\bnumeric_limits\b"
        ),
    ),
    (476, re.compile(r"(?:==|!=)\s*(?:NULL|nullptr)\b|\b(?:NULL|nullptr)\s*(?:==|!=)")),
    (
        416,
        re.compile(
            r"\b(?:\w+_)?(?:incref|decref|unref|kref_get|kref_put|refcount_\w+|get_ref|put_ref)\s*\("
            r"|\b\w+->ref(?:count|cnt)\b",
            re.I,
        ),
    ),
    (456, re.compile(r"\bmemset\s*\(|=\s*\{\s*0?\s*\}|\bcalloc\s*\(")),
    (129, re.compile(r"\b\w*(?:idx|index)\w*\s*(?:>=|>)|(?:<|<=)\s*\w*(?:idx|index)\w*\b", re.I)),
    # PR-4's last row: "any other rejection or clamp of input (bounds, length, early
    # return/error)" - a test in an if, a relational comparison anywhere (a loop bound, a check
    # macro, a continued condition), a clamp, or a bare error exit. `->`, shifts and C++ template
    # brackets are not comparisons.
    (
        20,
        re.compile(
            r"\bif\s*\(.*(?:!=|==).*\)"
            r"|(?<![-<>])(?<!_cast)(?:<=|>=|<(?![<=])|(?<!-)>(?![>=]))(?![<>])"
            r"|\bMIN\s*\(|\bstd::min\b|\bassert\w*\s*\(|\b\w*(?:Verify|Check|Ensure|Require)\w*\s*\("
            r"|^\s*(?:return\b[^;]*|goto\s+\w+|continue|break)\s*;",
            re.I | re.M,
        ),
    ),
]


# C++ template argument lists (`static_cast<uint32_t>`, `std::vector<int>`) are not comparisons.
_TEMPLATE = re.compile(
    r"\b(?:\w+_cast|std::\w+|vector|array|map|set|unique_ptr|shared_ptr|numeric_limits)"
    r"\s*<[^<>;()]*>"
)


def _same_line(text: str) -> str:
    """A line with whitespace and enclosing braces removed: re-indenting or re-bracing a line
    does not change it."""
    return re.sub(r"\s+", "", text).strip("{}")


def _added(hunk: str) -> str:
    """The lines a diff adds. A `+` line that only re-indents or re-braces a `-` line of the same
    diff adds nothing and is left out (PR-4 amendment, 2026-10-29): a check the fix merely moves
    was already there."""
    lines = hunk.splitlines()
    removed = {
        _same_line(ln[1:]) for ln in lines if ln.startswith("-") and not ln.startswith("---")
    }
    removed.discard("")
    added = "\n".join(
        ln[1:]
        for ln in lines
        if ln.startswith("+") and not ln.startswith("+++") and _same_line(ln[1:]) not in removed
    )
    return _TEMPLATE.sub("T", _COMMENT.sub("", added))


def guard_classes(hunk: str) -> list[int]:
    """Every PR-4 class a guard hunk matches, in precedence order."""
    added = _added(hunk)
    out = [cwe for cwe, rx in _GUARD_CLASSES if rx.search(added)]
    # Lifetime fix by clearing a pointer: only when the hunk also frees/releases something.
    if 416 not in out and re.search(r"=\s*(?:NULL|nullptr)\s*;", added) and _FREEISH.search(hunk):
        out.insert(min(2, len(out)), 416)
    return out


_NULL_TEST = re.compile(
    r"(?:\bif|\bwhile|&&|\|\||\?)\s*\(?\s*!\s*([A-Za-z_][\w.>-]*)\s*\)"
    r"|([A-Za-z_][\w.>-]*)\s*(?:==|!=)\s*(?:NULL|nullptr|0)\b"
    r"|\b(?:NULL|nullptr)\s*(?:==|!=)\s*([A-Za-z_][\w.>-]*)"
)


def unchecked_call_result(hunk: str) -> bool:
    """True if the hunk adds a NULL test of a value assigned from a function call in the hunk
    (its context, removed or added lines): the check the call's result was missing."""
    tested = {v for m in _NULL_TEST.finditer(_added(hunk)) for v in m.groups() if v}
    body = "\n".join(
        ln[1:] for ln in hunk.splitlines() if ln[:1] in " +-" and ln[:3] not in ("+++", "---")
    )
    return any(
        re.search(
            rf"(?<![\w.>-]){re.escape(v)}\s*=\s*(?:\([^()]*\)\s*)?[A-Za-z_][\w:.>-]*\s*\(", body
        )
        for v in tested
    )


# PR-17: what a CWE-20 check bounds, by the names of the operands it compares, clamps or rejects.
# A comparison is not `->`, a shift or a template bracket (as in the PR-4 CWE-20 class).
_CHECK_LINE = re.compile(
    r"(?<![-<>])(?:<=|>=|<(?![<=])|(?<!-)>(?![>=]))(?![<>])|[!=]="
    r"|\bMIN\s*\(|\bstd::min\b|\bmin\s*\(|\breturn\b|\bgoto\b",
    re.I,
)
_INDEX_WORDS = frozenset(
    ["idx", "index", "offset", "off", "pos", "position", "cursor", "ptr", "cur", "start", "end"]
)
_QUANTITY_WORDS = frozenset(
    [
        "len",
        "length",
        "size",
        "sz",
        "count",
        "cnt",
        "num",
        "nb",
        "total",
        "remaining",
        "avail",
        "capacity",
        "width",
        "height",
        "bytes",
        "sizeof",
    ]
)


def _words(text: str) -> set[str]:
    """Identifier pieces, split at `_` and camelCase, lower-cased (`bufLen` -> buf, len)."""
    out = set()
    for ident in re.findall(r"[A-Za-z_][A-Za-z0-9_]*", text):
        for part in re.split(r"_+|(?<=[a-z0-9])(?=[A-Z])", ident):
            if part:
                out.add(part.lower())
    return out


def input_validation_child(diff_or_hunk: str) -> int | None:
    """PR-17: the MITRE-allowed child of CWE-20 that an added check validates, or None.

    CWE-1285 when a checked operand names an index, offset or position; otherwise CWE-1284 when
    one names a quantity; otherwise None (the root stays CWE-20, class-level). Only added lines
    that compare, clamp or reject are read, with comments stripped.
    """
    lines = [ln for ln in _added(diff_or_hunk).splitlines() if _CHECK_LINE.search(ln)]
    words = _words("\n".join(lines))
    if words & _INDEX_WORDS:
        return 1285
    if words & _QUANTITY_WORDS:
        return 1284
    return None


def source_for_guard(hunk: str, sink: int, admissible) -> int | None:
    """PR-4 source CWE for this sink, or None (a proven site, no CWE credited).

    The FIRST matching class decides; if it is not admissible with the sink, nothing is credited
    rather than falling through to a weaker class. An index check means CWE-129 only toward a
    CWE-119 sink; toward any other sink it is input validation, CWE-20.
    """
    # PR-16: toward a NULL-dereference sink, a guard that tests for NULL a value the code took
    # from a function call is the missing check of that call's result, CWE-252. Any other guard
    # toward CWE-476 falls through to the classes below, none of which is admissible with it.
    if sink == 476 and unchecked_call_result(hunk):
        return 252 if admissible(252, sink) else None
    classes = guard_classes(hunk)
    if not classes:
        return None
    cwe = 20 if classes[0] == 129 and sink != 119 else classes[0]
    return cwe if admissible(cwe, sink) else None


_HUNK_POS = re.compile(r"^@@ -(\d+)(?:,\d+)? \+\d+(?:,\d+)? @@ ?(.*)$", re.M)


# Statement keywords git's hunk-header heuristic can report in place of a function name.
C_KEYWORDS = frozenset({"if", "else", "for", "while", "do", "switch", "case", "return", "sizeof"})


def guard_site(hunk: str, file: str) -> dict | None:
    """Where a proven guard is missing: the vulnerable-revision line its first added line goes
    before, and the enclosing function git names in the hunk header (if any)."""
    m = _HUNK_POS.search(hunk)
    if not m:
        return None
    line = int(m.group(1))
    for ln in hunk[m.end() :].split("\n")[1:]:  # the body, after the header line
        if ln.startswith("+"):
            break
        if ln.startswith((" ", "-")):
            line += 1
    fn = re.search(r"(\w+)\s*\(", m.group(2) or "")
    # git's hunk-header context is the nearest line that looks like a definition; in some
    # styles that is a statement (`if (`), which names no function.
    name = fn.group(1) if fn and fn.group(1) not in C_KEYWORDS else None
    return {
        "file": file,
        "line": line,
        "function": name,
        "stage": "missing guard (vulnerable revision, from the proven hunk)",
    }


def normalize_path(path: str) -> str:
    """A source path comparable across witnesses: build-tree hops resolved and the container's
    absolute `/src/<project>/` root dropped (`/src/skia/out/Fuzz/../../src/codec/X.cpp` ->
    `src/codec/X.cpp`). Relative paths are only normalised; `same_file` matches by suffix."""
    import posixpath

    p = posixpath.normpath(path or "")
    if p.startswith("/src/") and p.count("/") >= 3:
        return p.split("/", 3)[3]
    return p.lstrip("/") if p != "." else ""


def same_file(a: str, b: str) -> bool:
    """Two witnessed paths name one file if one normalised path is a suffix of the other."""
    x, y = normalize_path(a), normalize_path(b)
    if not x or not y:
        return False
    return x == y or x.endswith("/" + y) or y.endswith("/" + x)


def bare_function(name: str | None) -> str | None:
    """`SkSwizzler::swizzle(void*, int)` -> `swizzle`; `foo.part.0` -> `foo`."""
    if not name:
        return None
    name = name.replace("(anonymous namespace)::", "")
    n = name.split("(", 1)[0].strip().split("::")[-1].split(" ")[-1]
    return re.sub(r"\.(part|isra|constprop|cold)\.\d+$|\.cold$", "", n) or None


def locality(rec: dict) -> str | None:
    """Where the root cause sits relative to the sink, from their witnessed locations:
    "in-function", "cross-function" (same file), "same-file" (a function is unknown), or
    "cross-file"; None if either end is unlocated."""
    chain = rec.get("chain") or []
    if len(chain) < 2:
        return None
    a, b = ((c.get("evidence") or {}).get("location") or {} for c in (chain[0], chain[-1]))
    if not (a.get("file") and b.get("file")):
        return None
    if not same_file(a["file"], b["file"]):
        return "cross-file"
    fa, fb = bare_function(a.get("function")), bare_function(b.get("function"))
    if not (fa and fb):
        return "same-file"
    return "in-function" if fa == fb else "cross-function"


# Pairs whose two CWEs both classify the SAME faulting operation, the one the sanitizer reports:
# one defect described twice, not two weaknesses (PR-5, general rule of 2026-10-20).
#   416 -> 125|787  the access to freed memory is both the use-after-free and the bad access;
#   843 -> 119      the incompatibly typed access is both the type confusion and the bounds error.
# A pair is two weaknesses when the first CWE is defined by a DIFFERENT, earlier operation that
# enables the second: a missing check (20, 129, 252), a computation (190), a missing
# initialisation (456), a race (362). The recorded sites do not decide it: a 416 instance placed
# at the free still names the use.
STAGE_PAIRS = frozenset({(416, 125), (416, 787), (843, 119)})


def chain_kind(cwes: list[int]) -> str:
    """PR-5: "multi-weakness" if the chain holds >= 2 distinct weaknesses, else
    "stage-decomposition". Each consecutive pair in STAGE_PAIRS is one weakness, so it counts
    once."""
    pairs = zip(cwes, cwes[1:], strict=False)
    distinct = len(cwes) - sum((a, b) in STAGE_PAIRS for a, b in pairs)
    return "multi-weakness" if distinct >= 2 else "stage-decomposition"


# How an instance's CWE was assigned. Every CWE in the release comes from a rule; this names the
# strongest input that rule had. Evidence kinds say what was OBSERVED about the instance; this
# says where its LABEL came from. An intervention, in particular, tests the site; the CWE is then
# read from the tested hunk's added lines by the PR-4 guard classifier and is not itself tested.
CWE_BASES = (
    "guard-class",  # PR-4 classifier over the hunk an intervention showed sufficient
    "msan-origin",  # MSan origin tracking: the creating site is labelled CWE-456
    "sanitizer-class",  # the class and access of a sanitizer or KASAN report
    "fix-pattern",  # a pattern over the developer fix's added lines, untested
    "crash-class-implied",  # implied by the sink's crash class (e.g. Bad-cast -> 843)
    "dataflow-rank",  # Joern path from the catalogue's sources, most specific first, CWE-20 last
    "advisory",  # an NVD CWE assignment
    "catalogue-default",  # the catalogue's admissible source for the sink, nothing else
)


def cwe_basis(link: dict, provenance: str = "") -> str:
    """The strongest input the rule that assigned this instance's CWE had (see CWE_BASES)."""
    ev = link.get("evidence") or {}
    ref = ev.get("patch_hunk_ref") or ""
    role = link.get("role")
    if ev.get("causal_proof"):
        return "guard-class"
    if ref.startswith("MSan origin") or (
        link.get("cwe_id") == 456
        and role == "source"
        and ev.get("sanitizer_report_ref")
        and (ev.get("location") or {}).get("file")
    ):
        # The MSan arm labels CWE-456 at the origin block's site whatever its patch note says.
        return "msan-origin"
    if "NVD" in ref or (role == "sink" and provenance.startswith("nvd")):
        return "advisory"
    if role in ("sink", "intermediate") and ev.get("sanitizer_report_ref"):
        return "sanitizer-class"
    if ref.startswith("KASAN witnesses"):
        return "sanitizer-class"
    if role == "sink":
        # ARVO/syzbot sinks without an attributed report: the archived crash's class.
        return "sanitizer-class" if provenance and not provenance.startswith("nvd") else "advisory"
    if ref.startswith("crash-class-implied"):
        return "crash-class-implied"
    if _ATTESTED.search(ref) or re.match(r"(fix|patch) (adds|introduces)", ref):
        return "fix-pattern"
    if ev.get("dataflow_path"):
        return "dataflow-rank"
    return "catalogue-default"


SITE_KINDS = (
    "tested-repair-site",
    "origin-site",
    "crash-site",
    "witnessed-site",
    "annotated-site",
)


def site_kind(link: dict, provenance: str = "") -> str | None:
    """What an instance's recorded site is, independent of how its CWE was named.

    tested-repair-site  where a single-hunk test applied a hunk that alone stopped the crash
                        (with or without a CWE from the guard rule): a sufficient repair site
    origin-site         a site a sanitizer reported as the origin of the bad state: MSan's
                        "created by" block for CWE-456, or the free stack of a CWE-416
    crash-site          the sink's site, the top project frame of a crash report
    witnessed-site      an intermediate a sanitizer report places (UBSan, KASAN)
    annotated-site      a site from a static path, a fix pattern or a labeling rule, which no
                        run or test placed there
    None                no site recorded
    """
    ev = link.get("evidence") or {}
    loc = ev.get("location") or {}
    if not (loc.get("file") or loc.get("function")):
        return None
    stage = (loc.get("stage") or "").lower()
    role = link.get("role")
    if (ev.get("causal_proof") or ev.get("guard_site_proof")) and "guard" in stage:
        return "tested-repair-site"
    # An origin is where the bad state the sink trips on comes into being: the uninitialised
    # value's creation for CWE-456, the free that leaves the pointer dangling for CWE-416. A
    # KASAN allocation or free stack under any other CWE is an object's history, not its cause.
    # A CWE-456 root keeps MSan's origin as its site even when an intervention named the CWE
    # (the guard rule's basis then outranks the origin's), so the site is tested on the report.
    msan_origin = (
        link.get("cwe_id") == 456 and ev.get("sanitizer_report_ref") and not ev.get("reported_site")
    )
    if role == "source" and (
        cwe_basis(link, provenance) == "msan-origin"
        or msan_origin
        or (link.get("cwe_id") == 416 and stage.startswith(("freed", "free ")))
    ):
        return "origin-site"
    if role == "sink":
        return "crash-site"
    if role == "intermediate" and ev.get("sanitizer_report_ref"):
        return "witnessed-site"
    return "annotated-site"


def clip_patch(patch_diff: str, limit: int) -> str:
    """Cut a diff to at most `limit` bytes, keeping only WHOLE hunks.

    A naive slice ends wherever the byte count runs out - 22 GOLD records shipped diffs cut
    mid-expression at exactly 200,000 bytes. A hunk is only known to be complete once the next
    hunk header (or the end of the diff) has been seen, so cut at a hunk boundary and keep the
    file headers with it. If not even the first hunk fits, there is no valid patch to store and
    the empty string says so, rather than a fragment that reads like one.
    """
    if len(patch_diff) <= limit:
        return patch_diff
    cut = 0
    for m in list(_HUNK_HDR.finditer(patch_diff))[1:]:
        if m.start() > limit:
            break
        cut = m.start()
    # A cut at the first hunk of a new file would keep that file's header with no hunk under
    # it; drop the orphaned header too.
    hdr = patch_diff.rfind("diff --git ", 0, cut)
    if hdr > 0 and not _HUNK_HDR.search(patch_diff, hdr, cut):
        cut = hdr
    return patch_diff[:cut]


def classify_link(evidence: dict | None) -> EvidenceKind:
    """The strongest kind this link's evidence actually supports."""
    ev = evidence or {}
    if ev.get("causal_proof"):
        return EvidenceKind.CAUSALLY_PROVEN
    # A sanitizer reference is only an EXECUTION witness of *this* link when it also says
    # where (a file, or for a kernel report without line info, the reported function). A bare
    # reference names a log without attributing the link to a site in it.
    loc = ev.get("location") or {}
    if ev.get("sanitizer_report_ref") and (loc.get("file") or loc.get("function")):
        return EvidenceKind.EXECUTION
    ref = ev.get("patch_hunk_ref") or ""
    if _UNATTESTED.search(ref):
        return EvidenceKind.INFERRED
    if _ATTESTED.search(ref):
        return EvidenceKind.ATTESTED
    if ev.get("dataflow_path"):
        return EvidenceKind.DATAFLOW
    if _INFERRED.search(ref) or ref:
        return EvidenceKind.INFERRED
    return EvidenceKind.NONE


def floor(record: dict) -> EvidenceKind:
    """The WEAKEST link in the chain - what the record as a whole can honestly claim."""
    chain = [c for c in (record.get("chain") or []) if isinstance(c, dict)]
    if not chain:
        return EvidenceKind.NONE
    return max((classify_link(c.get("evidence")) for c in chain), key=lambda k: _RANK[k])


def at_least(record: dict, kind: EvidenceKind) -> bool:
    """True if EVERY link is backed at least this strongly - the query R3 implies."""
    return _RANK[floor(record)] <= _RANK[kind]
