"""The GOLD contract as code: PR-3's rules I2-I5, shared by the release transform and conformance.

One implementation, imported by both, so the rule that assigns a tier and the rule that checks it
cannot drift apart - the failure that let 12 harness proofs through two different path regexes.
"""

from __future__ import annotations

import re
from pathlib import Path

from chainforge.evidence import cwe_basis, guard_evidence_defect, harness_site

_CLASS = re.compile(
    r"(?:AddressSanitizer|MemorySanitizer|UndefinedBehaviorSanitizer|BUG: KASAN): ([\w-]+)"
)
_NULL_PAGE = re.compile(r"SEGV on unknown address (?:0x)?0{6,}[0-9a-f]{0,4}\b|zero page", re.I)
# ASan prints "READ of size N"; a SEGV report instead says "caused by a READ memory access".
_ACCESS = re.compile(r"\b(READ|WRITE) of size|caused by an? (READ|WRITE) memory access", re.I)
_WITNESSED = {"execution", "causally-proven"}
# A patched run is clean only if the input demonstrably ran to completion. Silence is not enough:
# 67 archived patched logs were 32-bit ASan aborting at startup ("Shadow memory range
# interleaves"), which prints no crash line and had been scored clean. One marker per engine.
_EXECUTED = re.compile(
    r"Executed /tmp/poc"  # libFuzzer
    r"|Execution successful"  # AFL driver
    r"|Accepting input from '/tmp/poc'[\s\S]*Usage for fuzzing"  # honggfuzz replay, completed
    r"|\[init\] environment up"  # kernel rootfs; the harness enforces the run window
)
# \b keeps the kernel's boot banner "KernelAddressSanitizer initialized" from reading as a crash.
_CRASHED = re.compile(
    r"\b(?:AddressSanitizer|UndefinedBehaviorSanitizer|MemorySanitizer|LeakSanitizer)|BUG: KASAN"
    r"|libFuzzer: deadly signal|DEADLYSIGNAL|runtime error:"
)


def ran_clean(log_text: str, declared_marker: str | None = None) -> bool:
    """True if this patched-side log shows the input executed and nothing fired.

    A run through a non-fuzzer driver (a hand-built reproducer) prints its own completion line;
    the report declares it as `executed_marker`, so the evidence stays checkable per record.
    """
    ran = bool(_EXECUTED.search(log_text)) or bool(declared_marker and declared_marker in log_text)
    return ran and not _CRASHED.search(log_text)


# MSan poisons freed memory: a read of it is reported as an uninitialized value whose origin
# is "created by a heap deallocation" (rule log, 2026-11-09, release 1.0.7).
FREED_ORIGIN = re.compile(r"Uninitiali[sz]ed value was created by a heap deallocation")


def freed_msan_origin(log_text: str) -> bool:
    """True if the log's first MemorySanitizer report is a use of an uninitialized value whose
    origin is a heap deallocation, i.e. a read of freed memory. Only that report counts."""
    start = log_text.find("WARNING: MemorySanitizer: use-of-uninitialized-value")
    if start < 0:
        return False
    end = log_text.find("SUMMARY:", start)
    return bool(FREED_ORIGIN.search(log_text[start : end if end > 0 else None]))


def crash_facts(log_text: str) -> dict:
    """Crash class, whether it is a NULL dereference, the access direction, and whether an MSan
    origin is a heap deallocation (a read of freed memory), from one log."""
    m = _CLASS.search(log_text)
    a = _ACCESS.search(log_text)
    return {
        "class": m.group(1) if m else None,
        "null_deref": bool(_NULL_PAGE.search(log_text)),
        "access": (a.group(1) or a.group(2)).upper() if a else None,
        "freed_origin": freed_msan_origin(log_text),
    }


def kasan_same_bug(lines: list[str], signature: str) -> list[int]:
    """PR-6: the console lines that open a KASAN report of syzbot's bug, given its signature
    "class:function". Same class, and syzbot's function is the report's own function or one of
    the first 12 frames of that report's call trace."""
    typ, fn = signature.split(":", 1) if ":" in signature else ("", "")
    out = []
    for i, ln in enumerate(lines):
        m = re.search(r"KASAN: ([\w-]+) (?:\w+ )?in (\w+)", ln)
        if not (m and fn and (typ.endswith(m.group(1)) or m.group(1).endswith(typ))):
            continue
        if m.group(2) == fn:
            out.append(i)
            continue
        block = []
        for nxt in lines[i + 1 : i + 200]:
            if "BUG: KASAN:" in nxt or re.search(r"={20,}", nxt):
                break
            block.append(nxt)
        frames = re.findall(r"\s(\w+)(?:\.[\w.]+)?\+0x[0-9a-f]+/0x", "\n".join(block))
        if fn in frames[:12]:
            out.append(i)
    return out


def source_contradiction(rec: dict, facts: dict | None) -> str | None:
    """I2: why the record's source CWE is contradicted by its own sink report, or None."""
    if not facts or not facts.get("class"):
        return None
    if rec["chain"][0].get("evidence_kind") == "causally-proven":
        return None  # PR-3 I2 governs statically assigned sources; ablation re-earns them (PR-4)
    src = rec["chain"][0]["cwe_id"]
    # An MSan report whose origin is a heap deallocation witnesses freed memory (1.0.7).
    if src == 416 and "use-after-free" not in facts["class"] and not facts.get("freed_origin"):
        return f"CWE-416 source but the sanitizer reports {facts['class']}"
    if src == 476 and not facts["null_deref"]:
        return f"CWE-476 source but the sanitizer reports {facts['class']}, not a NULL dereference"
    return None


def sink_contradiction(rec: dict, facts: dict | None) -> str | None:
    """Sink against the report: CWE-787 is a WRITE, CWE-125 a READ, and (PR-8) a use-after-free
    report is a CWE-125/787 sink only behind a CWE-416 link, the PR-2 convention."""
    if not facts:
        return None
    chain = rec["chain"]
    sink = chain[-1]["cwe_id"]
    cls = facts.get("class") or ""
    if sink in (125, 787) and "use-after" in cls and (len(chain) < 2 or chain[-2]["cwe_id"] != 416):
        return f"CWE-{sink} sink but the report is {cls} with no CWE-416 link before it"
    if sink == 787 and facts.get("freed_origin"):
        return "CWE-787 sink but MSan reports a read of freed memory (it cannot see writes)"
    if not facts.get("access"):
        return None
    want = {787: "WRITE", 125: "READ"}.get(sink)
    if want and facts["access"] != want:
        return f"CWE-{sink} sink but the access is a {facts['access']}"
    return None


def _sink_runs(rec: dict) -> list[dict]:
    """Reports that replay the sink crash (not a rebuild witnessing an intermediate)."""
    return [s for s in rec.get("sanitizer_reports") or [] if s.get("witnesses") != "intermediate"]


def vul_log(rec: dict, root: Path) -> Path | None:
    for s in _sink_runs(rec):
        if s.get("revision") == "vulnerable" and s.get("log_ref"):
            p = root / s["log_ref"]
            if p.is_file():
                return p
    return None


def _two_sided_self_run(rec: dict, root: Path) -> str | None:
    """I5: None if both runs are ours, archived, crash-then-clean; else the reason."""
    # Upstream's report may stay alongside ours as provenance; only our own runs count here.
    reps = _sink_runs(rec)
    vul_all = [s for s in reps if s.get("revision") == "vulnerable"]
    vul = [s for s in vul_all if s.get("observed_by") != "upstream"]
    fix = [s for s in reps if s.get("revision") == "patched" and s.get("observed_by") != "upstream"]
    if not any(s.get("triggered") for s in vul_all):
        return "no triggered vulnerable-side report"
    if not any(s.get("triggered") for s in vul):
        # Release 1.0.10: our own attempt found the fixed kernel crashing the same way. Its log
        # was not archived, but it contradicts the differential, so the record is not Upstream.
        if (rec.get("kernel_attempt") or {}).get("status") == "fix_still_crashes":
            return "our fixed-kernel run crashed with the same bug (attempt log not archived)"
        return "upstream"
    if rec.get("differential_complete") is not True or not fix:
        return "no patched-side run"
    # PR-3 I5: the fixed revision must run clean TWICE. One clean run was accepted until
    # 2026-10-20 (disclosed in PREREGISTRATION.md); a single run can be a lucky miss.
    if len(fix) < 2:
        return "one patched run (I5 requires two)"
    if any(s.get("triggered") for s in fix):
        return "patched side crashes"
    for s in vul + fix:
        if not (s.get("log_ref") and (root / s["log_ref"]).is_file()):
            return f"log not archived: {s.get('log_ref')}"
    for s in fix:
        if not ran_clean(
            (root / s["log_ref"]).read_text(errors="replace"), s.get("executed_marker")
        ):
            return f"patched run did not demonstrably execute: {s['log_ref']}"
    return None


def gold_violations(rec: dict, root: Path, facts: dict | None = None) -> dict[str, str]:
    """Every PR-3 rule (I2-I5) this record breaks, as {rule: reason}. Empty means GOLD holds."""
    out: dict[str, str] = {}
    if facts is None:
        p = vul_log(rec, root)
        facts = crash_facts(p.read_text(errors="replace")) if p else None
    if why := source_contradiction(rec, facts):
        out["I2"] = why
    if why := sink_contradiction(rec, facts):
        out["I2-sink"] = why
    for link in (rec.get("chain") or [])[:1] + (rec.get("chain") or [])[-1:]:
        loc = (link.get("evidence") or {}).get("location") or {}
        if link.get("evidence_kind") in _WITNESSED and harness_site(loc.get("file") or ""):
            out["I2-site"] = f"{link.get('role')} site in harness or test code: {loc.get('file')}"
            break
    cr = rec.get("commit_range") or {}
    sha = re.search(r"[0-9a-f]{40}", cr.get("fixed") or "")
    if why := guard_evidence_defect(rec.get("patch_diff"), sha.group(0) if sha else ""):
        out["I3"] = why
    elif not (cr.get("fix_commits") or sha):
        # Criterion (d): the fix is recorded under a commit id (normalize_fix_commits.py).
        out["I3"] = "no recorded fix commit"
    chain = rec.get("chain") or []
    if len(chain) >= 3 and any(c.get("evidence_kind") not in _WITNESSED for c in chain[1:-1]):
        out["I4"] = "intermediate link not execution-witnessed"
    if why := _two_sided_self_run(rec, root):
        out["I5"] = why
    elif chain and chain[-1].get("evidence_kind") not in _WITNESSED:
        out["I5"] = "sink link not attributed to a sanitizer report"
    return out


# Kernel attempt outcomes in which a kernel we built booted and ran the reproducer.
KERNEL_RAN = (
    "differential",
    "vul_no_repro",
    "vul_other_bug",
    "fix_still_crashes",
    "fix_untestable",
)


def attempt_ran(attempt: dict | None) -> bool:
    """A kernel attempt ran the reproducer: a kernel we built booted and the reproducer executed.

    `vul_no_repro` also covers a vulnerable kernel that never booted (detail ends `(no_boot)`) or
    whose reproducer never started (`(not_run)`); those ran nothing (R10)."""
    a = attempt or {}
    if a.get("status") not in KERNEL_RAN:
        return False
    if a.get("status") == "vul_no_repro":
        return not re.search(r"\((?:no_boot|not_run)\)\s*$", a.get("detail") or "")
    return True


def reached(rec: dict, root: Path) -> bool:
    """A run of ours reached the record: an archived run, a run report of ours, or a kernel
    attempt that ran the reproducer (not one with no C reproducer, a failed build or no boot)."""
    if vul_log(rec, root) is not None:
        return True
    if attempt_ran(rec.get("kernel_attempt")):
        return True
    return any(s.get("observed_by") != "upstream" for s in _sink_runs(rec))


# The root CWE rests on nothing of the record's own (release 1.0.10, the paper's Candidate rule).
WEAK_ROOT_BASES = ("advisory", "catalogue-default")


def unreached_tier(rec: dict) -> str:
    """Tier of a record no run of ours reached: Partial when its own material (a dataflow path, a
    check or lock the fix adds, the reporter's sanitizer report) supports the root CWE, Candidate
    when only an advisory's listed CWEs or the catalogue's default root for the sink do."""
    root = (rec.get("chain") or [{}])[0]
    weak = cwe_basis(root, rec.get("provenance") or "") in WEAK_ROOT_BASES
    return "bronze" if weak else "silver"


def expected_tier(rec: dict, root: Path) -> tuple[str, dict[str, str]]:
    """The tier the paper's rules give a record, and the contract gaps behind it (release 1.0.10).

    Reproduced or Upstream by the GOLD contract; otherwise Partial when a run of ours reached it,
    and, when none did, Partial or Candidate by `unreached_tier`. Used by `retier_all.py` and the
    gate alike."""
    v = gold_violations(rec, root)
    tier = tier_for(rec, v)
    if tier == "silver" and not reached(rec, root):
        tier = unreached_tier(rec)
    return tier, v


def tier_for(rec: dict, violations: dict[str, str]) -> str:
    """GOLD only with no violation; gold-upstream when the sole gap is that upstream ran it."""
    if not violations:
        return "gold"
    if set(violations) == {"I5"} and violations["I5"] == "upstream":
        return "gold-upstream"
    return "silver"
