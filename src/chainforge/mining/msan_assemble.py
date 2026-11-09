"""Assemble the CWE-456 -> CWE-457 arm into ChainRecords.

This arm is evidentially unusual: MSan built with -fsanitize-memory-track-origins reports
BOTH ends of the chain from one execution. The SUMMARY line gives the use site (CWE-457) and
the "was created by ..." origin block gives the site where the uninitialised value came into
being (CWE-456). Neither link is inferred from a patch heuristic or a dataflow query, so both
carry a witnessed file:line - which is what makes the records usable as step-level supervision
rather than record-level labels (see schema.LinkLocation).

Contrast with mining.newarm_assemble, where the sink is execution-witnessed but the source is
crash-class-implied. Here the source is witnessed too.

Tiering follows the rest of the corpus: GOLD needs the execution witness AND a patch (the
schema invariant); a case with a clean differential but no fetchable patch stays SILVER.
"""

from __future__ import annotations

import hashlib
import re

from ..schema import (
    ChainLink,
    ChainRecord,
    CommitRange,
    ConfidenceTier,
    LinkEvidence,
    LinkLocation,
    LinkRole,
    SanitizerReport,
)

SOURCE_CWE = 456
SINK_CWE = 457

# Frames inside the sanitizer's own runtime describe the instrumentation, not the bug - the
# same reason mining.kasan_report skips mm/kasan/ frames.
_NOISE = re.compile(r"(compiler-rt/lib/(msan|sanitizer_common)|msan_interceptors|/usr/include/)")
_LOC = re.compile(r"([a-zA-Z0-9_/.\-]+\.(?:c|cc|cpp|h|hpp|cxx)):(\d+)")
_ORIGIN = re.compile(r"was created by[^\n]*?(?:of '([^']+)')?[^\n]*\n((?:\s+#\d+[^\n]*\n){1,8})")
_SUMMARY = re.compile(
    r"SUMMARY: MemorySanitizer: \S+\s+"
    r"([a-zA-Z0-9_/.\-]+\.(?:c|cc|cpp|h|hpp|cxx)):(\d+)(?::\d+)?\s+in\s+(\S+)"
)
# Container build paths are an artefact of where OSS-Fuzz checked the source out, not part of
# the project's own layout; strip them so a file:line is comparable across records.
_PREFIX = re.compile(r"^(?:/src/[^/]+/|/work/build/(?:\.\./)+|/src/)")


def _tidy(path: str) -> str:
    return _PREFIX.sub("", path)


def parse_msan_log(text: str) -> dict:
    """Extract {var, source{file,line,function}, sink{file,line,function}} from an MSan log."""
    out: dict = {}
    m = _ORIGIN.search(text)
    if m:
        out["var"] = m.group(1)
        for line in m.group(2).splitlines():
            loc = _LOC.search(line)
            if loc and not _NOISE.search(loc.group(1)):
                fn = re.search(r"#\d+\s+0x\w+\s+in\s+([^\s/]+)", line)
                out["source"] = {
                    "file": loc.group(1),
                    "line": int(loc.group(2)),
                    "function": fn.group(1) if fn else None,
                }
                break
    s = _SUMMARY.search(text)
    if s and not _NOISE.search(s.group(1)):
        out["sink"] = {"file": s.group(1), "line": int(s.group(2)), "function": s.group(3)}
    return out


def _stable_id(local_id: int) -> str:
    """MSan-arm records get the 0x96 id band (distinct from arvo/kernel/git/len3/race/newarm)."""
    h = int(hashlib.sha1(str(local_id).encode()).hexdigest()[:8], 16) % 10_000_000
    return f"CHAINFORGE-96{h:07d}"


def assemble_msan_record(
    local_id: int,
    parsed: dict,
    *,
    project: str,
    language: str = "C",
    patch_diff: str | None = None,
    patch_url: str | None = None,
) -> ChainRecord | None:
    """Build one 456->457 ChainRecord. Returns None unless BOTH links were localized.

    A record with only the use site witnessed is a single weakness (CWE-457), not a chain, and
    is routed to single_weakness.jsonl by the caller rather than labelled with a guessed source.
    """
    src, sink = parsed.get("source"), parsed.get("sink")
    if not src or not sink:
        return None

    src_file, sink_file = _tidy(src["file"]), _tidy(sink["file"])
    var = parsed.get("var")
    tier = ConfidenceTier.GOLD if patch_diff else ConfidenceTier.SILVER

    chain = [
        ChainLink(
            cwe_id=SOURCE_CWE,
            role=LinkRole.SOURCE,
            evidence=LinkEvidence(
                sanitizer_report_ref="vul.sanitizer.txt",
                patch_hunk_ref=(
                    "MSan origin block: uninitialised value"
                    + (f" '{var}'" if var else "")
                    + " created here"
                )[:120],
                location=LinkLocation(
                    file=src_file, line=src["line"], function=src.get("function")
                ),
            ),
        ),
        ChainLink(
            cwe_id=SINK_CWE,
            role=LinkRole.SINK,
            evidence=LinkEvidence(
                sanitizer_report_ref="vul.sanitizer.txt",
                location=LinkLocation(
                    file=sink_file, line=sink["line"], function=sink.get("function")
                ),
            ),
        ),
    ]
    return ChainRecord(
        id=_stable_id(local_id),
        aliases=[f"OSS-Fuzz-{local_id}"],
        project=project,
        language=language,
        ecosystem="OSS-Fuzz",
        commit_range=CommitRange(fixed=patch_url),
        chain=chain,
        chain_string=f"CWE-{SOURCE_CWE}->CWE-{SINK_CWE}",
        sanitizer_reports=[
            SanitizerReport(
                revision="vulnerable",
                sanitizer="msan",
                log_ref=f"data/evidence/arvo/{local_id}/vul.sanitizer.txt",
                triggered=True,
                observed_by="self",
            ),
            SanitizerReport(
                revision="patched",
                sanitizer="msan",
                log_ref=f"data/evidence/arvo/{local_id}/fix.sanitizer.txt",
                triggered=False,
                observed_by="self",
            ),
        ],
        patch_diff=(patch_diff or patch_url) if tier == ConfidenceTier.GOLD else None,
        label_confidence_tier=tier,
        locality="cross-file" if src_file != sink_file else "same-file",
        dataflow_evidence=(
            "EXECUTION witness (both links): MemorySanitizer with origin tracking fires at the "
            f"vulnerable revision and is clean at patched. CWE-456 at {src_file}:{src['line']} "
            f"is the origin block's creation site; CWE-457 at {sink_file}:{sink['line']} is the "
            "SUMMARY use site. Neither link is inferred."
        ),
        differential_complete=True,
        provenance="arvo-msan",
    )
