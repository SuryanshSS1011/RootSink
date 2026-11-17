#!/usr/bin/env python3
"""Extract structured crash facts from an ASan/UBSan sanitizer log.

Emits raw, witnessed facts plus a *class-aware* suggested sink CWE. The mapping
deliberately keeps the weakness class in view rather than collapsing everything
to READ->125 / WRITE->787:

  heap/stack/global-buffer-overflow  READ  -> CWE-125   (genuinely out-of-bounds)
  heap/stack/global-buffer-overflow  WRITE -> CWE-787
  heap-use-after-free                *     -> CWE-416    (the UAF *is* the weakness;
                                                          a UAF READ is in-bounds-of-freed,
                                                          so it is NOT an OOB read -> flagged
                                                          for chain-vs-single review, not 125)
  UBSan signed/unsigned integer overflow    -> CWE-190
  SEGV / null-deref                          -> CWE-476

Usage: parse_sanitizer.py <logfile>   # prints one JSON object to stdout
"""

import json
import re
import sys

_ASAN = re.compile(r"ERROR:\s*AddressSanitizer:\s*([a-z0-9\-]+)", re.I)
# MemorySanitizer reports an uninitialised read as a WARNING, not an ERROR, so the ASan
# pattern never matches and every MSan case parsed as "no crash". That silently hid the
# largest single class in ARVO: 1183 cases (19.3%) are MSan use-of-uninitialized-value.
_MSAN = re.compile(r"(?:WARNING|ERROR):\s*MemorySanitizer:\s*([a-z0-9\-]+)", re.I)
_DIR = re.compile(r"\b(READ|WRITE) of size \d+", re.I)
_SUMMARY = re.compile(r"SUMMARY:\s*\w+Sanitizer:\s*[a-z0-9\-]+\s+(\S+)", re.I)
_UBSAN = re.compile(r"runtime error:\s*(.+)", re.I)
_SEGV = re.compile(
    r"SEGV on unknown address|Segmentation fault|"
    r"null (?:pointer )?dereference",
    re.I,
)

_OOB = {
    "heap-buffer-overflow",
    "stack-buffer-overflow",
    "global-buffer-overflow",
    "dynamic-stack-buffer-overflow",
}


def parse(text: str) -> dict:
    out = {
        "sanitizer": None,
        "bug_class": None,
        "direction": None,
        "crash_site": None,
        "ubsan_kinds": [],
        "suggested_sink_cwe": None,
        "notes": [],
    }

    mm = _MSAN.search(text)
    if mm:
        out["sanitizer"] = "memory"
        out["bug_class"] = mm.group(1).lower()

    m = _ASAN.search(text)
    if m:
        out["sanitizer"] = "address"
        out["bug_class"] = m.group(1).lower()
        d = _DIR.search(text)
        if d:
            out["direction"] = d.group(1).upper()

    ub = _UBSAN.findall(text)
    if ub:
        # de-dup while preserving order
        seen = set()
        for k in ub:
            k = k.strip()
            if k not in seen:
                seen.add(k)
                out["ubsan_kinds"].append(k)
        if out["sanitizer"] is None:
            out["sanitizer"] = "undefined"

    s = _SUMMARY.search(text)
    if s:
        out["crash_site"] = s.group(1)

    bc = out["bug_class"]
    direction = out["direction"]
    if bc in _OOB:
        if direction == "WRITE":
            out["suggested_sink_cwe"] = 787
        elif direction == "READ":
            out["suggested_sink_cwe"] = 125
        else:
            out["notes"].append("OOB with no READ/WRITE token; direction unknown")
    elif bc in ("heap-use-after-free", "use-after-free"):
        out["suggested_sink_cwe"] = 416
        if direction:
            out["notes"].append(
                f"UAF {direction}: in-bounds-of-freed, NOT CWE-125/787; "
                "sink stays 416 unless a downstream OOB is separately witnessed "
                "(chain-vs-single review)"
            )
    elif bc in ("stack-use-after-return", "use-after-poison"):
        out["suggested_sink_cwe"] = 416
    elif _SEGV.search(text):
        out["bug_class"] = out["bug_class"] or "segv"
        out["suggested_sink_cwe"] = 476
    # MSan use-of-uninitialized-value -> CWE-457. MITRE grounds this arm DIRECTLY:
    # CWE-456 (Missing Initialization of a Variable) CanPrecede CWE-457, which is stronger
    # grounding than several arms already shipped (416->787 and 476->787 are catalog-only).
    if (
        out["suggested_sink_cwe"] is None
        and out["sanitizer"] == "memory"
        and (out["bug_class"] or "").find("uninitialized") >= 0
    ):
        out["suggested_sink_cwe"] = 457

    if (
        out["suggested_sink_cwe"] is None
        and out["ubsan_kinds"]
        and any("overflow" in k for k in out["ubsan_kinds"])
    ):
        out["suggested_sink_cwe"] = 190

    return out


def main(argv):
    if len(argv) != 2:
        print("usage: parse_sanitizer.py <logfile>", file=sys.stderr)
        return 2
    with open(argv[1], errors="replace") as fh:
        text = fh.read()
    print(json.dumps(parse(text), separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
