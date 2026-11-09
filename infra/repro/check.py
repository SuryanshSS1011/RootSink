#!/usr/bin/env python3
"""Compare observed reproduction output against what a CRB bundle declares.

Called by verify.sh. Emits a JSON verdict and exits non-zero on mismatch, so a bundle
that has silently rotted (image retagged, crash changed, patch no longer clean) fails
loudly instead of being assumed good.

Usage: check.py <bundle.json> <vul.log> <fix.log> [ubsan.log]
"""

import json
import os
import re
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "mac"))
try:
    from parse_sanitizer import parse  # shared witness parser
except Exception:  # pragma: no cover - fallback keeps the verifier usable standalone
    parse = None

CRASH_RE = re.compile(
    r"ERROR: (Address|Undefined|Memory|Leak)Sanitizer|runtime error:|libFuzzer: deadly signal",
    re.I,
)


def read(path):
    if not path or not os.path.exists(path):
        return ""
    with open(path, errors="replace") as fh:
        return fh.read()


def main(argv):
    if len(argv) < 3:
        print("usage: check.py <bundle.json> <vul.log> <fix.log> [ubsan.log]", file=sys.stderr)
        return 2
    with open(argv[0]) as fh:
        b = json.load(fh)
    vul, fix, ub = read(argv[1]), read(argv[2]), read(argv[3] if len(argv) > 3 else None)

    checks = []

    def add(name, ok, detail=""):
        checks.append({"check": name, "ok": bool(ok), "detail": detail})

    # 1. The differential: vulnerable must crash, patched must not.
    vul_crashed = bool(CRASH_RE.search(vul))
    fix_crashed = bool(CRASH_RE.search(fix))
    add("vulnerable_crashes", vul_crashed, "no sanitizer signature" if not vul_crashed else "")
    add("patched_clean", not fix_crashed, "patched revision still crashes" if fix_crashed else "")

    # 2. The witness must match what the bundle declares, not merely "something crashed".
    exp = (b.get("expected", {}).get("vulnerable") or {}).get("witness")
    if exp and parse and vul_crashed:
        got = parse(vul)
        for field in ("bug_class", "direction"):
            want, have = exp.get(field), got.get(field)
            if want:
                add(f"witness_{field}", want == have, f"expected {want}, observed {have}")
        if exp.get("implies_sink_cwe"):
            want_sink = exp["implies_sink_cwe"]
            have_sink = got.get("suggested_sink_cwe")
            add(
                "sink_cwe",
                want_sink == have_sink,
                f"expected CWE-{want_sink}, observed CWE-{have_sink}",
            )
    elif exp:
        add("witness_comparable", False, "could not parse observed witness")

    # 3. Intermediate links: only assert when the UBSan rebuild actually ran and built.
    if ub:
        built = "BUILD_EXIT=0" in ub
        kinds = sorted(set(re.findall(r"runtime error: ([a-z \-]+)", ub)))
        overflow = [k for k in kinds if "overflow" in k]
        for link in b.get("links", []):
            if link.get("cwe_id") == 190 and link.get("role") != "sink":
                if not built:
                    add("link_cwe190_witnessed", False, "UBSan rebuild failed - INCONCLUSIVE")
                else:
                    add(
                        "link_cwe190_witnessed",
                        bool(overflow),
                        f"observed: {overflow or kinds or 'none'}",
                    )

    ok = all(c["ok"] for c in checks)
    verdict = {
        "record_id": b.get("record_id"),
        "chain": b.get("chain"),
        "verdict": "PASS" if ok else "FAIL",
        "checks": checks,
    }
    print(json.dumps(verdict, indent=2))
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
