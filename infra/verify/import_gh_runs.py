#!/usr/bin/env python3
"""Import clean-host replays from the public chainforge-runner (GitHub Actions) and score them.

The runner only replays public ARVO images; the comparison against what CHAINFORGE ships happens
here, so no private data leaves the repository. For each downloaded `<id>/result.json` this adds
the vulnerable crash signature (class + first project frame) and whether it matches the shipped
vulnerable log, writing results that `attach_arvo_reruns.py` consumes unchanged.

With --sample data/validation/clean_rerun_sample.json it also writes the independent reproduction
rate (two-sided AND same crash as shipped, Wilson 95%) to data/validation/clean_rerun.json (tracked:
it comes from external runs and cannot be regenerated locally).

Usage: import_gh_runs.py <downloaded_dir> --out <scored_dir> [--sample <sample.json>]
"""

from __future__ import annotations

import argparse
import json
import re
import shutil
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))
from chainforge.evidence import normalize_path  # noqa: E402

# The ERROR line names the crash class (MSan reports open with WARNING); ASan prints
# "AddressSanitizer:DEADLYSIGNAL" before its ERROR line, which is not a class. UBSan's class is
# the first words of its runtime-error message ("index out", "signed integer"). Frames may sit
# under /src, /work/build/../../src, or be relative.
_CLASS = re.compile(
    r"(?:ERROR|WARNING): \w+Sanitizer: ([\w-]+)|runtime error: ([a-z]+(?: [a-z]+)?)"
)
_FRAME = re.compile(r"#\d+ 0x[0-9a-f]+ in (.*?) (\S+\.(?:c|cc|cpp|cxx|h|hpp|inc|asm|S)):(\d+)")
_RUNTIME = re.compile(r"compiler-rt|llvm-project|libfuzzer|sanitizer_common|/asan/|/msan/|/ubsan/")


def signature(text: str) -> str:
    """Crash class + first project frame (normalised path:line); '|' if no crash parses."""
    c = _CLASS.search(text)
    cls = (c.group(1) or c.group(2) or "").strip() if c else ""
    f = next(
        (
            f"{normalize_path(m.group(2))}:{m.group(3)}"
            for m in _FRAME.finditer(text)
            if not _RUNTIME.search(m.group(2))
        ),
        "",
    )
    return f"{cls}|{f}"


def wilson(k: int, n: int, z: float = 1.96) -> list[float]:
    if not n:
        return [0.0, 0.0]
    p, d = k / n, 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    h = z * ((p * (1 - p) / n + z * z / (4 * n * n)) ** 0.5) / d
    return [round(c - h, 3), round(c + h, 3)]


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("downloaded")
    ap.add_argument("--out", required=True)
    ap.add_argument("--sample")
    args = ap.parse_args(argv)
    out = Path(args.out)
    scored = {}
    for rj in Path(args.downloaded).rglob("result.json"):
        aid = rj.parent.name
        res = json.loads(rj.read_text())
        dst = out / aid
        dst.mkdir(parents=True, exist_ok=True)
        for f in rj.parent.glob("*.sanitizer.txt"):
            shutil.copy(f, dst / f.name)
        vul = rj.parent / "vul.sanitizer.txt"
        shipped = Path(f"data/evidence/arvo/{aid}/vul.sanitizer.txt")
        if vul.is_file():
            res["vul_signature"] = signature(vul.read_text(errors="replace"))
        if shipped.is_file() and vul.is_file():
            res["shipped_vul_signature"] = signature(shipped.read_text(errors="replace"))
            # A shipped log with no parseable crash gives nothing to compare: unverifiable, not
            # a mismatch (as in attach_arvo_reruns).
            res["signature_matches_shipped"] = (
                None
                if res["shipped_vul_signature"].startswith("|")
                else res["vul_signature"] == res["shipped_vul_signature"]
            )
        res["differential_complete"] = res.get("vul") == "crashed" and all(
            o == "clean" for o in res.get("fix") or [None]
        )
        (dst / "result.json").write_text(json.dumps(res, indent=1))
        scored[aid] = res
    print(f"scored {len(scored)} -> {out}")

    if args.sample:
        ids = json.loads(Path(args.sample).read_text())["arvo_ids"]
        got = [scored[i] for i in ids if i in scored]
        ok = [
            r
            for r in got
            if r.get("differential_complete") and r.get("signature_matches_shipped") is not False
        ]
        summary = {
            "host": "GitHub-hosted runners (never built the corpus)",
            "sample": len(ids),
            "returned": len(got),
            "reproduced": len(ok),
            "same_crash_signature": sum(r.get("signature_matches_shipped") is True for r in ok),
            "no_shipped_log_to_compare": sum(
                r.get("signature_matches_shipped") is None for r in ok
            ),
            "rate": round(len(ok) / len(got), 3) if got else None,
            "wilson95": wilson(len(ok), len(got)),
            "not_reproduced": sorted(r["local_id"] for r in got if r not in ok),
        }
        Path("data/validation/clean_rerun.json").write_text(json.dumps(summary, indent=1))
        print(json.dumps({k: v for k, v in summary.items() if k != "not_reproduced"}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
