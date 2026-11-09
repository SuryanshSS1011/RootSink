"""Reward components for repair episodes, kept separate so a trainer can weigh them openly.

Only `replay` is a verified outcome. The other two are shaping signals with known blind spots,
named here so nobody mistakes them for correctness checks:

- replay(result)            score_patch.sh's outcome: 1 for `pass`, 0 for `crash`, `build_fail` or
                            `patch_fail`, None for `not_run` (an environment failure, never a
                            negative reward, R10). With `strict` (the default), a patch that
                            applied only with fuzz scores 0: its context did not match the
                            vulnerable tree, so its hunks may have landed elsewhere.
- root_site(patch, record)  1 if the patch edits the root-cause instance's function (or within a
                            few lines of its site), 0.5 if only its file, else 0. It uses the
                            chain's first instance, which the policy view withholds. A fix at
                            the sink can be legitimate, so this is a bonus, not a gate.
- coverage_kept(result, record)  libFuzzer feature coverage on the project's seed corpus, patched
                            over unpatched (score_patch.sh with CF_CORPUS=1; the unpatched figure
                            is stored by PR-12 scoring). A patch
                            that rejects inputs early loses coverage; a correct fix usually keeps
                            it. None when the image has no seed corpus or the engine is not
                            libFuzzer.

`shaped(...)` is one reasonable combination: replay gates everything, coverage below the
tolerance zeroes the reward, and the root-site bonus adds at most `bonus`.
"""

from __future__ import annotations

import re

from .evidence import bare_function, same_file

_FILE = re.compile(r"^\+\+\+ b/(\S+)", re.M)
_HUNK = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+\d+(?:,\d+)? @@ ?(.*)$", re.M)

PASS, NEGATIVE = "pass", ("crash", "build_fail", "patch_fail")


def replay(result: dict, strict: bool = True) -> float | None:
    out = result.get("outcome")
    if out == PASS:
        if strict and ((result.get("apply") or {}).get("fuzz") or 0) > 0:
            return 0.0
        return 1.0
    if out in NEGATIVE:
        return 0.0
    return None


def _hunks(patch: str) -> list[tuple[str, int, int, str]]:
    """(file, first old line, old line count, function context) for every hunk."""
    out, pos = [], 0
    files = [(m.start(), m.group(1)) for m in _FILE.finditer(patch)]
    for m in _HUNK.finditer(patch):
        while pos + 1 < len(files) and files[pos + 1][0] < m.start():
            pos += 1
        if files and files[pos][0] < m.start():
            out.append((files[pos][1], int(m.group(1)), int(m.group(2) or 1), m.group(3) or ""))
    return out


def root_site(patch: str, record: dict, window: int = 10) -> float:
    chain = record.get("chain") or []
    loc = (chain[0].get("evidence") or {}).get("location") if chain else None
    if not loc or not loc.get("file"):
        return 0.0
    fn = bare_function(loc.get("function"))
    line = loc.get("line")
    best = 0.0
    for f, start, n, ctx in _hunks(patch or ""):
        if not same_file(f, loc["file"]):
            continue
        best = max(best, 0.5)
        near = isinstance(line, int) and start - window <= line <= start + n + window
        in_fn = bool(fn) and re.search(rf"\b{re.escape(fn)}\s*\(", ctx) is not None
        if near or in_fn:
            return 1.0
    return best


def coverage_kept(result: dict, record: dict) -> float | None:
    """Patched feature coverage on the seed corpus over the unpatched build's (the record's
    `rl_scoring.corpus.nopatch_ft`, measured by PR-12 scoring)."""
    base = ((record.get("rl_scoring") or {}).get("corpus") or {}).get("nopatch_ft")
    got = (result.get("corpus") or {}).get("ft")
    if not base or got is None:
        return None
    return got / base


def shaped(
    result: dict,
    patch: str,
    record: dict,
    bonus: float = 0.25,
    tolerance: float = 0.9,
) -> float | None:
    r = replay(result)
    if r is None or r == 0.0:
        return r
    kept = coverage_kept(result, record)
    if kept is not None and kept < tolerance:
        return 0.0
    return r + bonus * root_site(patch, record)
