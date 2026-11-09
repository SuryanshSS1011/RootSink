"""A structural difficulty proxy, computable without a policy.

The honest position, stated first: real difficulty for GRPO is the pass rate of the base policy,
it is model- and time-dependent, and it cannot be read off the data. Predicting it without
rollouts is an open research problem, and the strongest published signal - token-level entropy
(arXiv:2608.05797) - still needs a model forward pass.

What CAN be computed from the record alone is the structural difficulty the guard thesis itself
predicts: a weakness whose enabling condition is decided in another file is harder to find than
one visible in the same function, and a one-line guard is subtler than a nine-line one. That is
a proxy, not a measurement, and it is named `difficulty_proxy` so it can never be mistaken for
a pass rate.

Its use is stratification, not scoring: a consumer can sample across bands so that GRPO groups
are not all-solved or all-failed, and then replace it with measured pass rates once they have
run their own probe.
"""

from __future__ import annotations

# Weights are deliberately coarse. They encode an ordering the thesis argues for, not a fit to
# observed pass rates - there are none to fit to.
_LOCALITY = {
    "in-function": 0.0,
    "same-file": 0.35,
    "cross-function": 0.35,
    "cross-file": 0.7,
    "cross-project": 0.85,
}


def _links(rec):
    return [c for c in (rec.get("chain") or []) if isinstance(c, dict)]


def _sites(rec):
    out = []
    for c in _links(rec):
        loc = (c.get("evidence") or {}).get("location")
        if loc and loc.get("file"):
            out.append(loc)
    return out


def features(rec: dict) -> dict:
    """Structural signals, each independently meaningful and reported alongside the score."""
    sites = _sites(rec)
    f: dict = {}
    loc = rec.get("locality")
    if loc in _LOCALITY:
        f["locality"] = _LOCALITY[loc]
    if len(sites) >= 2:
        # Different files means the enabling condition is not visible where the crash is.
        f["cross_file_links"] = 1.0 if sites[0]["file"] != sites[-1]["file"] else 0.0
        # Line distance within a file is a weak within-file analogue.
        if sites[0]["file"] == sites[-1]["file"]:
            d = abs(sites[0]["line"] - sites[-1]["line"])
            f["line_distance"] = min(d / 500.0, 1.0)
    # A smaller guard is a subtler omission: one missing bounds test is easier to overlook than
    # nine lines of validation. Only available where ablation proved the guard.
    ev = _links(rec)[0].get("evidence") if _links(rec) else None
    cp = (ev or {}).get("causal_proof") or {}
    if cp.get("added_lines"):
        f["guard_subtlety"] = min(3.0 / max(cp["added_lines"], 1), 1.0)
    # A chain with more links has more to get right.
    f["chain_length"] = 0.0 if len(_links(rec)) <= 2 else 1.0
    return f


def proxy(rec: dict) -> float | None:
    """Mean of available features, 0 (easiest) to 1 (hardest). None if nothing is computable."""
    f = features(rec)
    return round(sum(f.values()) / len(f), 3) if f else None


def band(rec: dict) -> str | None:
    """Coarse band for stratified sampling. Bands, not points: the proxy is not that precise."""
    p = proxy(rec)
    if p is None:
        return None
    return "easy" if p < 0.3 else ("medium" if p < 0.6 else "hard")
