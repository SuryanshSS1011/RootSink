"""dataflow_evidence must describe a hunk test only while the record carries a logged one."""

import importlib.util
from pathlib import Path

spec = importlib.util.spec_from_file_location(
    "pr4", Path(__file__).resolve().parents[1] / "infra/verify/apply_pr4.py"
)
pr4 = importlib.util.module_from_spec(spec)
spec.loader.exec_module(pr4)

LEGACY = (
    " CAUSAL PROOF: the unmodified rebuild reproduces the sink; rebuilding with only the guard "
    "hunk in a.c applied runs clean on the same input, so the source link is demonstrated rather "
    "than attested."
)


def _record(proof: dict | None, text: str) -> dict:
    ev = {"causal_proof": proof} if proof else {}
    return {"dataflow_evidence": text, "chain": [{"cwe_id": 20, "evidence": ev}, {"cwe_id": 787}]}


def test_unlogged_proof_is_withdrawn_with_its_narrative():
    r = _record({"file": "a.c", "hunk": "hunk00.patch"}, "Sites from ARVO." + LEGACY * 3)
    pr4.sync_narrative(r)
    ev = r["chain"][0]["evidence"]
    assert "causal_proof" not in ev
    assert ev["guard_site_proof"]["source_cwe"] is None
    assert r["dataflow_evidence"] == "Sites from ARVO."


def test_logged_proof_keeps_one_sentence():
    proof = {"file": "a.c", "control_log": "c.log", "guard_only_log": "g.log"}
    r = _record(proof, "Sites." + LEGACY * 6)
    pr4.sync_narrative(r)
    assert r["dataflow_evidence"].count("HUNK TEST:") == 1  # the 1.0.9 wording replaces it
    assert "CAUSAL PROOF" not in r["dataflow_evidence"]
    assert r["chain"][0]["evidence"]["causal_proof"] is proof


def test_narrative_without_proof_is_removed():
    r = _record(None, LEGACY)
    pr4.sync_narrative(r)
    assert r["dataflow_evidence"] is None
