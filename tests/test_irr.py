"""Agreement statistics: kappa misleads under imbalance, which is why AC1 is reported too."""

import importlib.util
from pathlib import Path

spec = importlib.util.spec_from_file_location(
    "irr", Path(__file__).resolve().parents[1] / "infra/verify/irr.py"
)
irr = importlib.util.module_from_spec(spec)
spec.loader.exec_module(irr)


def test_perfect_agreement():
    a = ["20", "416", "190", "20"]
    assert irr._kappa(a, a) == 1.0
    assert irr._ac1(a, a) == 1.0


def test_kappa_paradox_is_why_ac1_is_reported():
    # 18/20 agree, but almost everything is one class: kappa collapses, AC1 does not
    a = ["20"] * 18 + ["20", "416"]
    b = ["20"] * 18 + ["416", "20"]
    assert irr._kappa(a, b) < 0.0
    assert irr._ac1(a, b) > 0.85


def test_sample_is_seeded_and_covers_every_stratum():
    rows = [
        {"id": f"r{i}", "label_confidence_tier": t, "chain": [1, 2], "chain_string": arm}
        for i, (t, arm) in enumerate([("gold", "A")] * 50 + [("silver", "B")] * 5 + [("gold", "C")])
    ]
    s1 = irr.sample(rows, 10, seed=1)
    assert [r["id"] for r in s1] == [r["id"] for r in irr.sample(rows, 10, seed=1)]
    assert {r["chain_string"] for r in s1} == {"A", "B", "C"}


def test_precision_scores_a_blind_sheet_against_the_pipeline():
    rec = {
        "label_confidence_tier": "gold",
        "chain_string": "CWE-20->CWE-125",
        "chain": [
            {"cwe_id": 20, "evidence": {"location": {"file": "b.c", "line": 9}}},
            {"cwe_id": 125, "evidence": {"location": {"file": "a.c", "line": 3}}},
        ],
    }
    # sites are listed sorted (a.c first), so the sink is site 1 and the source site 2
    assert irr.truth(rec)["sink_site"] == "1" and irr.truth(rec)["source_site"] == "2"
    sheet = [
        {
            "id": "item-1",
            "source_cwe": "20",
            "sink_cwe": "787",
            "source_site": "2",
            "sink_site": "1",
            "causal": "unclear",
            "note": "",
        }
    ]
    rec["label_confidence_tier"] = "gold"
    p = irr.precision(sheet, [rec])["all"]
    assert p["source_cwe"]["precision"]["value"] == 1.0
    assert p["sink_cwe"]["precision"]["value"] == 0.0
    assert p["causal"]["precision"]["value"] == 0.0  # "unclear" is not a confirmation


def test_hierarchy_compatible_cwes():
    assert irr.compatible("125", "119")  # out-of-bounds read is-a buffer bounds weakness
    assert not irr.compatible("125", "787")  # read vs write is a real disagreement
    assert irr._answer(" CWE-787 ") == "787" and irr._answer("other:CWE-122") == "122"
