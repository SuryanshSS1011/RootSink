"""PR-9 amendment: location correctness at function granularity, by root site kind."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "infra" / "verify"))
import irr  # noqa: E402

REC = {
    "id": "X",
    "label_confidence_tier": "gold",
    "chain": [
        {
            "cwe_id": 20,
            "role": "source",
            "site_kind": "tested-repair-site",
            "evidence": {"location": {"file": "lib/a.c", "line": 10, "function": "check_len"}},
        },
        {
            "cwe_id": 787,
            "role": "sink",
            "site_kind": "crash-site",
            "evidence": {"location": {"file": "/src/p/lib/b.c", "line": 5, "function": "copy"}},
        },
    ],
}


def row(source_site, roles):
    return {"id": "item-1", "source_site": source_site, "site_roles": roles}


def test_function_match_accepts_a_listed_number_or_other():
    # sites are sorted by (file, line): "/src/p/lib/b.c" < "lib/a.c", so the root is site 2
    assert (
        irr.location_precision([row("2", "")], [REC])["all located roots"]["function_match"][
            "value"
        ]
        == 1.0
    )
    out = irr.location_precision([row("other:lib/a.c:check_len", "")], [REC])
    assert out["tested-repair-site"]["function_match"]["value"] == 1.0
    assert (
        irr.location_precision([row("1", "")], [REC])["tested-repair-site"]["function_match"][
            "value"
        ]
        == 0.0
    )


def test_strict_lenient_and_unclear():
    rep = irr.location_precision([row("2", "1:crash;2:repair")], [REC])["tested-repair-site"]
    assert rep["strict"]["value"] == 0.0 and rep["lenient"]["value"] == 1.0
    un = irr.location_precision([row("unclear", "1:crash")], [REC])["tested-repair-site"]
    assert un["unclear_rate"]["value"] == 1.0 and un["lenient"]["value"] == 0.0
