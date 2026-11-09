"""move_origin_roots.py (release 1.0.7): a witnessed origin with a tested hunk takes the tested
site as its root site, keeps its CWE, and gets the origin back if the test is withdrawn."""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "infra" / "verify"))
import move_origin_roots  # noqa: E402

TESTED = {"file": "lib/a.c", "line": 10, "function": "f", "stage": "missing guard (from the hunk)"}
ORIGIN = {"file": "lib/b.c", "line": 5, "function": "g", "stage": "freed"}


def record(rid="R1", proof=True, tested=True):
    ev = {"sanitizer_report_ref": "vul.txt", "location": dict(ORIGIN)}
    if proof:
        ev["guard_site_proof"] = {"hunk": "hunk00.patch", "file": "lib/a.c", "added_lines": 1}
    if tested:
        ev["tested_site"] = dict(TESTED)
    root = {"cwe_id": 416, "role": "source", "evidence": ev, "site_kind": "origin-site"}
    sink = {"cwe_id": 125, "role": "sink", "evidence": {}, "site_kind": None}
    return {"id": rid, "label_confidence_tier": "gold", "chain": [root, sink]}


def run(tmp_path, rows):
    (tmp_path / "dataset.jsonl").write_text("".join(json.dumps(r) + "\n" for r in rows))
    move_origin_roots.main(["--release", str(tmp_path)])
    out = [json.loads(x) for x in (tmp_path / "dataset.jsonl").read_text().splitlines()]
    logf = tmp_path / "corrections_changelog.jsonl"
    log = logf.read_text().splitlines() if logf.exists() else []
    return out, [json.loads(x) for x in log]


def test_origin_with_tested_hunk_moves_and_keeps_cwe(tmp_path):
    out, log = run(tmp_path, [record()])
    root = out[0]["chain"][0]
    assert root["site_kind"] == "tested-repair-site"
    assert root["evidence"]["location"] == TESTED
    assert root["evidence"]["origin_site"] == ORIGIN
    assert "tested_site" not in root["evidence"]
    assert root["cwe_id"] == 416
    assert [e["op"] for e in log] == ["origin-root-moved"]


def test_idempotent(tmp_path):
    run(tmp_path, [record()])
    out, log = run(tmp_path, [json.loads((tmp_path / "dataset.jsonl").read_text())])
    assert out[0]["chain"][0]["evidence"]["location"] == TESTED
    assert [e["op"] for e in log] == ["origin-root-moved"]  # the second run logs nothing


def test_origin_without_placed_tested_site_stays(tmp_path):
    out, _ = run(tmp_path, [record(tested=False)])
    assert out[0]["chain"][0]["evidence"]["location"] == ORIGIN


def test_withdrawn_test_restores_origin(tmp_path):
    out, _ = run(tmp_path, [record()])
    del out[0]["chain"][0]["evidence"]["guard_site_proof"]
    out, log = run(tmp_path, out)
    ev = out[0]["chain"][0]["evidence"]
    assert ev["location"] == ORIGIN and ev["withdrawn_tested_site"] == TESTED
    assert out[0]["chain"][0]["site_kind"] == "origin-site"
    assert log[-1]["op"] == "origin-root-restored"


def test_tested_site_outside_source_is_not_used(tmp_path):
    r = record()
    r["chain"][0]["evidence"]["tested_site"]["file"] = "configure.ac"
    out, log = run(tmp_path, [r])
    assert out[0]["chain"][0]["evidence"]["location"] == ORIGIN
    assert out[0]["chain"][0]["site_kind"] == "origin-site"
    assert log == []
