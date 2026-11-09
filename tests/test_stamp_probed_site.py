"""stamp_probed_site.py (release 1.0.8): path_observed names the site the PR-14 probe ran on."""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "infra" / "verify"))
import stamp_probed_site  # noqa: E402

CASES = {"cases": [{"id": "R1", "arvo": "7", "rf": "b.c", "rl": 5, "rfn": "g"}]}


def run(tmp_path, rows):
    (tmp_path / "supply.json").write_text(json.dumps(CASES))
    (tmp_path / "dataset.jsonl").write_text("".join(json.dumps(r) + "\n" for r in rows))
    stamp_probed_site.main(["--release", str(tmp_path), "--supply", str(tmp_path / "supply.json")])
    return [json.loads(x) for x in (tmp_path / "dataset.jsonl").read_text().splitlines()]


def record(rid="R1", aliases=()):
    root = {
        "evidence": {"location": {"file": "lib/a.c", "line": 10}},
        "path_observed": {"rule": "PR-14", "outcome": "line-hit"},
    }
    return {"id": rid, "aliases": list(aliases), "chain": [root]}


def test_moved_root_keeps_the_site_it_was_probed_at(tmp_path):
    out = run(tmp_path, [record()])
    assert out[0]["chain"][0]["path_observed"]["probed_site"] == {
        "file": "b.c",
        "line": 5,
        "function": "g",
    }
    log = (tmp_path / "corrections_changelog.jsonl").read_text().splitlines()
    assert json.loads(log[0])["current"] is False


def test_renumbered_record_is_matched_by_alias_and_idempotent(tmp_path):
    out = run(tmp_path, [record("R9", ["OSS-Fuzz-7"])])
    assert out[0]["chain"][0]["path_observed"]["probed_site"]["line"] == 5
    run(tmp_path, out)
    assert len((tmp_path / "corrections_changelog.jsonl").read_text().splitlines()) == 1
