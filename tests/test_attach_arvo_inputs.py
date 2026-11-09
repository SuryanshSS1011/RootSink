"""attach_arvo_inputs.py (release 1.0.9): an ARVO record points at its shipped crashing input,
only when the copy came from the image the record pins and its bytes are unchanged."""

import hashlib
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "infra" / "verify"))
import attach_arvo_inputs  # noqa: E402

DIG = "sha256:" + "a" * 64


def setup(tmp_path, data=b"crash", listed_sha=None, digest=DIG):
    poc = tmp_path / "data/evidence/arvo/123/poc"
    poc.parent.mkdir(parents=True)
    poc.write_bytes(data)
    sha = listed_sha or hashlib.sha256(data).hexdigest()
    (tmp_path / "data/evidence/arvo_inputs.jsonl").write_text(
        json.dumps({"arvo": "123", "digest": digest, "sha256": sha}) + "\n"
    )
    rel = tmp_path / "rel"
    rel.mkdir()
    rec = {
        "id": "R1",
        "label_confidence_tier": "gold",
        "pov_input": None,
        "docker_image_ref": {"vulnerable": f"n132/arvo:123-vul@{DIG}"},
    }
    (rel / "dataset.jsonl").write_text(json.dumps(rec) + "\n")
    return rel


def run(tmp_path, rel):
    attach_arvo_inputs.main(["--release", str(rel), "--root", str(tmp_path)])
    out = json.loads((rel / "dataset.jsonl").read_text())
    log = (rel / "corrections_changelog.jsonl").read_text().splitlines()
    return out, log


def test_input_attached_once(tmp_path):
    rel = setup(tmp_path)
    out, log = run(tmp_path, rel)
    assert out["pov_input"] == "data/evidence/arvo/123/poc" and len(log) == 1
    out, log = run(tmp_path, rel)
    assert len(log) == 1  # idempotent


def test_altered_copy_or_other_image_is_not_attached(tmp_path):
    rel = setup(tmp_path, listed_sha="0" * 64)
    out, _ = run(tmp_path, rel)
    assert out["pov_input"] is None


def test_copy_from_another_digest_is_not_attached(tmp_path):
    rel = setup(tmp_path, digest="sha256:" + "b" * 64)
    out, _ = run(tmp_path, rel)
    assert out["pov_input"] is None
