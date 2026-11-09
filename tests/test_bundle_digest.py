"""Rebuilding a reproduction bundle offline reproduces the shipped one, digests included."""

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "infra" / "repro"))
import bundle  # noqa: E402


def test_pinned_digest():
    rec = {
        "docker_image_ref": {
            "vulnerable": "n132/arvo:1-vul@sha256:ab",
            "patched": "n132/arvo:1-fix",
        }
    }
    assert bundle.pinned_digest(rec, "vulnerable") == "sha256:ab"
    assert bundle.pinned_digest(rec, "patched") is None
    assert bundle.pinned_digest({}, "vulnerable") is None


def test_offline_rebuild_matches_shipped(tmp_path):
    picked = []
    with open(ROOT / "data" / "release" / "dataset.jsonl") as fh:
        for line in fh:
            rec = json.loads(line)
            if (
                bundle.arvo_id(rec)
                and (ROOT / "infra/repro/bundles" / f"{rec['id']}.json").exists()
            ):
                picked.append(line)
                if len(picked) == 3:
                    break
    assert len(picked) == 3
    ds = tmp_path / "dataset.jsonl"
    ds.write_text("".join(picked))
    out = tmp_path / "bundles"
    facts = ROOT / "infra" / "repro" / "facts_by_id.json"
    bundle.main([str(ds), "--out", str(out), "--facts", str(facts), "--no-digest"])
    for line in picked:
        rid = json.loads(line)["id"]
        shipped = (ROOT / "infra/repro/bundles" / f"{rid}.json").read_text()
        assert (out / f"{rid}.json").read_text() == shipped, rid
