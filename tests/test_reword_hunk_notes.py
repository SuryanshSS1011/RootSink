"""reword_hunk_notes.py (release 1.0.9): a hunk test's notes say what it shows, a tested repair
site, and no longer "CAUSALLY PROVEN"."""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "infra" / "verify"))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
import reword_hunk_notes  # noqa: E402

from chainforge.evidence import is_hunk_test_note  # noqa: E402

OLD_REF = (
    "CAUSALLY PROVEN: applying src/a.c (+3 lines) alone to the vulnerable revision silences the "
    "sanitizer; the guard it adds establishes CWE-1284 (PR-4)"
)
OLD_NOTE = (
    "Paired run. CAUSAL PROOF: the unmodified rebuild reproduces the sink; rebuilding with only "
    "the guard hunk in src/a.c applied runs clean on the same input, so the source link is "
    "demonstrated rather than attested."
)


def run(tmp_path, rows):
    (tmp_path / "dataset.jsonl").write_text("".join(json.dumps(r) + "\n" for r in rows))
    reword_hunk_notes.main(["--release", str(tmp_path)])
    out = [json.loads(x) for x in (tmp_path / "dataset.jsonl").read_text().splitlines()]
    log = (tmp_path / "corrections_changelog.jsonl").read_text().splitlines()
    return out, [json.loads(x) for x in log]


def test_notes_are_hedged_and_keep_the_hunk_and_cwe(tmp_path):
    rec = {
        "id": "R1",
        "dataflow_evidence": OLD_NOTE,
        "chain": [{"cwe_id": 1284, "evidence": {"patch_hunk_ref": OLD_REF}}, {"cwe_id": 125}],
    }
    out, log = run(tmp_path, [rec])
    ref = out[0]["chain"][0]["evidence"]["patch_hunk_ref"]
    assert ref.startswith("HUNK TEST: applying src/a.c (+3 lines)") and "PROVEN" not in ref
    assert ref.endswith("names CWE-1284 (PR-4)") and is_hunk_test_note(ref)
    note = out[0]["dataflow_evidence"]
    assert note.startswith("Paired run. HUNK TEST:") and "demonstrated" not in note
    assert note.endswith("which marks a tested repair site.")
    assert [e["op"] for e in log] == ["hunk-note-reworded"]
    out, log = run(tmp_path, out)  # idempotent
    assert len(log) == 1


def test_stage_labels_and_no_cwe_note_are_reworded(tmp_path):
    ref = "guard site proven by ablation (src/b.c); source CWE not established by the guard (PR-4)"
    loc = {"file": "src/b.c", "line": 3, "stage": "proven guard site; CWE not established (PR-4)"}
    ts = {
        "file": "src/c.c",
        "line": 4,
        "stage": "missing guard (vulnerable revision, from the proven hunk)",
    }
    rec = {
        "id": "R2",
        "chain": [
            {
                "evidence": {
                    "patch_hunk_ref": ref,
                    "location": loc,
                    "tested_site": ts,
                    "tested_pair": {"hunks": [{"site": dict(ts)}]},
                }
            },
            {},
        ],
    }
    out, log = run(tmp_path, [rec])
    ev = out[0]["chain"][0]["evidence"]
    assert "proven" not in json.dumps(ev)
    assert ev["location"]["stage"].startswith("tested guard site")
    assert ev["tested_site"]["stage"].startswith("missing guard")
    assert ev["patch_hunk_ref"].startswith("guard site from a successful hunk test (src/b.c)")
    assert len(log) == 1
