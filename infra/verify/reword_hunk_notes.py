#!/usr/bin/env python3
"""Reword the notes a successful single-hunk test left on a root (release 1.0.9).

Before 1.0.9 such a root's `patch_hunk_ref` began "CAUSALLY PROVEN: ... the guard it adds
establishes CWE-N (PR-4)", and its `dataflow_evidence` ended "CAUSAL PROOF: ... so the source link
is demonstrated rather than attested." Its site's stage said "from the proven hunk" or
"proven guard site", and a test that named no CWE left "guard site proven by ablation". All of
these overstate what one input shows. The hunk suffices for
this input, and its site is a tested repair site, not a proven defect (the paper and the
datasheet say so). This step rewrites both notes to `chainforge.evidence.hunk_test_note` and
`hunk_test_narrative`, changing no label, site, tier or evidence kind. Every record changed is
logged with its rule. Idempotent.

Usage: reword_hunk_notes.py [--release data/release]
"""

from __future__ import annotations

import argparse
import collections
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))
from chainforge.evidence import (  # noqa: E402
    HUNK_SITE_STAGE,
    HUNK_SITE_STAGE_NO_CWE,
    hunk_site_note_no_cwe,
    hunk_test_narrative,
    hunk_test_note,
)

RULE = "hunk-test wording 2026-11-09 (release 1.0.9)"
OLD_REF = re.compile(
    r"^CAUSALLY PROVEN: applying (.+?) \(\+(\d+) lines\) alone to the vulnerable revision "
    r"silences the sanitizer"
    r"(?:; the guard it adds establishes CWE-(\d+) \(PR-4\)| on the same PoV)$"
)
OLD_NO_CWE = re.compile(
    r"^guard site proven by ablation \((.*?)\); source CWE not established by the guard \(PR-4\)$"
)
STAGES = {
    "missing guard (vulnerable revision, from the proven hunk)": HUNK_SITE_STAGE,
    "proven guard site; CWE not established (PR-4)": HUNK_SITE_STAGE_NO_CWE,
}


def _reword_stages(node, path):
    """Reword every site stage under `node` (sites, origins, hunk-pair tests), yielding paths."""
    if isinstance(node, dict):
        if node.get("stage") in STAGES:
            node["stage"] = STAGES[node["stage"]]
            yield f"{path}.stage"
        for k, v in node.items():
            yield from _reword_stages(v, f"{path}.{k}")
    elif isinstance(node, list):
        for v in node:
            yield from _reword_stages(v, f"{path}[]")


OLD_NARRATIVE = re.compile(
    r" ?CAUSAL ?PROOF: the unmodified rebuild reproduces the sink; rebuilding with only the "
    r"guard hunk in (\S+) applied runs clean on the same input, so the source link is "
    r"demonstrated rather than attested\."
)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--release", default="data/release")
    args = ap.parse_args(argv)
    rel = Path(args.release)
    with open(rel / "dataset.jsonl") as fh:
        rows = [json.loads(line) for line in fh]
    log, stats = [], collections.Counter()
    for r in rows:
        fields = []
        for i, inst in enumerate(r.get("chain") or []):
            ev = inst.get("evidence") or {}
            m = OLD_REF.match(ev.get("patch_hunk_ref") or "")
            if m:
                cwe = int(m.group(3)) if m.group(3) else None
                ev["patch_hunk_ref"] = hunk_test_note(m.group(1), m.group(2), cwe)
                fields.append(f"chain[{i}].evidence.patch_hunk_ref")
            m = OLD_NO_CWE.match(ev.get("patch_hunk_ref") or "")
            if m:
                ev["patch_hunk_ref"] = hunk_site_note_no_cwe(m.group(1))
                fields.append(f"chain[{i}].evidence.patch_hunk_ref")
            for path in _reword_stages(ev, f"chain[{i}].evidence"):
                fields.append(path)
        note = r.get("dataflow_evidence")
        if isinstance(note, str) and OLD_NARRATIVE.search(note):
            r["dataflow_evidence"] = OLD_NARRATIVE.sub(
                lambda m: hunk_test_narrative(m.group(1)), note
            )
            fields.append("dataflow_evidence")
        if fields:
            stats[r.get("label_confidence_tier")] += 1
            log.append({"id": r["id"], "op": "hunk-note-reworded", "rule": RULE, "fields": fields})
    with open(rel / "dataset.jsonl", "w") as fh:
        fh.writelines(json.dumps(r) + "\n" for r in rows)
    with open(rel / "corrections_changelog.jsonl", "a") as fh:
        fh.writelines(json.dumps(e) + "\n" for e in log)
    print(dict(stats))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
