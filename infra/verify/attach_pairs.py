#!/usr/bin/env python3
"""Attach PREREGISTRATION PR-13(a) hunk-pair results as `evidence.tested_pair` on the root.

Input: merged output of the runner's `pairs` workflow (`<out>/<arvo id>/{result.json,
control.log, <a>+<b>.log, proving_pair.patch, hunks/}`). The runner proposes; the verdict is made
here with the release's own rules: the control must have crashed (`integrity._CRASHED`) and the
proving pair's run must have read the input and stayed clean (`integrity.ran_clean`).

For each ARVO-backed record of a case with a verified pair, the root gets
`evidence.tested_pair = {rule, hunks: [{file, added, removed, site}], evidence}`. A pair credits no
CWE, changes no site, `site_kind`, evidence kind or tier (PR-13). The small files are archived
under data/evidence/pairs/<arvo id>/ and the funnel goes to data/validation/pr13_pairs_funnel.json.
Idempotent.

Usage: attach_pairs.py <pairs_out_dir> [--release data/release]
"""

from __future__ import annotations

import argparse
import collections
import json
import shutil
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))
from chainforge.evidence import guard_site  # noqa: E402
from chainforge.integrity import _CRASHED, ran_clean  # noqa: E402

EVID = Path("data/evidence/pairs")


def arvo_id(rec: dict) -> str | None:
    img = ((rec.get("docker_image_ref") or {}).get("vulnerable") or "").split("@")[0]
    return img.split(":")[-1].removesuffix("-vul") if img.startswith("n132/arvo:") else None


def verify(d: Path) -> tuple[str, dict | None]:
    res = json.loads((d / "result.json").read_text())
    if res.get("status") != "ok":
        return f"not run ({res.get('status')})", None
    read = lambda p: p.read_text(errors="replace") if p.is_file() else ""  # noqa: E731
    if not _CRASHED.search(read(d / "control.log")):
        return "control did not crash", None
    pair = res.get("proving_pair")
    if not pair:
        return "no clean pair", None
    a, b = (h["hunk"].removesuffix(".patch") for h in pair)
    if not ran_clean(read(d / f"{a}+{b}.log")):
        return "runner's clean pair not clean by the release rule", None
    hunks = []
    for h in pair:
        text = read(d / "hunks" / h["hunk"])
        hunks.append(
            {
                "file": h["file"],
                "added": h["added"],
                "removed": h["removed"],
                "site": guard_site(text, h["file"]) if text else None,
            }
        )
    return "pair suffices", {
        "rule": "PR-13(a)",
        "n_tried": res.get("n_tried"),
        "hunks": hunks,
        **({"application": "strict"} if res.get("fuzz") == 0 else {}),
    }


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("out_dir")
    ap.add_argument("--release", default="data/release")
    ap.add_argument("--funnel", default="data/validation/pr13_pairs_funnel.json")
    args = ap.parse_args(argv)
    rel, out = Path(args.release), Path(args.out_dir)
    with open(rel / "dataset.jsonl") as fh:
        rows = [json.loads(line) for line in fh]
    verdicts, found = {}, {}
    for d in sorted(p for p in out.iterdir() if (p / "result.json").is_file()):
        verdicts[d.name], pair = verify(d)
        if pair:
            found[d.name] = pair
            dst = EVID / d.name
            dst.mkdir(parents=True, exist_ok=True)
            for f in ("result.json", "proving_pair.patch", "control.log"):
                if (d / f).is_file():
                    shutil.copy(d / f, dst / f)
            a, b = (
                h["hunk"].removesuffix(".patch")
                for h in json.loads((d / "result.json").read_text())["proving_pair"]
            )
            shutil.copy(d / f"{a}+{b}.log", dst / "pair.log")
    log, by_tier = [], collections.Counter()
    for r in rows:
        aid = arvo_id(r)
        if aid not in found or not r.get("chain"):
            continue
        ev = r["chain"][0].setdefault("evidence", {})
        tp = found[aid] | {"evidence": str(EVID / aid)}
        if ev.get("tested_pair") == tp:
            continue
        ev["tested_pair"] = tp
        by_tier[r["label_confidence_tier"]] += 1
        log.append(
            {
                "id": r["id"],
                "op": "tested-pair-attached",
                "rule": "PR-13(a)",
                "files": [h["file"] for h in tp["hunks"]],
            }
        )
    with open(rel / "dataset.jsonl", "w") as fh:
        fh.writelines(json.dumps(r) + "\n" for r in rows)
    with open(rel / "corrections_changelog.jsonl", "a") as fh:
        fh.writelines(json.dumps(e) + "\n" for e in log)
    funnel = {
        "rule": "PREREGISTRATION PR-13(a)",
        "cases": len(verdicts),
        "verdicts": dict(collections.Counter(verdicts.values())),
        "records_with_pair_by_tier": dict(
            collections.Counter(
                r["label_confidence_tier"]
                for r in rows
                if ((r.get("chain") or [{}])[0].get("evidence") or {}).get("tested_pair")
            )
        ),
        "newly_attached": sum(by_tier.values()),
    }
    Path(args.funnel).write_text(json.dumps(funnel, indent=1) + "\n")
    print(json.dumps(funnel))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
