#!/usr/bin/env python3
"""Withdraw single-hunk proofs that a strict re-test did not replicate (PREREGISTRATION, strict
re-tests of 2026-10-22).

Input: merged output dirs of the runner's `ablate` workflow run at fuzz 0 (`<dir>/<arvo id>/
result.json`). For each case whose control crashed and where no hunk of the developer's fix
sufficed, every record on that image whose root still carries a proof not marked
`application: strict` has it moved into `evidence.unreplicated_test`; `rebuild_derived.sh` then
restamps the evidence category and re-tiers. A control that did not crash, or a case without a
result (pull or diff failure), changes nothing (R10). Logged as `hunk-test-withdrawn-unreplicated`.
Idempotent.

Usage: withdraw_unreplicated.py <ablate_out_dir>... [--release data/release]
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))
from chainforge.integrity import kasan_same_bug  # noqa: E402

KINDS = ("causal_proof", "guard_site_proof")


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("dirs", nargs="+")
    ap.add_argument("--release", default="data/release")
    args = ap.parse_args(argv)
    failed = set()
    for d in args.dirs:
        for rj in Path(d).glob("*/result.json"):
            res = json.loads(rj.read_text())
            if res.get("control") == "crashed" and not res.get("guard_hunk"):
                # A kernel control must crash with syzbot's bug (PR-6), as for a proof.
                kdiff = Path("data/evidence/kernel") / rj.parent.name / "differential.json"
                clog = rj.parent / "control.log"
                if kdiff.is_file():
                    sig = json.loads(kdiff.read_text()).get("expected_signature") or ""
                    text = clog.read_text(errors="replace").splitlines() if clog.is_file() else []
                    if not (sig and kasan_same_bug(text, sig)):
                        continue
                failed.add(rj.parent.name)
    rel = Path(args.release)
    with open(rel / "dataset.jsonl") as fh:
        rows = [json.loads(line) for line in fh]
    log = []
    for r in rows:
        img = ((r.get("docker_image_ref") or {}).get("vulnerable") or "").split("@")[0]
        aid = img.split(":")[-1].removesuffix("-vul") if img.startswith("n132/arvo:") else None
        # Kernel results are keyed by syzbot extid (cse-kvm/kablate_kvm.sh).
        ext = [a.removeprefix("syzbot-") for a in r.get("aliases") or [] if a.startswith("syzbot-")]
        if aid not in failed and not set(ext) & failed:
            continue
        ev = (r.get("chain") or [{}])[0].setdefault("evidence", {})
        for k in KINDS:
            if ev.get(k) and ev[k].get("application") != "strict":
                ev.setdefault("unreplicated_test", {})[k] = ev.pop(k)
                log.append(
                    {
                        "id": r["id"],
                        "op": "hunk-test-withdrawn-unreplicated",
                        "test": k,
                        "rule": "PR-4/PR-13 strict re-test",
                    }
                )
        # A test already parked as unverified (no logs) and now not replicated is withdrawn too.
        for k, t in list((ev.get("unverified_test") or {}).items()):
            ev.setdefault("unreplicated_test", {})[k] = t
            del ev["unverified_test"][k]
            if not ev["unverified_test"]:
                ev.pop("unverified_test")
            log.append(
                {
                    "id": r["id"],
                    "op": "hunk-test-withdrawn-unreplicated",
                    "test": k,
                    "rule": "PR-4/PR-13 strict re-test",
                }
            )
    with open(rel / "dataset.jsonl", "w") as fh:
        fh.writelines(json.dumps(r) + "\n" for r in rows)
    with open(rel / "corrections_changelog.jsonl", "a") as fh:
        fh.writelines(json.dumps(e) + "\n" for e in log)
    print(f"{len(failed)} cases with no sufficient hunk at fuzz 0; {len(log)} proofs withdrawn")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
