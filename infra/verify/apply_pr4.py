#!/usr/bin/env python3
"""Apply PREREGISTRATION PR-4: a guard-ablation proof credits the source CWE its guard checks.

For every ARVO-backed record with an ablation result whose control crashed and whose proving
hunk is library source (not a harness, PR-3 I6):

  - the source CWE is derived from the proving hunk (`evidence.source_for_guard`), admissibility
    judged against the NEXT link (the sink, or the intermediate of a length-3 chain);
  - derived: the source link becomes `causally-proven` with that CWE, relabelling the chain if it
    differs (logged, MITRE grounding recomputed);
  - not derived (undetermined or inadmissible): the proof is kept as `guard_site_proof`, crediting
    no CWE, and a proof attached under the old rule is moved there too.

Then every touched record is re-tiered by chainforge.integrity. Results are taken from the newest
batch that produced a verdict for an id. Idempotent.

Usage: apply_pr4.py <ablation_out_dir>... [--release data/release]
"""

from __future__ import annotations

import argparse
import collections
import json
import shutil
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))
from chainforge.cwe import is_admissible_edge  # noqa: E402
from chainforge.evidence import (  # noqa: E402
    HUNK_NARRATIVE,
    HUNK_SITE_STAGE_NO_CWE,
    chain_kind,
    classify_link,
    floor,
    guard_site,
    hunk_site_note_no_cwe,
    hunk_test_narrative,
    hunk_test_note,
    is_hunk_test_note,
    is_non_guard_path,
    site_kind,
    source_for_guard,
)
from chainforge.integrity import (  # noqa: E402
    _CRASHED,
    gold_violations,
    kasan_same_bug,
    ran_clean,
    tier_for,
)
from chainforge.mitre_chains import CWE_CATALOG_VERSION, classify_chain  # noqa: E402

# apply_causal_proof.py (pre-PR-4) appended this on every run; it must say only what the record's
# proof currently establishes, so it is removed and re-written from the proof itself.
_NARRATIVE = HUNK_NARRATIVE


def sync_narrative(r: dict) -> None:
    """Withdraw an unlogged proof (PR-4 addendum) and make dataflow_evidence match the proof."""
    ev = r["chain"][0].setdefault("evidence", {})
    cp = ev.get("causal_proof")
    if cp and not cp.get("control_log"):
        ev.pop("causal_proof")
        ev.pop("minimal_guard_patch", None)
        ev["guard_site_proof"] = {
            **cp,
            "source_cwe": None,
            "why": "PR-4 addendum: no archived log showing the guard-only run executed",
        }
        ev["patch_hunk_ref"] = hunk_site_note_no_cwe(cp.get("file"))
        cp = None
    text = _NARRATIVE.sub("", r.get("dataflow_evidence") or "").rstrip()
    if cp:
        text += hunk_test_narrative(cp.get("file"))
    r["dataflow_evidence"] = text or None


def load_results(dirs: list[str]) -> dict[str, tuple[dict, Path]]:
    """id -> (result, dir). Later dirs win, but only with a verdict (control ran)."""
    out: dict[str, tuple[dict, Path]] = {}
    for d in dirs:
        for rj in Path(d).glob("*/result.json"):
            res = json.loads(rj.read_text())
            if res.get("control") == "crashed" or rj.parent.name not in out:
                out[rj.parent.name] = (res, rj.parent)
    return out


def archive_extra_boots(d: Path, hunk: str, arch: Path) -> dict:
    """Kernel hunk tests since release 1.0.5 keep every boot's log (`<hunk>.bootN.log`); archive
    them next to the first, so a proof that needed N clean boots shows all N."""
    extra = sorted(d.glob(f"{hunk}.boot*.log"))
    for b in extra:
        shutil.copy(b, arch / f"guard_only.{b.name.removeprefix(hunk + '.')}")
    if not extra:
        return {}
    return {
        "guard_only_boot_logs": [
            str(arch / f"guard_only.{b.name.removeprefix(hunk + '.')}") for b in extra
        ]
    }


def mitre(chain: list[int]) -> dict:
    cp = classify_chain(chain)
    return {
        "catalog_version": CWE_CATALOG_VERSION,
        "all_recognized": cp.all_mitre_recognized,
        "any_catalog_only": cp.any_catalog_only,
        "edges": [
            {"src": e.src, "dst": e.dst, "kind": e.kind, "detail": e.detail} for e in cp.edges
        ],
    }


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("ablation_dirs", nargs="+")
    ap.add_argument("--release", default="data/release")
    args = ap.parse_args(argv)
    rel = Path(args.release)
    with open(rel / "dataset.jsonl") as fh:
        rows = [json.loads(line) for line in fh]
    results = load_results(args.ablation_dirs)
    log, stats = [], collections.Counter()
    before = {r["id"]: (r["chain"][0]["cwe_id"], r["chain"][0].get("evidence_kind")) for r in rows}

    def proofs(r: dict) -> dict:
        ev = r["chain"][0].get("evidence") or {}
        return {
            k: json.dumps(ev.get(k), sort_keys=True)
            for k in ("causal_proof", "guard_site_proof", "unverified_test")
        }

    had = {r["id"]: proofs(r) for r in rows}

    for r in rows:
        # ARVO results are keyed by OSS-Fuzz id, kernel ones (cse-kvm/kablate_kvm.sh) by extid.
        keys = [
            a.removeprefix("OSS-Fuzz-").removeprefix("syzbot-")
            for a in r.get("aliases") or []
            if a.startswith(("OSS-Fuzz-", "syzbot-"))
        ]
        aid = next((k for k in keys if k in results), None)
        if not aid:
            continue
        res, d = results[aid]
        g = res.get("guard_hunk")
        if res.get("control") != "crashed" or not g or is_non_guard_path(g.get("file") or ""):
            continue
        hunk_path = d / "hunks" / g["hunk"]
        if not hunk_path.is_file():
            stats["proving hunk file missing"] += 1
            continue
        hunk = hunk_path.read_text(errors="replace")
        # PR-4 addendum: the proof stands only on archived logs - control crashed, guard-only run
        # executed the input with no crash. Without them the site is kept, no CWE credited.
        glog, clog = d / f"{g['hunk']}.log", d / "control.log"
        logged = (
            glog.is_file()
            and clog.is_file()
            and ran_clean(glog.read_text(errors="replace"))
            and _CRASHED.search(clog.read_text(errors="replace"))
        )
        # A kernel control must crash with syzbot's bug (PR-6), not any KASAN report: a proof
        # that silences another bug says nothing about this record's source.
        kdiff = Path("data/evidence/kernel") / aid / "differential.json"
        if logged and f"syzbot-{aid}" in r["aliases"]:
            sig = json.loads(kdiff.read_text()).get("expected_signature") if kdiff.is_file() else ""
            if not (sig and kasan_same_bug(clog.read_text(errors="replace").splitlines(), sig)):
                ev = r["chain"][0].setdefault("evidence", {})
                for k in ("causal_proof", "guard_site_proof", "minimal_guard_patch"):
                    ev.pop(k, None)
                log.append({"id": r["id"], "op": "PR4-reject", "why": f"control is not {sig}"})
                stats["kernel control crashed with a different bug (no proof)"] += 1
                continue
        src = r["chain"][0]
        ev = src.setdefault("evidence", {})
        nxt = r["chain"][1]["cwe_id"]
        derived = source_for_guard(hunk, nxt, is_admissible_edge) if logged else None
        # PR-4 for origin roots (2026-10-21): a witnessed origin keeps its site and its CWE; a
        # conflicting guard class is recorded, never relabelled.
        # From 1.0.7 a moved origin root sits at its tested site and keeps the origin in
        # evidence.origin_site; it is still a witnessed origin for this rule.
        origin = site_kind(src, r.get("provenance") or "") == "origin-site" or bool(
            ev.get("origin_site")
        )
        conflict = origin and derived is not None and derived != src["cwe_id"]
        proof = {
            "method": "guard-ablation",
            "hunk": g["hunk"],
            "file": g.get("file"),
            "added_lines": g.get("added"),
            "control": "crashed",
            "with_guard_only": "clean",
            "arvo_id": aid,
            # Hunk tests since 2026-10-22 apply at fuzz 0 and say so in result.json.
            **({"application": "strict"} if res.get("fuzz") == 0 else {}),
            # Release 1.0.3, item 2: a one-hunk fix tested by the scorer's own runs says so.
            **({"basis": res["basis"]} if res.get("basis") else {}),
        }
        if derived is None and not logged:
            # PR-4 addendum, held for site proofs too (2026-10-24): without archived logs that
            # show the control crashing and the guard-only run executing cleanly, nothing is
            # tested. The result waits in unverified_test for a re-run with logs.
            ev.pop("causal_proof", None)
            ev.pop("minimal_guard_patch", None)
            old = ev.pop("guard_site_proof", None)
            ev.setdefault("unverified_test", {})["guard_site_proof"] = {
                **(old or proof),
                "why_unverified": "no archived log showing the guard-only run executed",
            }
            stats["site proof unverified (no logs)"] += 1
            continue
        if derived is None or conflict:
            ev.pop("causal_proof", None)
            ev.pop("minimal_guard_patch", None)
            arch = Path("data/evidence/ablation") / aid
            arch.mkdir(parents=True, exist_ok=True)
            shutil.copy(clog, arch / "control.log")
            shutil.copy(glog, arch / "guard_only.log")
            proof |= archive_extra_boots(d, g["hunk"], arch)
            (ev.get("unverified_test") or {}).pop("guard_site_proof", None)
            if "unverified_test" in ev and not ev["unverified_test"]:
                ev.pop("unverified_test")
            ev["guard_site_proof"] = {
                **proof,
                "control_log": str(arch / "control.log"),
                "guard_only_log": str(arch / "guard_only.log"),
                "source_cwe": None,
                "why": (
                    f"PR-4 for origin roots: the guard names CWE-{derived}, the witnessed origin "
                    f"CWE-{src['cwe_id']}; not relabelled"
                    if conflict
                    else "PR-4: guard class undetermined or not admissible"
                    if logged
                    else "PR-4 addendum: no archived log showing the guard-only run executed"
                ),
            }
            # The site is proven even when the CWE is not: localise the link if it has no site.
            site = guard_site(hunk, g.get("file") or "")
            if site and origin:
                ev["tested_site"] = site
            elif site and not (ev.get("location") or {}).get("file"):
                ev["location"] = {**site, "stage": HUNK_SITE_STAGE_NO_CWE}
            if is_hunk_test_note(ev.get("patch_hunk_ref")):
                ev["patch_hunk_ref"] = hunk_site_note_no_cwe(g.get("file"))
            stats["site proof only (no CWE credited)"] += 1
        else:
            ev.pop("guard_site_proof", None)
            (ev.get("unverified_test") or {}).pop("guard_site_proof", None)
            if "unverified_test" in ev and not ev["unverified_test"]:
                ev.pop("unverified_test")
            arch = Path("data/evidence/ablation") / aid
            arch.mkdir(parents=True, exist_ok=True)
            shutil.copy(clog, arch / "control.log")
            shutil.copy(glog, arch / "guard_only.log")
            proof |= archive_extra_boots(d, g["hunk"], arch)
            ev["causal_proof"] = {
                **proof,
                "source_cwe": derived,
                "rule": "PR-4",
                "control_log": str(arch / "control.log"),
                "guard_only_log": str(arch / "guard_only.log"),
            }
            ev["minimal_guard_patch"] = hunk
            if site := guard_site(hunk, g.get("file") or ""):
                if origin:
                    ev["tested_site"] = site
                else:
                    ev["location"] = site
            ev["patch_hunk_ref"] = hunk_test_note(g.get("file"), g.get("added"), derived)
            if derived != src["cwe_id"]:
                log.append(
                    {
                        "id": r["id"],
                        "op": "PR4-relabel-source",
                        "from": src["cwe_id"],
                        "to": derived,
                        "hunk": g.get("file"),
                    }
                )
                stats[f"relabel CWE-{src['cwe_id']} -> CWE-{derived}"] += 1
                src["cwe_id"] = derived
                cwes = [c["cwe_id"] for c in r["chain"]]
                r["chain_string"] = "->".join(f"CWE-{c}" for c in cwes)
                r["mitre_chain"] = mitre(cwes)
                r["chain_kind"] = chain_kind(cwes)
            stats[f"causally proven CWE-{derived}"] += 1
    # Every record, not only those with a result here: an unlogged proof is withdrawn wherever it
    # sits, and the narrative and tier follow the proof.
    for r in rows:
        src = r["chain"][0]
        had_proof = bool((src.get("evidence") or {}).get("causal_proof"))
        sync_narrative(r)
        if had_proof and not src["evidence"].get("causal_proof"):
            stats["unlogged proof withdrawn"] += 1
        for link in r["chain"]:
            link["evidence_kind"] = str(classify_link(link.get("evidence")))
        r["evidence_floor"] = str(floor(r))
        if proofs(r) != had[r["id"]]:  # a hunk-test proof attached, moved or withdrawn
            ev = src.get("evidence") or {}
            kind = next(
                (k for k in ("causal_proof", "guard_site_proof") if ev.get(k)),
                "unverified_test" if ev.get("unverified_test") else "none",
            )
            p = ev.get(kind) if kind in ("causal_proof", "guard_site_proof") else {}
            log.append(
                {
                    "id": r["id"],
                    "op": "PR4-hunk-test",
                    "rule": "PR-4",
                    "proof": kind,
                    **({"basis": p["basis"]} if (p or {}).get("basis") else {}),
                }
            )
        if (src["cwe_id"], src["evidence_kind"]) != before[r["id"]]:
            log.append(
                {
                    "id": r["id"],
                    "op": "PR4-source",
                    "from": list(before[r["id"]]),
                    "to": [src["cwe_id"], src["evidence_kind"]],
                }
            )

        if r["label_confidence_tier"] in ("gold", "gold-upstream", "silver"):
            v = gold_violations(r, Path("."))
            new = tier_for(r, v)
            if new != r["label_confidence_tier"]:
                log.append(
                    {
                        "id": r["id"],
                        "op": "PR4-retier",
                        "from": r["label_confidence_tier"],
                        "to": new,
                        "rules": v,
                    }
                )
                stats[f"retier {r['label_confidence_tier']} -> {new}"] += 1
                r["label_confidence_tier"] = new
            if v:
                r["gold_contract_gaps"] = v
            else:
                r.pop("gold_contract_gaps", None)

    with open(rel / "dataset.jsonl", "w") as fh:
        fh.writelines(json.dumps(r) + "\n" for r in rows)
    with open(rel / "corrections_changelog.jsonl", "a") as fh:
        fh.writelines(json.dumps(e) + "\n" for e in log)
    for k, n in sorted(stats.items()):
        print(f"{n:6d}  {k}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
