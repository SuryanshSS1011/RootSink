"""Promote race-arm records to GOLD for CVEs we replayed and witnessed KASAN fire ourselves.

Auto-discovers race_gold/<cve>/witness.json entries with status=kasan_fired, pairs each with its
archived KASAN report + the fix patch, and rewrites the matching record in race_records.jsonl to
GOLD: adds a triggered SanitizerReport (our own KASAN observation under SMP) + the fix patch_diff.
This is an EXECUTION witness we produced, not a re-tier of the NVD label. Idempotent.
"""

from __future__ import annotations

import glob
import json
import os
import shutil
import sys

CF = os.environ.get("CF_HOME") or sys.exit("set CF_HOME to the chainforge working directory")
sys.path.insert(0, f"{CF}/repo/src")
from chainforge.schema import ChainRecord, SanitizerReport  # noqa: E402

# CVE -> fix patch filename under race_gold_witness/. Promote only if BOTH a kasan_fired witness
# AND the fix patch exist (GOLD needs patch_diff).
FIX_PATCH = {
    "CVE-2022-45884": "fix_627bb528.patch",
    "CVE-2022-45885": "fix_45885.patch",
    "CVE-2022-45886": "fix_45886.patch",
}
WDIR = f"{CF}/race_gold_witness"
RECORDS = f"{CF}/race_records.jsonl"


def _read(path: str | None) -> str | None:
    if not path or not os.path.exists(path):
        return None
    with open(path) as fh:
        return fh.read()


def discover() -> dict[str, dict]:
    """CVE -> {witness, patch_text, report_ref} for every kasan_fired witness with a fix patch."""
    found: dict[str, dict] = {}
    for wpath in sorted(glob.glob(f"{CF}/race_gold/*/witness.json")):
        try:
            with open(wpath) as fh:
                wj = json.load(fh)
        except (OSError, ValueError):
            continue
        if wj.get("status") != "kasan_fired":
            continue
        cve = wj.get("cve", "").upper()
        patch = _read(f"{WDIR}/{FIX_PATCH.get(cve, '')}")
        if not patch:
            print(f"SKIP {cve}: kasan_fired but no fix patch ({FIX_PATCH.get(cve)})")
            continue
        # archive the per-cve report into the witness dir so records reference a stable path
        src_report = os.path.join(os.path.dirname(wpath), "kasan_report.log")
        ref_name = f"kasan_{cve.lower().replace('-', '_')}.log"
        if os.path.exists(src_report):
            os.makedirs(WDIR, exist_ok=True)
            shutil.copy(src_report, f"{WDIR}/{ref_name}")
        found[cve] = {
            "witness": wj,
            "patch": patch,
            "report_ref": f"race_gold_witness/{ref_name}",
            "cause": wj.get("cause_commit", "v6.0"),
        }
    return found


def main() -> None:
    with open(RECORDS) as fh:
        records = [json.loads(x) for x in fh if x.strip()]

    fired = discover()
    if not fired:
        print("no kasan_fired witnesses with a fix patch found; nothing to promote")
        return
    print("promotable (kasan_fired + patch):", sorted(fired))

    promoted = 0
    out = []
    for r in records:
        cve = next((a for a in r.get("aliases", []) if a.upper() in fired), None)
        if not cve:
            out.append(r)
            continue
        info = fired[cve.upper()]
        wj = info["witness"]
        ktype = wj.get("kasan_type", "KASAN: use-after-free")
        r["label_confidence_tier"] = "gold"
        r["patch_diff"] = info["patch"]
        r["sanitizer_reports"] = [
            SanitizerReport(
                revision="vulnerable",
                sanitizer="kasan",
                log_ref=info["report_ref"],
                triggered=True,
            ).model_dump()
        ]
        r["dataflow_evidence"] = (
            f"EXECUTION witness: replayed a stripped reproducer of {cve} under KVM+KASAN with "
            f"real SMP on a modern vulnerable kernel ({info['cause']}); observed {ktype} in the "
            f"dvb-core open-vs-teardown path (CWE-362 race -> CWE-416 UAF) ourselves. Not a "
            f"re-tier of the NVD label."
        )
        rec = ChainRecord.model_validate(r)  # enforces GOLD invariants
        out.append(json.loads(rec.model_dump_json()))
        promoted += 1
        print(f"PROMOTED {r['id']} ({cve}) -> GOLD")

    if promoted:
        with open(RECORDS, "w") as fh:
            for r in out:
                fh.write(json.dumps(r) + "\n")
    print(f"\ndone: promoted {promoted} race record(s) to GOLD")


if __name__ == "__main__":
    main()
