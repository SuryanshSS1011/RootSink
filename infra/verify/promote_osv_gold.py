#!/usr/bin/env python3
"""Promote osv-git records that earned a two-sided execution witness.

The osv-git arm shipped entirely SILVER because these CVEs publish no reproducer and cannot
inherit one from OSS-Fuzz (none of the 159 has an OSS-Fuzz reference). Where the PoC was
recovered from the upstream bug report and the project rebuilt under ASan/UBSan at fix^ and
fix, the record now has exactly what GOLD requires: a sanitizer report at the vulnerable
revision, silence at the patched one, and the patch itself.

Only sanitizer-kind witnesses are promoted. A bare abort is a real crash but a weaker claim,
and hdf5 aborts identically at BOTH revisions, so it earns nothing.
"""
import argparse, json, sys, collections


def main(argv):
    ap = argparse.ArgumentParser()
    ap.add_argument("dataset")
    ap.add_argument("results", help="json: {record_id: result.json contents}")
    ap.add_argument("--out", required=True)
    args = ap.parse_args(argv)

    with open(args.results) as fh:
        res = json.load(fh)
    with open(args.dataset) as fh:
        rows = [json.loads(x) for x in fh if x.strip()]

    st = collections.Counter()
    for r in rows:
        v = res.get(r["id"])
        if not v:
            continue
        if not (v.get("differential_complete") and v.get("witness_kind") == "sanitizer"):
            st["not promotable"] += 1
            continue
        base = f"data/evidence/osv/{r['id']}"
        r["sanitizer_reports"] = [
            {"revision": "vulnerable", "sanitizer": "asan",
             "log_ref": f"{base}/vul.run.log", "triggered": True, "observed_by": "self"},
            {"revision": "patched", "sanitizer": "asan",
             "log_ref": f"{base}/fix.run.log", "triggered": False, "observed_by": "self"},
        ]
        r["differential_complete"] = True
        chain = [c for c in (r.get("chain") or []) if isinstance(c, dict)]
        if chain:
            sig = v.get("vul_sig") or "sanitizer report"
            chain[-1].setdefault("evidence", {})["sanitizer_report_ref"] = sig[:120]
            loc = v.get("sink_location")
            if loc:
                chain[-1]["evidence"]["location"] = loc
        r["dataflow_evidence"] = (
            "EXECUTION witness: the project was rebuilt from source at fix^ and at fix under "
            "ASan+UBSan and the PoC recovered from the upstream bug report was replayed against "
            f"both. {sig} at the vulnerable revision; clean at the patched one. "
            "Neither revision came from a prebuilt image."
        )
        if r.get("patch_diff"):
            r["label_confidence_tier"] = "gold"
            st["PROMOTED to GOLD"] += 1
        else:
            st["witness attached, no patch -> stays SILVER"] += 1

    with open(args.out, "w") as fh:
        for r in rows:
            fh.write(json.dumps(r) + "\n")
    for k, val in st.most_common():
        print(f"  {val:4d}  {k}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
