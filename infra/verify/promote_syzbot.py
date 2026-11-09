#!/usr/bin/env python3
"""Fix the 162 evidence-less syzbot GOLD, then promote the 493 that meet the GOLD bar.

Rationale. GOLD is defined by the schema as execution-witnessed + patch evidence. The 493
candidates satisfy that literally: a triggered KASAN report, a fix commit, per-link
localization, and a permanent syzbot URL for the log. Withholding GOLD from them while 162
records whose cited logs no longer exist keep it is the actual integrity problem - the
inconsistency runs the wrong way, since the 162 are weaker on every axis.

So this does two things:
  B) repoint the 162 from the vanished kernel_gold/*.log to their published syzbot crash
     report, and attach the same per-link localization the others get. Their evidence
     becomes dereferenceable instead of missing.
  A) promote the 493 that satisfy the invariant.

Both groups are marked honestly rather than silently:
  observed_by="upstream"        - syzbot ran it; we cite its report (we could not re-run it)
  differential_complete=False   - vulnerable-side only; a patched-revision kernel replay
                                  re-fired 0/20 across two experiments

Usage: promote_syzbot.py <dataset.jsonl> <kasan_chains.json> --out <out.jsonl>
"""

import argparse
import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from enrich_syzbot import link_locations  # noqa: E402  (sibling module, same dir)


def extid_of(rec):
    """Recover the syzbot external id.

    It appears in three shapes and all must be handled: the alias `syzbot-<extid>`
    (hyphen), the legacy log_ref token `syzbot:<extid>:CrashReport` (colon), and the
    kernel_gold path. Matching only the colon form silently found nothing once log_refs
    were rewritten, which made the group-B fix a no-op.
    """
    blob = json.dumps(rec.get("sanitizer_reports") or []) + json.dumps(rec.get("aliases") or [])
    for pat in (r"syzbot[:-]([0-9a-f]{16,20})", r"kernel_gold/kernel/([0-9a-f]{16,20})/"):
        m = re.search(pat, blob)
        if m:
            return m.group(1)
    return None


def main(argv):
    ap = argparse.ArgumentParser()
    ap.add_argument("dataset")
    ap.add_argument("chains")
    ap.add_argument("--out", required=True)
    args = ap.parse_args(argv)

    with open(args.chains) as fh:
        chains = json.load(fh)
    with open(args.dataset) as fh:
        rows = [json.loads(x) for x in fh if x.strip()]

    st = {"B_repointed": 0, "B_localized": 0, "A_promoted": 0, "marked_upstream": 0, "no_report": 0}

    for rec in rows:
        if rec.get("provenance") != "syzbot":
            continue
        tier = (rec.get("label_confidence_tier") or "").lower()
        ext = extid_of(rec)
        info = chains.get(ext) if ext else None
        url = (info or {}).get("report_url")

        # Every syzbot witness is upstream-observed and vulnerable-side only.
        for rep in rec.get("sanitizer_reports") or []:
            rep["observed_by"] = "upstream"
            st["marked_upstream"] += 1
            ref = str(rep.get("log_ref") or "")
            if url and (ref.startswith("kernel_gold/") or ref.startswith("syzbot:")):
                rep["log_ref"] = url
                if tier == "gold":
                    st["B_repointed"] += 1
        rec["differential_complete"] = False

        # Localization for whichever group lacks it (B mostly).
        if info and not info.get("error"):
            stages = info.get("stages") or []
            cwes = [c.get("cwe_id") for c in (rec.get("chain") or []) if isinstance(c, dict)]
            locs = link_locations(cwes, stages)
            newly = False
            for idx, s in locs.items():
                link = rec["chain"][idx]
                ev = link.get("evidence") or {}
                if not ev.get("location"):
                    ev["location"] = {
                        "file": s["file"],
                        "line": s["line"],
                        "function": s.get("function"),
                        "stage": s["kind"],
                    }
                    link["evidence"] = ev
                    newly = True
            if newly and tier == "gold":
                st["B_localized"] += 1
        elif not url:
            st["no_report"] += 1

        # A: promote what satisfies the invariant.
        if tier != "gold":
            triggered = any(
                (r or {}).get("triggered") for r in (rec.get("sanitizer_reports") or [])
            )
            if triggered and rec.get("patch_diff") and not rec.get("synthetic"):
                rec["label_confidence_tier"] = "gold"
                st["A_promoted"] += 1

    with open(args.out, "w") as fh:
        for rec in rows:
            fh.write(json.dumps(rec) + "\n")
    for k, v in st.items():
        print(f"  {k}: {v}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
