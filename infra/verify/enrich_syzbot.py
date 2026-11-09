#!/usr/bin/env python3
"""Enrich syzbot records with resolvable evidence, per-link localization, and a patch
reference - then promote the ones that meet the GOLD invariant.

These records already carry a triggered KASAN witness; what they lacked was (a) a
`patch_diff`, (b) a `log_ref` a third party could actually dereference, and (c) any
localization. All three are fixable from data syzbot already publishes:

  patch_diff   <- commit_range.fixed rendered as a kernel.org commit URL
  log_ref      <- the crash-report URL harvested from the syzbot API (replaces the opaque
                  "syzbot:<extid>:CrashReport" token, which resolves to nothing)
  location     <- the symbolized alloc/free/use stages parsed out of that report
                  (mining.kasan_report), mapped onto the chain links

Honest scope: this does NOT make the evidence two-sided. A syzbot record is witnessed at
the vulnerable revision only; a 20-case experiment re-fired 0/20 on patched kernels, so
`differential_complete` is set False rather than left implied. Container (ARVO) GOLD keeps
its differential and is marked True.

Usage: enrich_syzbot.py <dataset.jsonl> <kasan_chains.json> --out <out.jsonl>
"""

import argparse
import json
import re
import sys

KERNEL_COMMIT = "https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id={}"
SYZBOT = "https://syzkaller.appspot.com"


def extid_of(rec):
    blob = json.dumps(rec.get("sanitizer_reports") or []) + json.dumps(rec.get("aliases") or [])
    m = re.search(r"syzbot:([0-9a-f]{16,20})", blob)
    return m.group(1) if m else None


def link_locations(chain_cwes, stages):
    """Map KASAN stages onto chain links.

    A KASAN use-after-free is alloc -> free -> use. For a chain like CWE-416 -> CWE-125 the
    416 (the use-after-free itself) is established at the FREE site, and the sink is where
    the invalid access actually faults, i.e. the USE site. `allocated` is retained as
    context on the source link when there is nothing better.
    """
    by_kind = {s["kind"]: s for s in stages if s.get("file")}
    out = {}
    n = len(chain_cwes)
    if n == 0:
        return out
    src_stage = by_kind.get("freed") or by_kind.get("allocated")
    if src_stage:
        out[0] = src_stage
    sink_stage = by_kind.get("use")
    if sink_stage and n > 1:
        out[n - 1] = sink_stage
    # A middle link (len-3) sits between: prefer the allocation as its evidence.
    if n > 2 and by_kind.get("allocated") and by_kind.get("allocated") is not src_stage:
        out[1] = by_kind["allocated"]
    return out


def main(argv):
    ap = argparse.ArgumentParser()
    ap.add_argument("dataset")
    ap.add_argument("chains", help="kasan_chains.json from the harvest")
    ap.add_argument("--out", required=True)
    ap.add_argument(
        "--promote", action="store_true", help="promote to GOLD when the invariant is met"
    )
    args = ap.parse_args(argv)

    with open(args.chains) as fh:
        chains = json.load(fh)
    with open(args.dataset) as fh:
        rows = [json.loads(x) for x in fh if x.strip()]

    stats = {
        "patch_filled": 0,
        "logref_resolvable": 0,
        "localized_links": 0,
        "records_localized": 0,
        "promoted": 0,
        "already_gold": 0,
    }

    for rec in rows:
        prov = rec.get("provenance")
        tier = (rec.get("label_confidence_tier") or "").lower()

        # Container cases carry a real differential; record that explicitly.
        if prov and prov.startswith("arvo"):
            reps = rec.get("sanitizer_reports") or []
            revs = {(r or {}).get("revision"): (r or {}).get("triggered") for r in reps}
            if revs.get("vulnerable") is True and revs.get("patched") is False:
                rec["differential_complete"] = True
            continue
        if prov != "syzbot":
            continue

        ext = extid_of(rec)
        info = chains.get(ext) if ext else None

        # 1. patch reference from the fix commit
        fixed = (rec.get("commit_range") or {}).get("fixed")
        if not rec.get("patch_diff") and fixed:
            rec["patch_diff"] = KERNEL_COMMIT.format(fixed)
            stats["patch_filled"] += 1

        # 2. resolvable log_ref + 3. per-link localization
        if info and not info.get("error"):
            stages = info.get("stages") or []
            if info.get("report_url"):
                for r in rec.get("sanitizer_reports") or []:
                    if str(r.get("log_ref", "")).startswith("syzbot:"):
                        r["log_ref"] = info["report_url"]
                        stats["logref_resolvable"] += 1
            cwes = [c.get("cwe_id") for c in (rec.get("chain") or []) if isinstance(c, dict)]
            locs = link_locations(cwes, stages)
            if locs:
                stats["records_localized"] += 1
                for idx, st in locs.items():
                    link = rec["chain"][idx]
                    ev = link.get("evidence") or {}
                    ev["location"] = {
                        "file": st["file"],
                        "line": st["line"],
                        "function": st.get("function"),
                        "stage": st["kind"],
                    }
                    link["evidence"] = ev
                    stats["localized_links"] += 1

        # syzbot evidence is vulnerable-side only.
        rec["differential_complete"] = False

        # 4. promotion
        if args.promote and tier != "gold":
            triggered = any(
                (r or {}).get("triggered") for r in (rec.get("sanitizer_reports") or [])
            )
            if triggered and rec.get("patch_diff") and not rec.get("synthetic"):
                rec["label_confidence_tier"] = "gold"
                stats["promoted"] += 1
        elif tier == "gold":
            stats["already_gold"] += 1

    with open(args.out, "w") as fh:
        for rec in rows:
            fh.write(json.dumps(rec) + "\n")

    for k, v in stats.items():
        print(f"  {k}: {v}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
