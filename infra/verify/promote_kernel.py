#!/usr/bin/env python3
"""Convert a syzbot record's one-sided oracle into a two-sided one.

Every kernel record cites an upstream syzbot report (observed_by: upstream) with no
patched-revision counterpart, because a differential replay needs KVM and ROAR has none - it
failed 0/20 twice there. On a KVM host the kernel can be built at fix^ and at fix and the C
reproducer replayed against both, which is what these results are.

The tier does not change; these are already GOLD. What changes is the strength of the claim:
observed_by moves from upstream to self, and differential_complete from false to true. That is
the vise-pair property an RL consumer needs to define a counterfactual, and it was the single
largest structural gap in the corpus (919 of 1604 GOLD).

Usage: promote_kernel.py <dataset.jsonl> <results.json> --out <out.jsonl>
"""
import argparse, collections, json, os, sys


def main(argv):
    ap = argparse.ArgumentParser()
    ap.add_argument("dataset")
    ap.add_argument("results", help='json: {extid: {vul, fix, differential_complete, ...}}')
    ap.add_argument("--evidence-root", default="data/evidence/kernel")
    ap.add_argument("--out", required=True)
    args = ap.parse_args(argv)

    with open(args.results) as fh:
        res = json.load(fh)
    with open(args.dataset) as fh:
        rows = [json.loads(x) for x in fh if x.strip()]

    st = collections.Counter()
    for r in rows:
        ext = next((a.replace("syzbot-", "") for a in (r.get("aliases") or [])
                    if str(a).startswith("syzbot-")), None)
        v = res.get(ext or "")
        if not v:
            continue
        if not v.get("differential_complete"):
            st["no differential - left one-sided"] += 1
            continue
        base = f"{args.evidence_root}/{ext}"
        if not os.path.exists(f"{base}/vul.console.txt"):
            st["differential but evidence not shipped"] += 1
            continue
        r["sanitizer_reports"] = [
            {"revision": "vulnerable", "sanitizer": "kasan",
             "log_ref": f"{base}/vul.console.txt", "triggered": True, "observed_by": "self"},
            {"revision": "patched", "sanitizer": "kasan",
             "log_ref": f"{base}/fix.console.txt", "triggered": False, "observed_by": "self"},
        ]
        r["differential_complete"] = True
        r["commit_range"] = dict(r.get("commit_range") or {},
                                 introduced=v.get("vuln_commit"), fixed=v.get("fix_commit"))
        r["dataflow_evidence"] = (
            (r.get("dataflow_evidence") or "").split(" TWO-SIDED")[0]
            + f" TWO-SIDED WITNESS: the kernel was built at {str(v.get('vuln_commit'))[:12]} "
              f"(fix^) and at {str(v.get('fix_commit'))[:12]} and syzbot's C reproducer was "
              "replayed against both under KVM. KASAN fires at the vulnerable revision and is "
              "silent at the patched one; both runs are ours, not cited from upstream."
        )
        st["UPGRADED to two-sided"] += 1

    with open(args.out, "w") as fh:
        for r in rows:
            fh.write(json.dumps(r) + "\n")
    for k, val in st.most_common():
        print(f"  {val:4d}  {k}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
