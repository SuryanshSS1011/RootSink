#!/usr/bin/env python3
"""Trivial baselines that set each task's floor, learned on the training split and scored on
the test split of GOLD.

1. Root CWE (and the whole chain) from the crash class: predict the training majority for the
   crash's sanitizer class and access (`integrity.crash_facts` on our own vulnerable log). A
   label a model can read off the report it is shown carries little beyond that report.
2. Root-cause localization from the crash: predict that the root is the crashing function (the
   sink's site), scored at function and at file granularity on records whose root is a tested
   repair site (the localization target), and the share whose root function is anywhere on the
   crash stack (`root_site_relation`), an upper bound for a localizer that reads only the stack.

Writes data/validation/baselines.json, which the paper's macros read.

Usage: baselines.py [--release data/release]
"""

from __future__ import annotations

import argparse
import collections
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))
from chainforge.evidence import bare_function, same_file  # noqa: E402
from chainforge.integrity import crash_facts, vul_log  # noqa: E402


def crash_key(r: dict, root: Path) -> str | None:
    p = vul_log(r, root)
    f = crash_facts(p.read_text(errors="replace")) if p else None
    if not f or not f.get("class"):
        return None
    return f"{f['class']}/{f.get('access') or '-'}"


def line_in_report(r: dict, loc: dict) -> bool:
    """Does the localization input's vulnerable-run report name the root's file:line?
    The same test as build_macros' NShownTested."""
    f, ln = (loc.get("file") or "").split("/")[-1], loc.get("line")
    if not (f and ln):
        return False
    for s in r.get("sanitizer_reports") or []:
        p = Path(s.get("log_ref") or "")
        if (
            s.get("revision") == "vulnerable"
            and s.get("witnesses") != "intermediate"
            and s.get("log_ref")
            and p.is_file()
            and f"{f}:{ln}" in p.read_text(errors="replace")
        ):
            return True
    return False


def majority_accuracy(train, test, label) -> dict:
    by = collections.defaultdict(collections.Counter)
    overall = collections.Counter()
    for k, r in train:
        by[k][label(r)] += 1
        overall[label(r)] += 1
    top = overall.most_common(1)[0][0]
    hit = sum((by[k].most_common(1)[0][0] if by[k] else top) == label(r) for k, r in test)
    return {"n": len(test), "correct": hit, "accuracy": round(hit / len(test), 4)}


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--release", default="data/release")
    ap.add_argument("--out", default="data/validation/baselines.json")
    args = ap.parse_args(argv)
    root = Path(".")
    with open(Path(args.release) / "dataset.jsonl") as fh:
        gold = [r for r in map(json.loads, fh) if r["label_confidence_tier"] == "gold"]
    keyed = [(crash_key(r, root), r) for r in gold]
    keyed = [(k, r) for k, r in keyed if k]
    train = [(k, r) for k, r in keyed if r.get("split") == "train"]
    test = [(k, r) for k, r in keyed if r.get("split") == "test"]
    out = {
        "rule": "trivial baselines (train -> test, GOLD)",
        "crash_class_known": len(keyed),
        "root_cwe_from_crash_class": majority_accuracy(
            train, test, lambda r: r["chain"][0]["cwe_id"]
        ),
        "chain_from_crash_class": majority_accuracy(train, test, lambda r: r["chain_string"]),
        "root_cwe_class_from_crash_class": majority_accuracy(
            train, test, lambda r: r["chain"][0].get("cwe_class") or r["chain"][0]["cwe_id"]
        ),
    }
    loc = {"all": [], "test": []}
    for r in gold:
        if r["chain"][0].get("site_kind") != "tested-repair-site":
            continue
        a = (r["chain"][0].get("evidence") or {}).get("location") or {}
        b = (r["chain"][-1].get("evidence") or {}).get("location") or {}
        if not (a.get("file") and b.get("file")):
            continue
        fa, fb = bare_function(a.get("function")), bare_function(b.get("function"))
        row = {
            "file": same_file(a["file"], b["file"]),
            "function": bool(fa and fb and fa == fb and same_file(a["file"], b["file"])),
            "fn_known": bool(fa and fb),
            "stack": r.get("root_site_relation") in ("crash-line", "crash-function", "on-stack"),
            "line_in_report": line_in_report(r, a),
        }
        loc["all"].append(row)
        if r.get("split") == "test":
            loc["test"].append(row)
    for g, rows in loc.items():
        fk = [x for x in rows if x["fn_known"]]
        out[f"localization_crash_site_{g}"] = {
            "n": len(rows),
            "file_accuracy": round(sum(x["file"] for x in rows) / len(rows), 4) if rows else None,
            "n_fn_known": len(fk),
            "function_accuracy": round(sum(x["function"] for x in fk) / len(fk), 4)
            if fk
            else None,
            "on_crash_stack": round(sum(x["stack"] for x in fk) / len(fk), 4) if fk else None,
        }
        # The same baseline without sites whose file:line the input's report already names.
        hid = [x for x in fk if not x["line_in_report"]]
        out[f"localization_crash_site_{g}"] |= {
            "n_line_in_report": sum(x["line_in_report"] for x in fk),
            "n_fn_known_line_hidden": len(hid),
            "function_accuracy_line_hidden": round(sum(x["function"] for x in hid) / len(hid), 4)
            if hid
            else None,
        }
    Path(args.out).write_text(json.dumps(out, indent=1) + "\n")
    print(json.dumps(out, indent=1))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
