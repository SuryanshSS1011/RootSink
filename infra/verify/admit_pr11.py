#!/usr/bin/env python3
"""Admit PR-11 mined ARVO cases (and re-derive contradicted ARVO labels), through the locked
rules only, and report the funnel.

PREREGISTRATION PR-11. Per class:
  msan       [CWE-456 -> CWE-457]: origin site and use site, both from our own MSan report;
  uaf        [CWE-416 -> CWE-125|787]: free site ("freed by" stack) and use site, both from our
             own ASan report (stage-decomposition, PR-5);
  index-oob  [derived -> CWE-119]: PR-7's guard ablation and PR-4 derivation, unchanged
             (admit_pr7.evaluate with the index sink).
  nullderef  [derived -> CWE-476] (PR-16): as index-oob, with a CWE-476 sink when our own ASan
             report is a SEGV at a near-zero address; PR-4 plus PR-16's CWE-252 rule.
Shared: two-sided replay as PR-3 I5; the report must be of the class; every site is the first
frame outside the sanitizer runtime and outside a fuzzing harness or test file; the chain must
be admissible. Tiers come from chainforge.integrity.

`--rederive` evaluates data/validation/pr11_rederive.json instead: each contradicted ARVO record
is judged by the class its own report shows (overflow by PR-7, use-after-free by the rule above).
An admitted chain replaces the record's chain under the same id (`PR11-rederive`, old chain
kept in the log); anything else leaves the record unchanged.

Usage: admit_pr11.py --cls msan --name pilot --rerun <dir> --diffs <dir> [--ablation <dir>...]
       admit_pr11.py --rederive --rerun <dir> --diffs <dir> --ablation <dir>...
"""

from __future__ import annotations

import argparse
import collections
import json
import re
import sqlite3
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent))
import admit_pr7 as p7  # noqa: E402
from apply_pr4 import mitre  # noqa: E402

from chainforge.cwe import is_admissible_edge  # noqa: E402
from chainforge.evidence import (  # noqa: E402
    chain_kind,
    classify_link,
    clip_patch,
    floor,
    is_non_guard_path,
    locality,
    normalize_path,
)
from chainforge.integrity import crash_facts, gold_violations, ran_clean, tier_for  # noqa: E402
from chainforge.mining.msan_assemble import parse_msan_log  # noqa: E402

STEPS = ["selected", "reproduced", "class", "sites", "admitted", "gold"]
STEPS_ABL = ["selected", "reproduced", "class", "proof", "CWE derived", "admitted", "gold"]
MARKER = "Mined under PREREGISTRATION PR-11"
_INDEX = re.compile(r"runtime error: index -?\d+ out of bounds", re.I)
_RUNTIME_LINE = re.compile(r"(\S+?\.(?:c|cc|cpp|cxx|h|hpp)):(\d+)(?::\d+)?: runtime error: index")
_OVERFLOW = re.compile(r"(heap|stack|global|dynamic-stack|container)-buffer-overflow", re.I)


def null_sink(log: str) -> int | None:
    """PR-16: our own ASan SEGV at a near-zero address is a CWE-476 sink; any other SEGV is not."""
    f = crash_facts(log)
    return 476 if f["null_deref"] else None


def index_sink(log: str) -> int | None:
    """PR-11 index class: a UBSan index-out-of-bounds report is a CWE-119 sink."""
    return 119 if _INDEX.search(log) else None


def index_site(log: str) -> dict | None:
    site = p7.first_project_frame(log)
    if site:
        return site
    m = _RUNTIME_LINE.search(log)
    return {"file": m.group(1), "line": int(m.group(2)), "function": None} if m else None


def freed_site(log: str) -> dict | None:
    """First frame outside the sanitizer runtime in ASan's "freed by thread" stack."""
    m = re.search(r"freed by thread [^\n]*\n((?:[ \t]*#\d+[^\n]*\n?)+)", log)
    return p7.first_project_frame(m.group(1)) if m else None


def harness(site: dict | None) -> bool:
    return bool(site) and is_non_guard_path(normalize_path(site.get("file") or ""))


def replay(aid: str, rerun: Path) -> tuple[str, dict]:
    """PR-3 I5, exactly as PR-7 step 1."""
    rj = rerun / aid / "result.json"
    if not rj.is_file():
        return "selected", {"why": "no replay result"}
    res = json.loads(rj.read_text())
    got = {"rerun": res}
    if res.get("status") == "pull_failed":
        return "selected", got | {"why": "image pull failed (infrastructure; retry)"}
    if not (res.get("vul") == "crashed" and res.get("fix") == ["clean", "clean"]):
        return "selected", got | {"why": f"replay {res.get('vul')} / {res.get('fix')}"}
    vul = rerun / aid / "vul.sanitizer.txt"
    fixes = [rerun / aid / f"fix{i}.sanitizer.txt" for i in (1, 2)]
    if not vul.is_file() or not all(p.is_file() for p in fixes):
        return "selected", got | {"why": "replay logs missing"}
    if not all(ran_clean(p.read_text(errors="replace")) for p in fixes):
        return "selected", got | {"why": "a patched run did not demonstrably execute"}
    got["vlog"] = vul.read_text(errors="replace")
    return "reproduced", got


def evaluate_witnessed(aid: str, cls: str, rerun: Path, diffs: Path) -> tuple[str, dict]:
    """MSan and use-after-free: both instances from one report of our own run."""
    step, got = replay(aid, rerun)
    if step != "reproduced":
        return step, got
    log, f = got["vlog"], crash_facts(got["vlog"])
    if cls == "msan":
        if (f["class"] or "").lower() != "use-of-uninitialized-value":
            return "reproduced", got | {"why": f"report is not this class: {f}"}
        p = parse_msan_log(log)
        src, sink, cwes = p.get("source"), p.get("sink"), [456, 457]
        if not src:
            return "class", got | {"why": "no origin block outside the sanitizer runtime"}
        if not sink:
            return "class", got | {"why": "use site not outside the sanitizer runtime"}
        stages = ("origin: uninitialised value created here", "use (MSan SUMMARY)")
    else:
        if (f["class"] or "").lower() != "heap-use-after-free" or f["access"] not in (
            "READ",
            "WRITE",
        ):
            return "reproduced", got | {"why": f"report is not this class: {f}"}
        src, sink = freed_site(log), p7.first_project_frame(log)
        cwes = [416, {"READ": 125, "WRITE": 787}[f["access"]]]
        if not src:
            return "class", got | {"why": "no free site outside the sanitizer runtime"}
        if not sink:
            return "class", got | {"why": "use site not outside the sanitizer runtime"}
        stages = ("free (ASan 'freed by' stack)", "use after free (ASan access stack)")
    for name, site in (("source", src), ("sink", sink)):
        if harness(site):
            return "class", got | {"why": f"{name} site in harness/test code: {site['file']}"}
    if not is_admissible_edge(*cwes):
        return "sites", got | {"why": f"CWE-{cwes[0]}->CWE-{cwes[1]} not admissible"}
    diff = diffs / f"{aid}.diff"
    if not diff.is_file():
        return "sites", got | {"why": "fix diff not fetched"}
    got |= {
        "cwes": cwes,
        "sites": (src, sink),
        "stages": stages,
        "patch": clip_patch(diff.read_text(errors="replace"), 200_000),
    }
    return "admitted", got


def build_witnessed(aid: str, cls: str, meta: dict, got: dict, rerun: Path, rows) -> dict:
    ev_dir = Path("data/evidence/arvo") / aid
    for name in ("vul", "fix1", "fix2"):
        p7._archive(rerun / aid / f"{name}.sanitizer.txt", ev_dir / f"{name}.sanitizer.txt")
    ref = str(ev_dir / "vul.sanitizer.txt")
    (src, sink), (s_stage, k_stage), cwes = got["sites"], got["stages"], got["cwes"]
    san = "msan" if cls == "msan" else "asan"
    chain = [
        {
            "cwe_id": cwes[0],
            "role": "source",
            "evidence": {
                "dataflow_path": None,
                "sanitizer_report_ref": ref,
                "patch_hunk_ref": (
                    "MSan origin block: uninitialised value created here" if cls == "msan" else None
                ),
                "location": src | {"stage": s_stage},
            },
        },
        {
            "cwe_id": cwes[1],
            "role": "sink",
            "evidence": {
                "dataflow_path": None,
                "sanitizer_report_ref": ref,
                "patch_hunk_ref": None,
                "location": sink | {"stage": k_stage},
            },
        },
    ]
    for link in chain:
        link["evidence_kind"] = str(classify_link(link["evidence"]))
    same = [
        r
        for r in rows
        if p7.canonical_project(r["project"]) == p7.canonical_project(meta["project"])
    ]
    sha = p7._SHA.search(meta.get("patch_url") or "") or p7._SHA.search(
        meta.get("fix_commit") or ""
    )
    res = got["rerun"]
    what = (
        "MemorySanitizer with origin tracking: CWE-456 at the origin block's creation site, "
        "CWE-457 at the SUMMARY use site"
        if cls == "msan"
        else "AddressSanitizer use-after-free: CWE-416 at the free site of the 'freed by' stack, "
        f"CWE-{cwes[1]} at the use"
    )
    rec = {
        "id": f"CHAINFORGE-{int(aid):010d}",
        "aliases": [f"OSS-Fuzz-{aid}"],
        "project": meta["project"],
        "language": same[0]["language"] if same else {"c": "C"}.get(meta["language"], "C++"),
        "ecosystem": "OSS-Fuzz",
        "commit_range": {"introduced": None, "fixed": sha.group(0) if sha else None},
        "chain": chain,
        "chain_string": "->".join(f"CWE-{c}" for c in cwes),
        "pov_input": None,
        "docker_image_ref": {
            "vulnerable": res["vul_digest"].replace("n132/arvo@", f"n132/arvo:{aid}-vul@"),
            "patched": res["fix_digest"].replace("n132/arvo@", f"n132/arvo:{aid}-fix@"),
        },
        "sanitizer_reports": [
            {
                "revision": "vulnerable",
                "sanitizer": san,
                "log_ref": ref,
                "triggered": True,
                "observed_by": "self",
            }
        ]
        + [
            {
                "revision": "patched",
                "sanitizer": san,
                "observed_by": "self",
                "triggered": False,
                "log_ref": str(ev_dir / f"fix{i}.sanitizer.txt"),
            }
            for i in (1, 2)
        ],
        "patch_diff": got["patch"],
        "label_confidence_tier": "silver",
        "dataflow_evidence": (
            f"{MARKER} (execution-first, no static labelling). EXECUTION witness (both "
            f"instances, one run of our own): {what}. Clean twice at the fix."
        ),
        "synthetic": False,
        "link_validation": [],
        "mitre_chain": mitre(cwes),
        "related_records": [],
        "license": same[0].get("license") if same else None,
        "provenance": "arvo-msan" if cls == "msan" else "arvo",
        "datasheet_ref": None,
        "differential_complete": True,
        "split": p7.split_for(meta["project"], rows),
        "eval_stratum": None,
        "chain_kind": chain_kind(cwes),
    }
    return finish(rec)


def finish(rec: dict) -> dict:
    rec["locality"] = locality(rec)
    rec["evidence_floor"] = str(floor(rec))
    v = gold_violations(rec, Path("."))
    rec["label_confidence_tier"] = tier_for(rec, v)
    rec.pop("gold_contract_gaps", None)
    if v:
        rec["gold_contract_gaps"] = v
    return rec


def load_ablations(dirs: list[str]) -> dict[str, Path]:
    """As admit_pr7: later dirs win, except over an earlier verdict they lack."""
    abl: dict[str, Path] = {}

    def crashed(d: Path) -> bool:
        return json.loads((d / "result.json").read_text()).get("control") == "crashed"

    for d in dirs:
        for rj in Path(d).glob("*/result.json"):
            old = abl.get(rj.parent.name)
            if old is None or crashed(rj.parent) or not crashed(old):
                abl[rj.parent.name] = rj.parent
    return abl


def evaluate_index(aid, rerun, abl, diffs):
    step, got = p7.evaluate(aid, rerun, abl, diffs, sink_fn=index_sink)
    # PR-7's step names map onto this class's: its "reproduced" stop is a class mismatch here.
    if step == "selected":
        return "selected", got
    if step == "reproduced":
        return "reproduced", got
    if "sink_site" in got and not got["sink_site"]:
        got["sink_site"] = index_site((rerun / aid / "vul.sanitizer.txt").read_text("replace"))
    return {"sink": "class"}.get(step, step), got


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--cls", choices=["msan", "uaf", "index-oob", "nullderef"])
    ap.add_argument("--name", default="pilot")
    ap.add_argument("--rederive", action="store_true")
    ap.add_argument("--rerun", required=True)
    ap.add_argument("--diffs", required=True)
    ap.add_argument("--ablation", nargs="*", default=[])
    ap.add_argument("--db", default="data/cache/arvo.db")
    ap.add_argument("--release", default="data/release")
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args(argv)
    if not args.rederive and not args.cls:
        ap.error("--cls or --rederive")
    rel, rerun, diffs = Path(args.release), Path(args.rerun), Path(args.diffs)
    tag = "rederive" if args.rederive else f"{args.cls}_{args.name}"
    sel = json.loads(Path(f"data/validation/pr11_{tag}.json").read_text())["selected"]
    with open(rel / "dataset.jsonl") as fh:
        rows = [json.loads(line) for line in fh]
    abl = load_ablations(args.ablation)
    db = sqlite3.connect(f"file:{args.db}?mode=ro", uri=True)
    db.row_factory = sqlite3.Row

    by_id = {r["id"]: i for i, r in enumerate(rows)}
    # Earlier admissions of this batch are rebuilt from current evidence (re-runnable).
    batch = {f"OSS-Fuzz-{c['localId']}" for c in sel}
    prior = {
        r["id"]
        for r in rows
        if not args.rederive
        and (r.get("dataflow_evidence") or "").startswith(MARKER)
        and batch & set(r["aliases"])
    }
    rows = [r for r in rows if r["id"] not in prior]
    by_id = {r["id"]: i for i, r in enumerate(rows)}
    have = {a for r in rows for a in r["aliases"]}

    reached, cases, added, log = collections.Counter(), [], [], []
    for s in sel:
        aid = s["localId"]
        meta = dict(db.execute("select * from arvo where localId=?", (aid,)).fetchone())
        if args.rederive:
            cls = (
                "uaf"
                if re.match(r"heap-use-after-free", s["crash_type"], re.I)
                else "overflow"
                if _OVERFLOW.match(s["crash_type"])
                else "other"
            )
        else:
            cls = args.cls
            if f"OSS-Fuzz-{aid}" in have:
                raise SystemExit(f"OSS-Fuzz-{aid} is already in the release")
        steps = STEPS if cls in ("msan", "uaf") else STEPS_ABL
        rec = None
        if cls in ("msan", "uaf"):
            step, got = evaluate_witnessed(aid, cls, rerun, diffs)
            if step == "admitted":
                rec = build_witnessed(aid, cls, meta, got, rerun, rows + added)
        elif cls in ("index-oob", "overflow", "nullderef"):
            if cls == "index-oob":
                step, got = evaluate_index(aid, rerun, abl, diffs)
            elif cls == "nullderef":
                step, got = p7.evaluate(aid, rerun, abl, diffs, sink_fn=null_sink)
                step = {"sink": "class"}.get(step, step)
            else:
                step, got = p7.evaluate(aid, rerun, abl, diffs)
                step = {"sink": "class"}.get(step, step)
            if step == "admitted":
                rec = p7.build(
                    aid,
                    meta,
                    got,
                    rerun,
                    rows + added,
                    sanitizer="ubsan" if cls == "index-oob" else "asan",
                    marker=MARKER,
                )
                rec = finish(rec)
        else:
            step, got = "selected", {"why": f"no PR-11 rule for {s['crash_type'][:40]}"}
        if rec and args.rederive:
            old = rows[by_id[s["id"]]]
            keep = (
                "id",
                "aliases",
                "split",
                "duplicate_group",
                "related_records",
                "fix_date",
                "license",
                "eval_stratum",
                "difficulty_proxy",
                "difficulty_band",
                "sampling_weight",
            )
            new = rec | {k: old[k] for k in keep if k in old}
            new = finish(new)
            rows[by_id[s["id"]]] = new
            # Re-runnable: a record already re-derived to this chain and tier is not logged again.
            same = (old["chain_string"], old["label_confidence_tier"]) == (
                new["chain_string"],
                new["label_confidence_tier"],
            )
            if not same:
                log.append(
                    {
                        "id": s["id"],
                        "op": "PR11-rederive",
                        "old_chain": old["chain_string"],
                        "new_chain": new["chain_string"],
                        "tier": new["label_confidence_tier"],
                    }
                )
            rec = new
        elif rec:
            added.append(rec)
            if rec["id"] not in prior:
                log.append(
                    {"id": rec["id"], "op": "PR11-admit", "tier": rec["label_confidence_tier"]}
                )
            prior.discard(rec["id"])
        if rec and rec["label_confidence_tier"] == "gold":
            step = "gold"
        for k in steps[: steps.index(step) + 1]:
            reached[(cls, k)] += 1
        cases.append(
            {
                "localId": aid,
                "record": s.get("id"),
                "project": s["project"],
                "class": cls,
                "reached": step,
                "why_stopped": got.get("why"),
                "chain": rec and rec["chain_string"],
                "old_chain": s.get("old_chain"),
                "tier": rec and rec["label_confidence_tier"],
                "gaps": rec and rec.get("gold_contract_gaps"),
            }
        )

    funnels = collections.defaultdict(dict)
    for (cls, k), n in reached.items():
        funnels[cls][k] = n
    out = {
        "rule": "PREREGISTRATION PR-11",
        "funnel": {
            cls: {k: f.get(k, 0) for k in (STEPS if cls in ("msan", "uaf") else STEPS_ABL)}
            for cls, f in funnels.items()
        },
        "stopped_at": dict(
            collections.Counter(
                f"{c['class']} {c['reached']}: {(c['why_stopped'] or '').split(':')[0]}"
                for c in cases
                if c["reached"] not in ("admitted", "gold")
            )
        ),
        "admitted": {
            "projects": len({c["project"] for c in cases if c["chain"]}),
            "chains": dict(collections.Counter(c["chain"] for c in cases if c["chain"])),
        },
        "cases": cases,
    }
    print(json.dumps({k: out[k] for k in ("funnel", "stopped_at", "admitted")}, indent=1))
    if args.dry_run:
        p7._undo_writes()
        return 0
    Path(f"data/validation/pr11_{tag}_funnel.json").write_text(json.dumps(out, indent=1))
    log += [{"id": i, "op": "PR11-withdraw", "why": "no longer passes PR-11"} for i in prior]
    with open(rel / "dataset.jsonl", "w") as fh:
        fh.writelines(json.dumps(r) + "\n" for r in rows + added)
    with open(rel / "corrections_changelog.jsonl", "a") as fh:
        fh.writelines(json.dumps(e) + "\n" for e in log)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
