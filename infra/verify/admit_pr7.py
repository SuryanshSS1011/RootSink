#!/usr/bin/env python3
"""Admit PR-7 mined ARVO cases as records, through the locked rules only, and report the funnel.

PREREGISTRATION PR-7. A selected case becomes a record only if, in order:
  1. reproduced  - our two-sided replay crashed at the vulnerable image and ran clean twice at
                   the fixed one, each patched run demonstrably executing the input (PR-3 I5);
  2. sink        - the vulnerable report is an ASan overflow READ (-> CWE-125) or WRITE
                   (-> CWE-787); nothing else is admitted;
  3. proof       - guard ablation: the unmodified control crashed, one library-source hunk
                   (PR-3 I6) alone ran clean, both with archived logs (PR-4 addendum);
  4. CWE derived - PR-4 derives the root-cause CWE from that guard, admissible before the sink;
  5. admitted    - the chain [derived -> sink] is multi-weakness (PR-5).
An admitted record is then tiered by chainforge.integrity like any other (6. GOLD). Every case
is logged with the step it failed; none is labelled any other way.

Writes the funnel and per-case outcome to data/validation/pr7_<name>_funnel.json, archives the
logs it relies on under data/evidence/, and writes admitted records to the release. Re-runnable:
records an earlier admission made are rebuilt from the current evidence, and any other record
already holding a selected id stops the run. With --retry-infra only the cases the existing funnel
stopped for an infrastructure reason (failed pull, unfetchable diff, a run that never executed) are
re-evaluated, from new runs of those cases; every other case and record is left as it is.

Usage: admit_pr7.py --name pilot --rerun <scored gh dir> --ablation <dir>... --diffs <dir>
       admit_pr7.py --name b2 --retry-infra --rerun <retry dir> --ablation <retry dir> --diffs <dir>
"""

from __future__ import annotations

import argparse
import collections
import contextlib
import hashlib
import json
import re
import shutil
import sqlite3
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))
from chainforge.cwe import is_admissible_edge  # noqa: E402
from chainforge.evidence import (  # noqa: E402
    chain_kind,
    classify_link,
    clip_patch,
    floor,
    guard_site,
    hunk_test_narrative,
    hunk_test_note,
    is_non_guard_path,
    locality,
    source_for_guard,
)
from chainforge.field_policy import canonical_project  # noqa: E402
from chainforge.integrity import (  # noqa: E402
    _CRASHED,
    crash_facts,
    gold_violations,
    ran_clean,
    tier_for,
)

sys.path.insert(0, str(Path(__file__).resolve().parent))
from apply_pr4 import mitre  # noqa: E402
from select_pr7 import stratum  # noqa: E402

STEPS = ["selected", "reproduced", "sink", "proof", "CWE derived", "admitted", "gold"]
_OVERFLOW = re.compile(r"(heap|stack|global|dynamic-stack|container)-buffer-overflow", re.I)
_RUNTIME = re.compile(r"compiler-rt|llvm-project|libfuzzer|sanitizer_common|/asan/|/msan/|/ubsan/")
_FRAME = re.compile(r"#\d+ 0x[0-9a-f]+ in (.*?) (\S+?):(\d+)(?::\d+)?\s*$", re.M)
# The LAST 40 hex digits of a hex run: ARVO glues some pointers (".../glib" + sha gives
# "glibb4c2...", whose leftmost 40 hex digits start one letter early).
_SHA = re.compile(r"[0-9a-f]{40}(?![0-9a-f])")
_MINED = "Mined under PREREGISTRATION PR-7"


def first_project_frame(log: str) -> dict | None:
    for m in _FRAME.finditer(log):
        if not _RUNTIME.search(m.group(2)):
            return {"file": m.group(2), "line": int(m.group(3)), "function": m.group(1)}
    return None


def sink_cwe(log: str) -> int | None:
    """Step 2: the sink CWE from the witnessed report alone."""
    f = crash_facts(log)
    if not f["class"] or not _OVERFLOW.fullmatch(f["class"]):
        return None
    return {"READ": 125, "WRITE": 787}.get(f["access"] or "")


def split_for(project: str, rows: list[dict]) -> str:
    """A project already in the release keeps its fold; a new one goes where the folds are short."""
    canon = canonical_project(project)
    for r in rows:
        if canonical_project(r["project"]) == canon and r.get("split"):
            return r["split"]
    # The same targets as the original split builder (fix_p0_metadata.py: 70/15/15).
    target = {"train": 0.7, "validation": 0.15, "test": 0.15}
    have = collections.Counter(r.get("split") for r in rows)
    n = sum(have[k] for k in target) or 1
    return max(
        target,
        key=lambda k: (target[k] - have[k] / n, hashlib.md5(f"{canon}{k}".encode()).hexdigest()),
    )


# Stops that say nothing about the case: the run, the fetch or the image failed, not the rule.
_INFRA = (
    "no replay result",
    "image pull failed",
    "replay logs missing",
    "fix diff unfetchable",
    "fix diff not fetched",
    "no ablation result",
    "ablation control infrafail",
    "ablation control buildfail",
    "ablation control None",
)


def infra_stop(case: dict) -> bool:
    why = case.get("why_stopped") or ""
    if case["reached"] in ("admitted", "gold"):
        return False
    # A replay whose patched side never ran is an infrastructure outcome, not "not differential".
    return why.startswith(_INFRA) or (why.startswith("replay crashed") and "not_run" in why)


def evaluate(
    aid: str, rerun: Path, abl: dict[str, Path], diffs: Path, sink_fn=None
) -> tuple[str, dict]:
    """The furthest step a case passes, and what it established on the way.

    `sink_fn` maps the vulnerable log to the admitted sink CWE (PR-7: `sink_cwe`; PR-11's index
    class passes its own). Everything else is PR-7's."""
    sink_fn = sink_fn or sink_cwe
    got: dict = {}
    rj = rerun / aid / "result.json"
    if not rj.is_file():
        return "selected", {"why": "no replay result"}
    res = json.loads(rj.read_text())
    got["rerun"] = res
    vul = rerun / aid / "vul.sanitizer.txt"
    fixes = [rerun / aid / f"fix{i}.sanitizer.txt" for i in (1, 2)]
    if res.get("status") == "pull_failed":
        return "selected", got | {"why": "image pull failed (infrastructure; retry)"}
    if not (res.get("vul") == "crashed" and res.get("fix") == ["clean", "clean"]):
        return "selected", got | {"why": f"replay {res.get('vul')} / {res.get('fix')}"}
    if not vul.is_file() or not all(p.is_file() for p in fixes):
        return "selected", got | {"why": "replay logs missing"}
    if not all(ran_clean(p.read_text(errors="replace")) for p in fixes):
        return "selected", got | {"why": "a patched run did not demonstrably execute"}
    vlog = vul.read_text(errors="replace")
    got["sink"] = sink_fn(vlog)
    got["sink_site"] = first_project_frame(vlog)
    if got["sink"] is None:
        return "reproduced", got | {"why": f"sink not admitted: {crash_facts(vlog)}"}

    d = abl.get(aid)
    a = json.loads((d / "result.json").read_text()) if d else None
    g = (a or {}).get("guard_hunk")
    if not a:
        why = "no ablation result" if (diffs / f"{aid}.diff").is_file() else "fix diff unfetchable"
        return "sink", got | {"why": why}
    if a.get("status") == "image_pull_failed":
        return "sink", got | {"why": "image pull failed (infrastructure; retry)"}
    if a.get("status") == "diff_unfetchable":
        return "sink", got | {"why": "fix diff unfetchable"}
    if a.get("status") == "no_code_hunks":
        return "sink", got | {"why": "fix has no source hunk to ablate"}
    if a.get("control") != "crashed":
        return "sink", got | {"why": f"ablation control {a.get('control')}"}
    if not g:
        return "sink", got | {"why": "no single hunk silences the sanitizer"}
    if is_non_guard_path(g.get("file") or ""):
        return "sink", got | {"why": f"proving hunk is harness/test code: {g.get('file')}"}
    glog, clog, hunk = d / f"{g['hunk']}.log", d / "control.log", d / "hunks" / g["hunk"]
    if not (
        glog.is_file()
        and clog.is_file()
        and hunk.is_file()
        and ran_clean(glog.read_text(errors="replace"))
        and _CRASHED.search(clog.read_text(errors="replace"))
    ):
        return "sink", got | {"why": "proof logs missing or guard-only run did not execute"}
    got |= {"guard": g, "dir": d, "hunk": hunk.read_text(errors="replace")}

    got["source"] = source_for_guard(got["hunk"], got["sink"], is_admissible_edge)
    if got["source"] is None:
        return "proof", got | {"why": "PR-4: guard class undetermined or not admissible"}
    if chain_kind([got["source"], got["sink"]]) != "multi-weakness":
        return "CWE derived", got | {"why": f"CWE-{got['source']}->CWE-{got['sink']} not a chain"}
    # The GitHub ablation fetches the diff itself and keeps it beside its result.
    diff = diffs / f"{aid}.diff" if (diffs / f"{aid}.diff").is_file() else d / "fix.diff"
    if not diff.is_file():
        return "CWE derived", got | {"why": "fix diff not fetched"}
    got["patch"] = clip_patch(diff.read_text(errors="replace"), 200_000)
    return "admitted", got


# Every evidence file build() writes, with what it held before (None: absent), so a dry run can
# tier records against their logs and then put the tree back exactly as it was.
_WRITTEN: list[tuple[Path, bytes | None]] = []


def _archive(src: Path, dst: Path) -> None:
    dst.parent.mkdir(parents=True, exist_ok=True)
    _WRITTEN.append((dst, dst.read_bytes() if dst.is_file() else None))
    shutil.copy(src, dst)


def _undo_writes() -> None:
    for dst, old in reversed(_WRITTEN):
        if old is None:
            dst.unlink(missing_ok=True)
            with contextlib.suppress(OSError):
                dst.parent.rmdir()
        else:
            dst.write_bytes(old)
    _WRITTEN.clear()


def build(
    aid: str,
    meta: dict,
    got: dict,
    rerun: Path,
    rows: list[dict],
    sanitizer: str = "asan",
    marker: str = _MINED,
) -> dict:
    ev_dir, ab_dir = Path("data/evidence/arvo") / aid, Path("data/evidence/ablation") / aid
    for name in ("vul", "fix1", "fix2"):
        _archive(rerun / aid / f"{name}.sanitizer.txt", ev_dir / f"{name}.sanitizer.txt")
    g, d = got["guard"], got["dir"]
    _archive(d / "control.log", ab_dir / "control.log")
    _archive(d / f"{g['hunk']}.log", ab_dir / "guard_only.log")
    src_cwe, sink = got["source"], got["sink"]
    same = [
        r for r in rows if canonical_project(r["project"]) == canonical_project(meta["project"])
    ]
    sha = _SHA.search(meta.get("patch_url") or "") or _SHA.search(meta.get("fix_commit") or "")
    source_ev = {
        "dataflow_path": None,
        "sanitizer_report_ref": None,
        "patch_hunk_ref": hunk_test_note(g.get("file"), g.get("added"), src_cwe),
        "causal_proof": {
            "method": "guard-ablation",
            "hunk": g["hunk"],
            "file": g.get("file"),
            "added_lines": g.get("added"),
            "control": "crashed",
            "with_guard_only": "clean",
            "arvo_id": aid,
            "source_cwe": src_cwe,
            "rule": "PR-4",
            "control_log": str(ab_dir / "control.log"),
            "guard_only_log": str(ab_dir / "guard_only.log"),
        },
        "minimal_guard_patch": got["hunk"],
    }
    if site := guard_site(got["hunk"], g.get("file") or ""):
        source_ev["location"] = site
    sink_ev = {"dataflow_path": None, "sanitizer_report_ref": str(ev_dir / "vul.sanitizer.txt")}
    if got["sink_site"]:
        sink_ev["location"] = got["sink_site"] | {"stage": "crash (our vulnerable-side run)"}
    chain = [
        {"cwe_id": src_cwe, "role": "source", "evidence": source_ev},
        {"cwe_id": sink, "role": "sink", "evidence": sink_ev},
    ]
    for link in chain:
        link["evidence_kind"] = str(classify_link(link["evidence"]))
    res = got["rerun"]
    rec = {
        "id": f"CHAINFORGE-{int(aid):010d}",
        "aliases": [f"OSS-Fuzz-{aid}"],
        "project": meta["project"],
        "language": same[0]["language"] if same else {"c": "C"}.get(meta["language"], "C++"),
        "ecosystem": "OSS-Fuzz",
        "commit_range": {"introduced": None, "fixed": sha.group(0) if sha else None},
        "chain": chain,
        "chain_string": f"CWE-{src_cwe}->CWE-{sink}",
        "pov_input": None,
        "docker_image_ref": {
            "vulnerable": res["vul_digest"].replace("n132/arvo@", f"n132/arvo:{aid}-vul@"),
            "patched": res["fix_digest"].replace("n132/arvo@", f"n132/arvo:{aid}-fix@"),
        },
        "sanitizer_reports": [
            {
                "revision": "vulnerable",
                "sanitizer": sanitizer,
                "log_ref": str(ev_dir / "vul.sanitizer.txt"),
                "triggered": True,
                "observed_by": "self",
            }
        ]
        + [
            {
                "revision": "patched",
                "sanitizer": sanitizer,
                "observed_by": "self",
                "triggered": False,
                "log_ref": str(ev_dir / f"fix{i}.sanitizer.txt"),
            }
            for i in (1, 2)
        ],
        "patch_diff": got["patch"],
        "label_confidence_tier": "silver",
        "dataflow_evidence": (
            f"{marker} (execution-first, no static labelling)." + hunk_test_narrative(g.get("file"))
        ),
        "synthetic": False,
        "link_validation": [],
        "mitre_chain": mitre([src_cwe, sink]),
        "related_records": [],
        "license": same[0].get("license") if same else None,
        "provenance": "arvo",
        "datasheet_ref": None,
        "differential_complete": True,
        "split": split_for(meta["project"], rows),
        "eval_stratum": None,
        "chain_kind": chain_kind([src_cwe, sink]),
    }
    rec["locality"] = locality(rec)
    rec["evidence_floor"] = str(floor(rec))
    v = gold_violations(rec, Path("."))
    rec["label_confidence_tier"] = tier_for(rec, v)
    if v:
        rec["gold_contract_gaps"] = v
    return rec


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--name", default="pilot")
    ap.add_argument("--rerun", required=True)
    ap.add_argument("--ablation", nargs="+", required=True)
    ap.add_argument("--diffs", required=True)
    ap.add_argument("--db", default="data/cache/arvo.db")
    ap.add_argument("--release", default="data/release")
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument(
        "--retry-infra",
        action="store_true",
        help="re-evaluate only cases the batch's funnel stopped for an infrastructure reason; "
        "every other case and record is kept as it is",
    )
    args = ap.parse_args(argv)
    rel = Path(args.release)
    sel = json.loads(Path(f"data/validation/pr7_{args.name}.json").read_text())["selected"]
    with open(rel / "dataset.jsonl") as fh:
        rows = [json.loads(line) for line in fh]
    # Only this batch's earlier admissions are rebuilt; other batches' records are left alone.
    # With --retry-infra, only the cases an infrastructure failure stopped are (R10: such a stop
    # is not a negative result, so the case is still owed a verdict).
    kept: dict[str, dict] = {}
    if args.retry_infra:
        old = json.loads(Path(f"data/validation/pr7_{args.name}_funnel.json").read_text())
        kept = {c["localId"]: c for c in old["cases"] if not infra_stop(c)}
    batch = {f"OSS-Fuzz-{c['localId']}" for c in sel if c["localId"] not in kept}
    prior = {
        r["id"]: r
        for r in rows
        if (r.get("dataflow_evidence") or "").startswith(_MINED) and batch & set(r["aliases"])
    }
    rows = [r for r in rows if r["id"] not in prior]
    have = {a for r in rows for a in r["aliases"]}
    # Later --ablation dirs win, except over an earlier verdict (control crashed) they lack: a
    # retry replaces an infrastructure failure even when its own outcome is negative.
    abl: dict[str, Path] = {}

    def crashed(d: Path) -> bool:
        return json.loads((d / "result.json").read_text()).get("control") == "crashed"

    for d in args.ablation:
        for rj in Path(d).glob("*/result.json"):
            old = abl.get(rj.parent.name)
            if old is None or crashed(rj.parent) or not crashed(old):
                abl[rj.parent.name] = rj.parent
    db = sqlite3.connect(f"file:{args.db}?mode=ro", uri=True)
    db.row_factory = sqlite3.Row

    reached, cases, added, log = collections.Counter(), [], [], []
    for s in sel:
        aid = s["localId"]
        if aid in kept:
            cases.append(kept[aid])
            for k in STEPS[: STEPS.index(kept[aid]["reached"]) + 1]:
                reached[k] += 1
            continue
        if f"OSS-Fuzz-{aid}" in have:
            raise SystemExit(f"OSS-Fuzz-{aid} is already in the release")
        step, got = evaluate(aid, Path(args.rerun), abl, Path(args.diffs))
        rec = None
        if step == "admitted":
            meta = dict(db.execute("select * from arvo where localId=?", (aid,)).fetchone())
            rec = build(aid, meta, got, Path(args.rerun), rows + added)
            if rec["label_confidence_tier"] == "gold":
                step = "gold"
            added.append(rec)
            old = prior.pop(rec["id"], None)
            if not old or old["label_confidence_tier"] != rec["label_confidence_tier"]:
                log.append(
                    {"id": rec["id"], "op": "PR7-admit", "tier": rec["label_confidence_tier"]}
                )
        for k in STEPS[: STEPS.index(step) + 1]:
            reached[k] += 1
        cases.append(
            {
                "localId": aid,
                "project": s["project"],
                "stratum": "-".join(stratum(s["crash_type"]) or ("other",)),
                "reached": step,
                "why_stopped": got.get("why"),
                "chain": rec and rec["chain_string"],
                "tier": rec and rec["label_confidence_tier"],
                "gaps": rec and rec.get("gold_contract_gaps"),
            }
        )

    def comp(xs):
        return {
            "projects": len({x["project"] for x in xs}),
            "strata": dict(collections.Counter(x["stratum"] for x in xs)),
            "chains": dict(collections.Counter(x["chain"] for x in xs if x["chain"])),
        }

    funnel = {
        "rule": "PREREGISTRATION PR-7",
        "funnel": {k: reached[k] for k in STEPS},
        "drawn": comp(cases),
        "admitted": comp([c for c in cases if c["reached"] in ("admitted", "gold")]),
        "stopped_at": dict(
            collections.Counter(
                f"{c['reached']}: {(c['why_stopped'] or '').split(':')[0]}"
                for c in cases
                if c["reached"] not in ("admitted", "gold")
            )
        ),
        "cases": cases,
    }
    print(json.dumps({k: funnel[k] for k in ("funnel", "stopped_at")}, indent=1))
    if args.dry_run:
        _undo_writes()
        return 0
    Path(f"data/validation/pr7_{args.name}_funnel.json").write_text(json.dumps(funnel, indent=1))
    # An earlier admission that no longer passes is withdrawn, and says so.
    log += [{"id": i, "op": "PR7-withdraw", "why": "no longer passes PR-7"} for i in prior]
    with open(rel / "dataset.jsonl", "w") as fh:
        fh.writelines(json.dumps(r) + "\n" for r in rows + added)
    with open(rel / "corrections_changelog.jsonl", "a") as fh:
        fh.writelines(json.dumps(e) + "\n" for e in log)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
