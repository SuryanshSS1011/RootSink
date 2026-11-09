#!/usr/bin/env python3
"""Emit paper_artifacts/macros.tex: every number the paper cites, as a LaTeX macro.

The paper never types a figure. Each macro is computed here from the release, its changelog and
the archived evidence, so a rebuild after any data change updates the paper with it.

Usage: build_macros.py [--release data/release] [--out paper_artifacts/macros.tex]
"""

from __future__ import annotations

import argparse
import collections
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "infra" / "verify"))
from chainforge.evidence import bare_function, locality  # noqa: E402
from chainforge.field_policy import (  # noqa: E402
    LEAKAGE_FIELDS,
    codebase,
    fixed_after,
    held_out_accuracy,
    localization_eligible,
)
from chainforge.integrity import _CRASHED, ran_clean  # noqa: E402


def in_sample(rows: list[dict], key) -> float:
    groups = collections.defaultdict(collections.Counter)
    for r in rows:
        groups[key(r)][r["chain_string"]] += 1
    return sum(max(c.values()) for c in groups.values()) / len(rows)


def crash_key(r: dict) -> str:
    return next((a for a in r["aliases"] if a.startswith(("OSS-Fuzz-", "syzbot-"))), r["id"])


def attrition(log: list[dict], by_id: dict) -> dict[str, list[tuple[str, int]]]:
    """Reproduction funnels from the latest attempt per record (RustXec-style attrition)."""
    out = {}
    for side, op in (("Kernel", "kernel-differential-attempt"), ("Arvo", "arvo-rerun-attempt")):
        last = {e["id"]: e["status"] for e in log if e.get("op") == op}
        st = collections.Counter(last.values())
        n = len(last)
        if side == "Kernel":
            built = n - st["no_crepro"] - st["repro_cc_failed"] - st["vul_build_failed"]
            fired = built - st["vul_no_repro"] - st["vul_other_bug"]
            two = st["differential"]
            stages = [
                ("attempted", n),
                ("C reproducer available", n - st["no_crepro"]),
                ("built and booted", built),
                ("syzbot bug reproduced at fix^", fired),
                ("clean at fix (two boots)", two),
            ]
        else:
            same = n - st["vul_signature_differs"]
            two = st["differential"] + st["differential (shipped log unparseable)"]
            stages = [
                ("attempted", n),
                ("same crash as shipped (or none shipped)", same),
                ("two-sided: crash, then clean twice", two),
            ]
        two_ids = [i for i, s_ in last.items() if s_.startswith("differential")]
        stages.append(
            (
                "meets the GOLD contract",
                sum(by_id.get(i, {}).get("label_confidence_tier") == "gold" for i in two_ids),
            )
        )
        out[side] = stages
    return out


def entry_routes(rows: list[dict], log: list[dict]) -> dict:
    """Every GOLD record by the route that witnessed it, so Table III's funnels plus the rest sum
    to GOLD; and why two-sided ARVO re-runs miss the contract (a record can miss several rules)."""
    by_id = {r["id"]: r for r in rows}
    last = {}
    for op in ("arvo-rerun-attempt", "kernel-differential-attempt"):
        last[op] = {e["id"]: e["status"] for e in log if e.get("op") == op}
    mined = {i for i, r in by_id.items() if (r.get("dataflow_evidence") or "").startswith("Mined")}
    route = collections.Counter()
    for i, r in by_id.items():
        if r["label_confidence_tier"] != "gold":
            continue
        if r.get("provenance") == "arvo-len3-exec":
            # A PR-10 view copies its length-2 record's evidence, mining marker included; it is
            # its own route so the mined count equals the PR-7 funnel's records.
            route["Views"] += 1
        elif i in mined:
            route["Mined"] += 1
            # PR-7 admits only intervention-derived roots; PR-11 also admits roots its
            # sanitizer witnesses (an MSan origin for CWE-456, a free site for CWE-416).
            if "PR-11" in (r.get("dataflow_evidence") or "")[:40]:
                cwe = r["chain"][0].get("cwe_id")
                route[
                    "MinedMsan" if cwe == 456 else "MinedUaf" if cwe == 416 else "MinedOther"
                ] += 1
            else:
                route["MinedSeven"] += 1
        elif last["kernel-differential-attempt"].get(i) == "differential":
            route["Kernel"] += 1
        elif (last["arvo-rerun-attempt"].get(i) or "").startswith("differential"):
            route["Rerun"] += 1
        else:
            route["FirstPass"] += 1
    # The paper says the routes account for every GOLD record; hold it to that.
    gold_n = sum(r["label_confidence_tier"] == "gold" for r in rows)
    whole = ("Mined", "Kernel", "Rerun", "Views", "FirstPass")
    assert sum(route[k] for k in whole) == gold_n, "GOLD routes do not sum to GOLD"
    assert route["Mined"] == sum(
        route[k] for k in ("MinedSeven", "MinedMsan", "MinedUaf", "MinedOther")
    )
    two = [i for i, st in last["arvo-rerun-attempt"].items() if st.startswith("differential")]
    miss = [by_id[i] for i in two if i in by_id and by_id[i]["label_confidence_tier"] != "gold"]
    gaps = [set(r.get("gold_contract_gaps") or {}) for r in miss]
    return {
        **{
            f"NGoldRoute{k}": route[k]
            for k in (
                "Mined",
                "Kernel",
                "Rerun",
                "Views",
                "FirstPass",
                "MinedSeven",
                "MinedMsan",
                "MinedUaf",
                "MinedOther",
            )
        },
        "NRerunMiss": len(miss),
        "NRerunMissPatch": sum("I3" in g for g in gaps),
        "NRerunMissRoot": sum("I2" in g for g in gaps),
        "NRerunMissSink": sum("I2-sink" in g for g in gaps),
        "NRerunMissMiddle": sum("I4" in g for g in gaps),
    }


def guard_off_stack(gold: list[dict], root: Path = Path(".")) -> dict:
    """Where the proven guard sits relative to the crash stack in our own vulnerable log: a
    localizer or reward that reads only the sanitizer report can find the guard's file there but
    not, half the time, its function."""
    from backfill_functions import frames

    from chainforge.evidence import same_file
    from chainforge.integrity import vul_log

    n = in_file = fn_known = fn_off = 0
    for r in gold:
        src = r["chain"][0]
        ev = src.get("evidence") or {}
        cp = ev.get("causal_proof")
        p = vul_log(r, root) if cp and src.get("evidence_kind") == "causally-proven" else None
        if not p:
            continue
        stack = frames(p.read_text(errors="replace"))
        gfile, gfn = (
            cp.get("file") or (ev.get("location") or {}).get("file"),
            (ev.get("location") or {}).get("function"),
        )
        n += 1
        in_file += any(same_file(f, gfile or "") for _, f, _ in stack)
        if gfn:
            fn_known += 1
            fn_off += not any(fn == gfn for fn, _, _ in stack)
    return {
        "NGuardStack": n,
        "PctGuardFileInStack": pct(in_file / n) if n else "n/a",
        "NGuardFnKnown": fn_known,
        "NGuardFnOffStack": fn_off,
        "PctGuardFnOffStack": pct(fn_off / fn_known) if fn_known else "n/a",
    }


def split_leakage(rows: list[dict]) -> dict:
    """Identity-field leakage on the release's own split: predict each test record's chain as
    the majority among training records with the same identity fields."""
    key = LEAKAGE_FIELDS["project+provenance+ecosystem+language"]
    train = [r for r in rows if r.get("split") == "train"]
    test = [r for r in rows if r.get("split") == "test"]
    if not train or not test:
        return {}
    by = collections.defaultdict(collections.Counter)
    for r in train:
        by[key(r)][r["chain_string"]] += 1
    majority = collections.Counter(r["chain_string"] for r in train)
    hit = sum((by[key(r)] or majority).most_common(1)[0][0] == r["chain_string"] for r in test)
    base = sum(majority.most_common(1)[0][0] == r["chain_string"] for r in test)
    return {"LeakSplit": pct(hit / len(test)), "LeakSplitBaseline": pct(base / len(test))}


def _tree_bytes(d: Path) -> int:
    """Total size of the files under d (the logs of our runs that the release ships)."""
    return sum(f.stat().st_size for f in d.rglob("*") if f.is_file())


def characterize(gold: list[dict]) -> dict:
    """Minor characterization of the multi-weakness GOLD chains (PR-5), for the paper."""
    import re
    import statistics

    mw = [r for r in gold if r.get("chain_kind") == "multi-weakness"]

    def loc(c):
        return (c.get("evidence") or {}).get("location") or {}

    place = collections.Counter(lk for r in mw if (lk := locality(r)) is not None)
    both = sum(place.values())
    known = place["in-function"] + place["cross-function"] + place["cross-file"]
    proven = [r for r in mw if r["chain"][0].get("evidence_kind") == "causally-proven"]
    added = [r["chain"][0]["evidence"]["causal_proof"].get("added_lines") or 0 for r in proven]
    kinds = collections.Counter(
        "catalog-only"
        if any(e["kind"] == "catalog-only" for e in (r.get("mitre_chain") or {}).get("edges", []))
        else "mitre"
        for r in mw
    )
    from backfill_functions import frames
    from stamp_attribution import crash_stack

    from chainforge.integrity import vul_log

    away = here = 0
    off_stack = off_crash_stack = stack_known = 0
    for r in gold:  # every Reproduced-tier record, as the paper states (1.0.5 corrections, item 3)
        sink = loc(r["chain"][-1]).get("file")
        files = re.findall(r"^diff --git a/\S+ b/(\S+)", r.get("patch_diff") or "", re.M)
        if sink and files:
            names = {f.split("/")[-1] for f in files}
            if sink.split("/")[-1] in names:
                here += 1
            else:
                away += 1
            # The same test against every frame of our vulnerable-side report's call stack. ASan
            # names each frame's file; our KASAN traces are unsymbolized, so this is ARVO only.
            p = vul_log(r, Path(".")) if r.get("project") != "linux-kernel" else None
            if p is not None:
                text = p.read_text(errors="replace")
                stack = {(f or "").split("/")[-1] for _, f, _ in frames(text)}
                stack.add(sink.split("/")[-1])
                stack_known += 1
                off_stack += not (names & stack)
                # The crash stack alone (the first run of frames), as root_site_relation uses it;
                # the set above also holds the allocation and free stacks ASan adds for heap errors.
                crash = {(f or "").split("/")[-1] for _, f, _ in frames(crash_stack(text))}
                crash.add(sink.split("/")[-1])
                off_crash_stack += not (names & crash)
    # The paper says no Reproduced-tier record lacks a crash file or a fix, and that the stack
    # test covers every Reproduced-tier ARVO record.
    assert away + here == len(gold), (away + here, len(gold))
    assert stack_known == sum(r.get("project") != "linux-kernel" for r in gold)
    edges = collections.Counter(
        (e["src"], e["dst"], e["kind"])
        for r in mw
        for e in (r.get("mitre_chain") or {}).get("edges", [])
    )
    arms = collections.Counter(r["chain_string"] for r in mw)
    top3 = sum(n for _, n in arms.most_common(3))
    return {
        "NTransitions": len({(a, b) for a, b, _ in edges}),
        "NMitreDirectEdges": len({(a, b) for a, b, k in edges if k == "mitre-direct"}),
        "PctTopThreeArms": pct(top3 / len(mw)) if mw else "n/a",
        "NMultiWeakness": len(mw),
        "NMultiWeaknessBugs": len({r.get("duplicate_group") or r["id"] for r in mw}),
        "NBothLocalized": both,
        "PctCrossFile": pct(place["cross-file"] / both) if both else "n/a",
        "PctSameFileOtherFn": pct(place["cross-function"] / both) if both else "n/a",
        "PctSameFunction": pct(place["in-function"] / both) if both else "n/a",
        "PctSameFileUnknownFn": pct(place["same-file"] / both) if both else "n/a",
        "NPlacementKnown": known,
        "NSameFileUnknownFn": place["same-file"],
        "PctSpanFunctionsKnown": pct((place["cross-function"] + place["cross-file"]) / known)
        if known
        else "n/a",
        "NProvenGuards": len(proven),
        "MedianGuardLines": int(statistics.median(added)) if added else 0,
        "PctGuardsSmall": pct(sum(a <= 3 for a in added) / len(added)) if added else "n/a",
        "PctMitreGrounded": pct(kinds["mitre"] / len(mw)) if mw else "n/a",
        "PctFixAwayFromCrash": pct(away / (away + here)) if away + here else "n/a",
        "NFixAwayBase": away + here,
        "PctFixOffStackArvo": pct(off_stack / stack_known) if stack_known else "n/a",
        "PctFixOffCrashStackArvo": pct(off_crash_stack / stack_known) if stack_known else "n/a",
        "NFixStackBaseArvo": stack_known,
    }


def revision_counts(rows: list[dict], gold: list[dict]) -> dict:
    """Numbers behind the 2026-10-24 revision: PR-17 CWE mapping, fix attribution, where root
    sites sit against the crash, baselines, the PatchBench comparison and image availability."""
    m = {}
    root = [r["chain"][0] for r in gold]
    m["NGoldRootFormerTwenty"] = sum(c.get("cwe_class") == 20 or c["cwe_id"] == 20 for c in root)
    m["NGoldRootQty"] = sum(c["cwe_id"] == 1284 for c in root)
    m["NGoldRootIdx"] = sum(c["cwe_id"] == 1285 for c in root)
    m["NGoldRootClassLevel"] = sum(c["cwe_id"] == 20 for c in root)
    m["PctGoldRootClassLevel"] = pct(m["NGoldRootClassLevel"] / len(gold))
    sink = [r["chain"][-1] for r in gold]
    m["NGoldSinkOneNineteen"] = sum(c["cwe_id"] == 119 for c in sink)
    m["NGoldSinkDirMapped"] = sum(c.get("cwe_class") == 119 and c["cwe_id"] != 119 for c in sink)
    # Multi-weakness chains by what establishes the root CWE.
    mw = [r for r in gold if r.get("chain_kind") == "multi-weakness"]
    m["NMultiOriginUse"] = sum(r["chain"][0]["cwe_id"] == 456 for r in mw)
    m["NMultiCheck"] = len(mw) - m["NMultiOriginUse"]
    m["NMultiCheckGuard"] = sum(
        r["chain"][0]["cwe_id"] != 456 and r["chain"][0].get("cwe_basis") == "guard-class"
        for r in mw
    )
    m["NGoldUnreplicated"] = sum(
        bool((r["chain"][0].get("evidence") or {}).get("unreplicated_test") or {}) for r in gold
    )
    m["NGoldUnverifiedSites"] = sum(
        bool((r["chain"][0].get("evidence") or {}).get("unverified_test") or {}) for r in gold
    )
    # Fix attribution: does the recorded fix alone remove the crash?
    fa = collections.Counter((r.get("fix_attribution") or {}).get("status") for r in gold)
    m["NGoldFixAttr"], m["NGoldNotFixAttr"], m["NGoldFixAttrUnknown"] = (
        fa[True],
        fa[False],
        fa[None],
    )
    m["NGoldFixAttrKernel"] = sum(
        (r.get("fix_attribution") or {}).get("status") is True and r["provenance"] == "syzbot"
        for r in gold
    )
    m["NGoldFixAttrArvo"] = m["NGoldFixAttr"] - m["NGoldFixAttrKernel"]
    core = [
        r
        for r in gold
        if (r.get("fix_attribution") or {}).get("status") is True
        and r.get("evidence_floor") == "execution"
    ]
    m["NCoreFixExec"], m["NCoreProjects"] = len(core), len({codebase(r["project"]) for r in core})
    # Tested repair sites against the crash.
    rel = collections.Counter(
        r.get("root_site_relation")
        for r in gold
        if r["chain"][0].get("site_kind") == "tested-repair-site"
    )
    m["NTestedCrashLine"], m["NTestedCrashFn"] = rel["crash-line"], rel["crash-function"]
    m["NTestedOnStack"], m["NTestedOffStack"] = rel["on-stack"], rel["off-stack"]
    m["NTestedRelKnown"] = sum(v for k, v in rel.items() if k not in (None, "file-only"))
    m["NTestedFileOnly"] = rel["file-only"]  # a file but no function, so not placeable
    assert m["NTestedRelKnown"] + m["NTestedFileOnly"] + rel[None] == sum(rel.values())
    bl = Path("data/validation/baselines.json")  # baselines.py
    if bl.is_file():
        b = json.loads(bl.read_text())
        m["BaseRootOld"] = pct(b["root_cwe_class_from_crash_class"]["accuracy"])
        m["BaseRoot"] = pct(b["root_cwe_from_crash_class"]["accuracy"])
        m["BaseChain"] = pct(b["chain_from_crash_class"]["accuracy"])
        m["BaseTestN"] = b["root_cwe_from_crash_class"]["n"]
        t = b["localization_crash_site_test"]
        m["BaseLocN"], m["BaseLocFn"] = t["n_fn_known"], pct(t["function_accuracy"])
        m["BaseLocNAll"] = t["n"]
        m["BaseLocFile"], m["BaseLocStack"] = pct(t["file_accuracy"]), pct(t["on_crash_stack"])
        if t.get("n_fn_known_line_hidden"):  # without sites whose line the report names
            m["NBaseLocLineShown"] = t["n_line_in_report"]
            m["BaseLocNHidden"] = t["n_fn_known_line_hidden"]
            m["BaseLocFnHidden"] = pct(t["function_accuracy_line_hidden"])
    pbp = Path("data/validation/patchbench_overlap.json")  # compare_patchbench.py
    if pbp.is_file():
        pb = json.loads(pbp.read_text())
        k = pb["by_site_kind"]
        m["NPbTasks"], m["NPbGold"] = pb["tasks_with_gold"], pb["gold_records"]
        m["NPbTested"] = sum(v for x, v in k.items() if x.startswith("tested-repair-site"))
        m["NPbTestedFn"] = k.get("tested-repair-site: function", 0)
        m["NPbTestedFile"] = k.get("tested-repair-site: file", 0)
        m["NPbOrigin"] = sum(v for x, v in k.items() if x.startswith("origin-site"))
        m["NPbOriginOther"] = k.get("origin-site: other file", 0)
        m["NPbTestedAgree"] = m["NPbTestedFn"] + m["NPbTestedFile"]
        m["NPbTestedOther"] = k.get("tested-repair-site: other file", 0)
        m["NPbAnnotated"] = sum(v for x, v in k.items() if x.startswith("annotated-site"))
        m["NPbAnnotatedFn"] = k.get("annotated-site: function", 0)
        # Every overlapping GOLD record is accounted for in the paper's sentence.
        assert m["NPbTested"] + m["NPbOrigin"] + m["NPbAnnotated"] == m["NPbGold"], k
        assert m["NPbTestedFn"] + m["NPbTestedFile"] + m["NPbTestedOther"] == m["NPbTested"], k
        assert m["NPbAnnotatedFn"] == m["NPbAnnotated"], k
        # The paper says "all" origin sites lie in other files; fail loudly if that stops holding.
        assert m["NPbOriginOther"] == m["NPbOrigin"], (m["NPbOriginOther"], m["NPbOrigin"])
    sb = Path("data/validation/scorer_build_failures.json")  # classify_scorer_build_failures.py
    if sb.is_file():
        c = json.loads(sb.read_text())["counts"]
        m["NBuildPkgGone"] = c.get("package unavailable", 0)
        m["NBuildDepChanged"] = c.get("dependency changed", 0)
        m["NBuildNotRerun"] = c.get("build not re-runnable", 0)
        m["NBuildUnknown"] = c.get("unknown", 0)
    ia = Path("data/validation/image_availability.json")  # image_availability.py
    if ia.is_file():
        m["NImagesPulled"] = json.loads(ia.read_text())["counts"].get("pulled and ran", 0)
    return m


def review_counts(rows: list[dict], gold: list[dict]) -> dict:
    """Populations, units and evidence breakdowns the adviser's review asked to keep visible."""
    import re

    mw = [r for r in gold if r.get("chain_kind") == "multi-weakness"]
    root = collections.Counter(r["chain"][0].get("evidence_kind") for r in gold)
    m = {
        "NStageGold": sum(r.get("chain_kind") == "stage-decomposition" for r in gold),
        "NStageAll": sum(r.get("chain_kind") == "stage-decomposition" for r in rows),
        "NBronzeCooc": sum(
            r["label_confidence_tier"] == "bronze"
            and (r.get("dataflow_evidence") or "").startswith("NVD multi-CWE co-occurrence")
            for r in rows
        ),
        "NArmsMulti": len(
            {r["chain_string"] for r in rows if r.get("chain_kind") == "multi-weakness"}
        ),
        "NArmsGoldMulti": len({r["chain_string"] for r in mw}),
        "NGoldRootExec": root["execution"],
        "NGoldRootAttested": root["attested"],
        "NGoldRootInferred": root["inferred"],
        "NGoldRootDataflow": root["dataflow"],
        "NGoldRootNone": root["none"],
        "NSiteProofsGold": sum(
            bool(r["chain"][0].get("evidence", {}).get("guard_site_proof")) for r in gold
        ),
        # Root causes with a successful single-hunk test, with or without a guard-rule CWE.
        "NGoldTestedRoot": sum(
            bool(
                r["chain"][0].get("evidence", {}).get("causal_proof")
                or r["chain"][0].get("evidence", {}).get("guard_site_proof")
            )
            for r in gold
        ),
        # What the recorded root site is (chainforge.evidence.site_kind).
        "NRootSiteTested": sum(
            r["chain"][0].get("site_kind") == "tested-repair-site" for r in gold
        ),
        "NRootSiteOrigin": sum(r["chain"][0].get("site_kind") == "origin-site" for r in gold),
        "NRootSiteAnnotated": sum(r["chain"][0].get("site_kind") == "annotated-site" for r in gold),
        "NRootSiteNone": sum(not r["chain"][0].get("site_kind") for r in gold),
        "NGoldSinglePatched": sum(
            sum(s.get("revision") == "patched" for s in r.get("sanitizer_reports") or []) < 2
            for r in gold
        ),
        "NGoldTrain": sum(r.get("split") == "train" for r in gold),
        "NGoldValidation": sum(r.get("split") == "validation" for r in gold),
        "NGoldTest": sum(r.get("split") == "test" for r in gold),
        "NGoldKernelSplitUnits": len(
            {r.get("split") for r in gold if r.get("provenance") == "syzbot"}
        ),
    }
    # Sanitizer-witnessed roots: an MSan origin (CWE-456, where the uninitialised value was
    # created) or a use-after-free's free site (CWE-416). The fix-file statistic is MSan only.
    witnessed = [r for r in gold if r["chain"][0].get("evidence_kind") == "execution"]
    m["NGoldRootExecMsan"] = sum(r["chain"][0].get("cwe_id") == 456 for r in witnessed)
    m["NGoldRootExecUaf"] = sum(r["chain"][0].get("cwe_id") == 416 for r in witnessed)
    four56 = [r for r in witnessed if r["chain"][0].get("cwe_id") == 456]
    touches = 0
    for r in four56:
        e = r["chain"][0].get("evidence") or {}
        f = (e.get("origin_site") or e.get("location") or {}).get("file") or ""  # 1.0.7: origin
        files = re.findall(r"^diff --git a/\S+ b/(\S+)", r.get("patch_diff") or "", re.M)
        touches += bool(f) and any(x.split("/")[-1] == f.split("/")[-1] for x in files)
    m |= {"NGoldFourFiveSix": len(four56), "NGoldFourFiveSixFixAtOrigin": touches}
    twenty = sum(r["chain"][0].get("cwe_id") == 20 for r in gold)
    m["NGoldRootTwentyProven"] = sum(
        r["chain"][0].get("cwe_id") == 20
        and r["chain"][0].get("evidence_kind") == "causally-proven"
        for r in gold
    )
    m |= {"NGoldRootTwenty": twenty, "PctGoldRootTwenty": pct(twenty / len(gold))}
    # MITRE grounding per record: the weakest edge kind decides.
    order = [
        "mitre-direct",
        "mitre-transitive",
        "mitre-inherited",
        "mitre-hierarchy",
        "catalog-only",
    ]
    worst = collections.Counter()
    for r in mw:
        ks = [e["kind"] for e in (r.get("mitre_chain") or {}).get("edges", [])]
        worst[max(ks, key=order.index) if ks else "catalog-only"] += 1
    n = len(mw) or 1
    m |= {
        "NMitreDirectOnly": worst["mitre-direct"],
        "PctMitreDirectOnly": pct(worst["mitre-direct"] / n),
        "NMitreTransitive": worst["mitre-transitive"],
        "NMitreHierarchy": worst["mitre-hierarchy"],
        "NMitreCatalogOnly": worst["catalog-only"],
    }
    # Locality on the subset whose root cause has intervention evidence.
    pv = [r for r in mw if r["chain"][0].get("evidence_kind") == "causally-proven"]
    place = collections.Counter(lk for r in pv if (lk := locality(r)) is not None)
    known = place["in-function"] + place["cross-function"] + place["cross-file"]
    m |= {
        "NPlacementKnownProven": known,
        "PctSpanFunctionsProven": pct((place["cross-function"] + place["cross-file"]) / known)
        if known
        else "n/a",
        "NUnlocatedMulti": sum(locality(r) is None for r in mw),
    }
    # Distinct-bug units over the whole release, from the duplicate audit when present.
    dup = Path("paper_artifacts/duplicate_audit.json")
    if dup.is_file():
        da = json.loads(dup.read_text())
        for k, name in (
            ("bug_clusters", "NBugClusters"),
            ("rows_in_multi_row_clusters", "NInMultiCluster"),
        ):
            if k in da:
                m[name] = da[k]
    first = (
        f"{m['NGoldSinglePatched']} first-pass records carry one patched run while their "
        "second runs on a clean host; until then they fall short of this rule."
        if m["NGoldSinglePatched"]
        else ""
    )
    m["FirstPassNote"] = first
    m["NSameFileUnknownFn"] = sum(locality(r) == "same-file" for r in mw)
    m["NMitreHierarchyAny"] = sum(
        any(e["kind"] == "mitre-hierarchy" for e in (r.get("mitre_chain") or {}).get("edges", []))
        for r in mw
    )
    m["NBronzeWithRuns"] = sum(
        r["label_confidence_tier"] == "bronze"
        and any(s.get("revision") == "patched" for s in r.get("sanitizer_reports") or [])
        for r in rows
    )
    # Records no run of ours reached keep the tier their source pipeline assigned (retier_all.py);
    # the paper counts the Partial ones and says every Candidate is among them.
    from chainforge.integrity import vul_log

    unrun = {r["id"] for r in rows if vul_log(r, Path(".")) is None}
    m["NPartialUnrun"] = sum(
        r["label_confidence_tier"] == "silver" and r["id"] in unrun for r in rows
    )
    assert all(r["id"] in unrun for r in rows if r["label_confidence_tier"] == "bronze"), (
        "the paper says no Candidate has a run of ours"
    )
    m["NGoldFullyLocated"] = sum(
        all(((c.get("evidence") or {}).get("location") or {}).get("file") for c in r["chain"])
        for r in gold
    )
    # Localization inputs whose sanitizer report already names the target file:line.
    shown = shown_eligible = 0
    shown_kind: collections.Counter = collections.Counter()
    for r in gold:
        loc = (r["chain"][0].get("evidence") or {}).get("location") or {}
        f, ln = (loc.get("file") or "").split("/")[-1], loc.get("line")
        logs = [
            Path(s["log_ref"])
            for s in r.get("sanitizer_reports") or []
            if s.get("revision") == "vulnerable"
            and s.get("witnesses") != "intermediate"
            and s.get("log_ref")
        ]
        if (
            f
            and ln
            and any(p.is_file() and f"{f}:{ln}" in p.read_text(errors="replace") for p in logs)
        ):
            shown += 1
            shown_eligible += localization_eligible(r)
            shown_kind[r["chain"][0].get("site_kind") or "none"] += 1
    m["NLocTargetInReport"] = shown
    m["NLocEligibleInReport"] = shown_eligible
    # Disclosure per root site kind, so the text can say how many of each the report names.
    m["NShownTested"] = shown_kind["tested-repair-site"]
    m["NShownOrigin"] = shown_kind["origin-site"]
    m["NShownAnnotated"] = shown_kind["annotated-site"]
    # Function-level disclosure: the tested site's function named anywhere in that report.
    fn_shown = 0
    for r in gold:
        if r["chain"][0].get("site_kind") != "tested-repair-site":
            continue
        fn = bare_function(
            ((r["chain"][0].get("evidence") or {}).get("location") or {}).get("function")
        )
        text = "\n".join(
            Path(s["log_ref"]).read_text(errors="replace")
            for s in r.get("sanitizer_reports") or []
            if s.get("revision") == "vulnerable"
            and s.get("witnesses") != "intermediate"
            and s.get("log_ref")
            and Path(s["log_ref"]).is_file()
        )
        fn_shown += bool(fn and re.search(r"\bin (?:[\w:~<>]*::)?" + re.escape(fn) + r"\b", text))
    m["NShownTestedFn"] = fn_shown
    return m


def tex(x) -> str:
    """Escape a data string for LaTeX text mode."""
    out = str(x)
    for a, b in (
        ("\\", r"\textbackslash{}"),
        ("_", r"\_"),
        ("&", r"\&"),
        ("%", r"\%"),
        ("#", r"\#"),
        ("$", r"\$"),
        ("{", r"\{"),
        ("}", r"\}"),
        ("^", r"\^{}"),
        ("~", r"\~{}"),
    ):
        out = out.replace(a, b)
    return out


def composition_table(gold: list[dict], top: int = 8) -> str:
    """GOLD by chain type: its MITRE grounding, spread across projects, and how its root cause
    is evidenced (the weakest link, usually)."""
    kinds = {
        "mitre-direct": "direct",
        "mitre-transitive": "trans.",
        "mitre-inherited": "inher.",
        "mitre-hierarchy": "hier.",
    }
    by = collections.defaultdict(collections.Counter)
    proj, rel = collections.defaultdict(set), {}
    for r in gold:
        k = r["chain_string"].replace("CWE-", "").replace("->", r"$\to$")
        kind = r["chain"][0].get("evidence_kind")
        by[k][kind if kind in ("causally-proven", "execution", "attested") else "weaker"] += 1
        proj[k].add(codebase(r["project"]))
        edges = [kinds.get(e["kind"], "modeling") for e in r["mitre_chain"]["edges"]]
        rel[k] = "+".join(dict.fromkeys(edges)) if edges else "---"
    keys = sorted(by, key=lambda k: -sum(by[k].values()))
    rows, rest = keys[:top], keys[top:]
    cols = ("causally-proven", "execution", "attested", "weaker")

    def line(name, c, relation, projects):
        n = sum(c.values())
        share = rf"\,({100 * c['causally-proven'] / n:.0f}\%)" if c["causally-proven"] else ""
        cells = [str(c[x]) for x in cols]
        cells[0] += share
        return " & ".join([name, relation, str(n), str(projects), *cells]) + r"\\"

    other = sum((by[k] for k in rest), collections.Counter())
    total = sum((by[k] for k in keys), collections.Counter())
    body = [line(k, by[k], rel[k], len(proj[k])) for k in rows]
    if rest:
        p_rest = len(set().union(*(proj[k] for k in rest)))
        body.append(line(f"{len(rest)} other types", other, "mixed", p_rest))
    p_all = len({codebase(r["project"]) for r in gold})
    return (
        "\n".join(
            [
                r"\begin{tabular}{@{}llrrrrrr@{}}",
                r"\toprule",
                r" & & & & \multicolumn{4}{c@{}}{root-cause evidence}\\",
                r"\cmidrule(l){5-8}",
                r"chain (CWE ids) & MITRE & GOLD & proj. & interv. & sanit. & attest. & weaker\\",
                r"\midrule",
                *body,
                r"\midrule",
                line("all GOLD", total, "", p_all),
                r"\bottomrule",
                r"\end{tabular}",
            ]
        )
        + "\n"
    )


def bounds_check(hunk: str) -> bool:
    """An added line that compares with < or > (not ->, <<, >>): a bound, the plainest guard."""
    return any(
        re.search(r"(?<![<>])[<>]=?(?![<>=])", ln.replace("->", ""))
        for ln in hunk.splitlines()
        if ln.startswith("+") and not ln.startswith("+++")
    )


def example_record(gold: list[dict], exclude: set[str]) -> str:
    """One GOLD chain drawn as root cause -> call path -> sink, with its replay verdicts.
    Chosen by rule: multi-weakness, causally proven root cause in a different file from the
    sink, a guard that adds a bound of at most four lines, smallest id."""
    from chainforge.cwe import CWE_NAMES

    def ok(r):
        src, snk = r["chain"][0], r["chain"][-1]
        cp = (src.get("evidence") or {}).get("causal_proof") or {}
        a, b = ((c.get("evidence") or {}).get("location") or {} for c in (src, snk))
        return (
            r.get("chain_kind") == "multi-weakness"
            and len(r["chain"]) == 2
            and src.get("evidence_kind") == "causally-proven"
            and r.get("locality") == "cross-file"
            and a.get("function")
            and b.get("function")
            and 0 < (cp.get("added_lines") or 99) <= 4
            and r["id"] not in exclude
            and bounds_check(src["evidence"].get("minimal_guard_patch") or "")
        )

    pick = min((r for r in gold if ok(r)), key=lambda r: r["id"], default=None)
    if not pick:
        return "% no record meets the example rule\n"
    src, snk = pick["chain"][0], pick["chain"][-1]
    a, b = src["evidence"]["location"], snk["evidence"]["location"]
    # The proving hunk as a diff: removed and added lines, minus pure re-indentation, so a
    # tightened condition reads as old -> new rather than as an if with no body.
    hunk = [
        ln
        for ln in (src["evidence"].get("minimal_guard_patch") or "").splitlines()
        if ln[:1] in "+-" and not ln.startswith(("+++", "---"))
    ]
    removed = {ln[1:].strip() for ln in hunk if ln.startswith("-")}
    added = {ln[1:].strip() for ln in hunk if ln.startswith("+")}
    guard = [
        (ln[0], ln[1:].strip())
        for ln in hunk
        if ln[1:].strip() and ln[1:].strip() not in (removed & added)
    ]
    vul = next(s["log_ref"] for s in pick["sanitizer_reports"] if s["revision"] == "vulnerable")
    log = Path(vul).read_text(errors="replace") if Path(vul).is_file() else ""
    err = next((ln.split("ERROR: ", 1)[1] for ln in log.splitlines() if "ERROR: " in ln), "")
    err = err.split(" on ")[0].replace("AddressSanitizer: ", "")
    acc = next((ln.split(" at ")[0] for ln in log.splitlines() if " of size " in ln), "")
    frames = [
        (m.group(1).split("(")[0], m.group(2), m.group(3))
        for m in re.finditer(r"#\d+ 0x[0-9a-f]+ in (\S+) (\S+?):(\d+)", log)
        if not re.search(r"compiler-rt|llvm|libfuzzer|sanitizer", m.group(2))
    ]
    names = [f[0] for f in frames]
    root_fn, sink_fn = a["function"].split("(")[0], b["function"].split("(")[0]
    caller = None
    if root_fn in names and names.index(root_fn) + 1 < len(names):
        caller = frames[names.index(root_fn) + 1]

    depth = names.index(root_fn) - names.index(sink_fn) if {root_fn, sink_fn} <= set(names) else 0
    hops = "calls the sink" if depth == 1 else f"reaches the sink through {depth} calls"

    def short(path):
        return "/".join(str(path).split("/")[-2:])

    def clip(code, n=42):  # one column wide; a wrapped code line is unreadable
        return code if len(code) <= n else code[: n - 3] + "..."

    def cwe(c):
        return rf"CWE-{c['cwe_id']} {tex(CWE_NAMES.get(c['cwe_id'], ''))}"

    guard_tex = r"\\".join(rf"\texttt{{{sign} {tex(clip(g))}}}" for sign, g in guard[:6])
    issue = pick["aliases"][0].split("-")[-1]
    lines = [
        r"\begin{tikzpicture}[font=\scriptsize, node distance=3.2mm,",
        r"  link/.style={draw, rounded corners=1.5pt, text width=0.9\columnwidth, inner sep=3pt,",
        r"    align=left},",
        r"  frame/.style={text width=0.9\columnwidth, inner sep=1pt, align=left, text=black!60},",
        r"  ar/.style={-{Latex[length=1.4mm]}, semithick}]",
    ]
    if caller:
        lines.append(
            rf"\node[frame] (caller) {{caller \texttt{{{tex(caller[0])}}}"
            rf" \hfill {tex(short(caller[1]))}:{caller[2]}}};"
        )
    lines += [
        rf"\node[link, fill=black!4{', below=of caller' if caller else ''}] (root)"
        rf" {{\textbf{{root cause}} {cwe(src)} \hfill \emph{{intervention}}\\",
        rf"\texttt{{{tex(root_fn)}}} \hfill {tex(short(a['file']))}:{a['line']}\\[1pt]",
        r"{\color{black!60}sufficient tested hunk, applied alone to the vulnerable revision:}\\",
        rf"{guard_tex}}};",
        rf"\node[link, below=of root] (sink) {{\textbf{{sink}} {cwe(snk)} \hfill"
        r" \emph{execution}\\",
        rf"\texttt{{{tex(sink_fn)}}} \hfill {tex(short(b['file']))}:{b['line']}\\[1pt]",
        rf"\texttt{{{tex(err)}}}, \texttt{{{tex(acc)}}}}};",
    ]
    if caller:
        lines.append(r"\draw[ar, black!50] (caller) -- (root);")
    lines += [
        rf"\draw[ar] (root) -- node[right, font=\scriptsize] {{{hops}}} (sink);",
        rf"\node[frame, below=2mm of sink] {{\textbf{{{tex(pick['project'])}}},"
        rf" OSS-Fuzz {tex(issue)} \hfill re-run: crash, then clean twice}};",
        r"\end{tikzpicture}",
    ]
    return "\n".join(lines) + "\n"


def wilson(k: int, n: int, z: float = 1.96) -> tuple[float, float]:
    p, d = k / n, 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    h = z * ((p * (1 - p) / n + z * z / (4 * n * n)) ** 0.5) / d
    return c - h, c + h


def pct(x: float) -> str:
    return f"{100 * x:.0f}\\%"


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--release", default="data/release")
    ap.add_argument("--out", default="paper_artifacts/macros.tex")
    args = ap.parse_args(argv)
    rel = Path(args.release)
    with open(rel / "dataset.jsonl") as fh:
        rows = [json.loads(line) for line in fh]
    with open(rel / "corrections_changelog.jsonl") as fh:
        log = [json.loads(line) for line in fh]
    man = json.loads((rel / "dataset.manifest.json").read_text())

    tier = collections.Counter(r["label_confidence_tier"] for r in rows)
    gold = [r for r in rows if r["label_confidence_tier"] == "gold"]
    proven = [r for r in rows if r["chain"][0].get("evidence_kind") == "causally-proven"]
    sites = [r for r in rows if r["chain"][0].get("evidence", {}).get("guard_site_proof")]
    ops = collections.Counter(e.get("op") for e in log)
    retier = collections.Counter(
        (e["op"], e.get("from"), e.get("to")) for e in log if "retier" in (e.get("op") or "")
    )
    pr3_rules = collections.Counter()
    for e in log:
        if e.get("op") == "PR3-retier":
            for rule in e.get("rules") or {}:
                pr3_rules[rule.split("-")[0]] += 1
    kd = collections.Counter(
        e["status"] for e in log if e.get("op") == "kernel-differential-attempt"
    )
    # Patched-side logs that print no crash and show no executed input: environment failures that
    # an absence-of-crash check had scored clean.
    aborted = sum(
        1
        for p in Path("data/evidence/arvo").glob("*/fix.sanitizer.txt")
        if not _CRASHED.search(t := p.read_text(errors="replace")) and not ran_clean(t)
    )
    four = LEAKAGE_FIELDS["project+provenance+ecosystem+language"]
    funnel = attrition(log, {r["id"]: r for r in rows})

    m = {
        "NRecords": len(rows),
        "NGold": tier["gold"],
        "NGoldUpstream": tier["gold-upstream"],
        "NSilver": tier["silver"],
        "NBronze": tier["bronze"],
        # One codebase arrives under several names (gdal, OSGeo/gdal); count codebases.
        "NProjects": len({codebase(r["project"]) for r in rows}),
        # Records mined from advisories alone: no crash or image of their own (Sec. III).
        "NAdvisoryOnly": sum(
            r.get("provenance") in ("nvd-race", "nvd-mined", "osv-git", "osv-git-len3")
            for r in rows
        ),
        # Records by source, for Fig. 2: ARVO's OSS-Fuzz crashes, syzbot's kernel bugs, advisories.
        "NRecArvo": sum((r.get("provenance") or "").startswith("arvo") for r in rows),
        "NRecSyzbot": sum(r.get("provenance") == "syzbot" for r in rows),
        "NAdvisoryOnlyGold": sum(
            r.get("provenance") in ("nvd-race", "nvd-mined", "osv-git", "osv-git-len3")
            for r in gold
        ),
        "DatasetMB": f"{round(Path('data/release/dataset.jsonl').stat().st_size / 1e6)}\\,MB",
        "LogsGB": f"{_tree_bytes(Path('data/evidence')) / 1e9:.1f}\\,GB",
        "NProjectsGold": len({codebase(r["project"]) for r in gold}),
        "NArms": len({r["chain_string"] for r in rows}),
        "NArmsGold": len({r["chain_string"] for r in gold}),
        "NLenThree": sum(len(r["chain"]) == 3 for r in rows),
        "NGoldCrashes": len({crash_key(r) for r in gold}),
        "NGoldKernel": sum(r["provenance"] == "syzbot" for r in gold),
        "NGoldArvo": sum(r["provenance"] != "syzbot" for r in gold),
        # 1.0.9: crashing inputs copied out of the images the records pin.
        "NGoldArvoInput": sum(
            r["provenance"] != "syzbot"
            and str(r.get("pov_input") or "").startswith("data/evidence/arvo/")
            for r in gold
        ),
        "PctGoldArvo": f"{man['gold_arvo_share_pct']}\\%",
        "NGoldAllExecution": sum(
            r["evidence_floor"] in ("execution", "causally-proven") for r in gold
        ),
        "NGoldLocalized": sum(
            all(((c.get("evidence") or {}).get("location") or {}).get("file") for c in r["chain"])
            for r in gold
        ),
        "NChainWitnessed": sum(
            r["chain"][0].get("evidence_kind") in ("causally-proven", "execution", "attested")
            for r in gold
        ),
        # One definition of "distinct bug": the duplicate audit's clusters (crash, CVE, fix,
        # identical or near-identical patch), falling back to fix-commit groups without it.
        "NGoldBugs": (
            json.loads(Path("paper_artifacts/duplicate_audit.json").read_text())[
                "gold_bug_clusters"
            ]
            if Path("paper_artifacts/duplicate_audit.json").is_file()
            else len({r.get("duplicate_group") or r["id"] for r in gold})
        ),
        "NGoldLenThree": sum(len(r["chain"]) == 3 for r in gold),
        "NProven": len(proven),
        "NProvenProjects": len({codebase(r["project"]) for r in proven}),
        "NProvenRelabelled": ops["PR4-relabel-source"],
        "NSiteProofs": len(sites),
        "NIdenticalRows": ops["PR3-I1-identical-row-removed"],
        "NConflictingClaims": ops["PR3-I1-dropped"],
        "NHarnessProofs": ops["PR3-I6-withdraw-proof"],
        "NDemotedSource": pr3_rules["I2"],
        "NDemotedPatch": pr3_rules["I3"],
        "NDemotedLenThree": pr3_rules["I4"],
        "NDemotedTwoSided": pr3_rules["I5"],
        "NToGoldUpstream": retier[("PR3-retier", "gold", "gold-upstream")],
        "NRerunPromoted": retier[("arvo-rerun-retier", "silver", "gold")],
        "NKernelAttempted": sum(kd.values()),
        "NKernelDifferential": kd["differential"],
        "NKernelNoCRepro": kd["no_crepro"],
        "NKernelNoRepro": kd["vul_no_repro"],
        "NPatchedAborted": aborted,
        "LeakFourHeldOut": pct(held_out_accuracy(rows, four)),
        "LeakProvenanceHeldOut": pct(held_out_accuracy(rows, LEAKAGE_FIELDS["provenance"])),
        "LeakFixDateHeldOut": pct(held_out_accuracy(rows, LEAKAGE_FIELDS["fix_date"])),
        "LeakFixDateInSample": pct(in_sample(rows, LEAKAGE_FIELDS["fix_date"])),
        "LeakBaseline": pct(held_out_accuracy(rows, LEAKAGE_FIELDS["baseline"])),
    }
    # Fig. 2's three sources must account for every record.
    assert m["NRecArvo"] + m["NRecSyzbot"] + m["NAdvisoryOnly"] == m["NRecords"], "Fig. 2 sources"
    for side, stages in funnel.items():
        for i, (_, n) in enumerate(stages):
            m[f"Funnel{side}{'ABCDEFG'[i]}"] = n
    (Path(args.out).parent / "funnel.md").write_text(
        "\n".join(
            f"## {side}\n\n| stage | records |\n|---|---:|\n"
            + "\n".join(f"| {name} | {n} |" for name, n in stages)
            for side, stages in funnel.items()
        )
        + "\n"
    )
    weak = sum(
        r["chain"][0].get("evidence_kind") not in ("causally-proven", "execution", "attested")
        for r in gold
    )
    m["NGoldProven"] = sum(r["chain"][0].get("evidence_kind") == "causally-proven" for r in gold)
    m["NGoldWeakRoot"] = weak
    m["PctGoldWeakRoot"] = pct(weak / len(gold))
    m |= characterize(gold)
    m |= entry_routes(rows, log)
    tested = sum(
        bool(
            r["chain"][0].get("evidence", {}).get("causal_proof")
            or r["chain"][0].get("evidence", {}).get("guard_site_proof")
        )
        for r in gold
    )
    m["PctGoldTestedRoot"] = pct(tested / len(gold))
    m["NGoldDated"] = sum(bool(r.get("fix_date")) for r in gold)
    # "from 2025 or later": fixed_after is strict, so the cutoff is the last day of 2024.
    m["NGoldAfterTwentyFive"] = sum(fixed_after(r, "2024-12-31") is True for r in gold)
    m["NGoldUntestedRoot"] = len(gold) - tested

    # Roots with a successful hunk test whose stored site is an MSan or free origin (the origin
    # defines that CWE; the tested site is kept in evidence.tested_site). Every tested root sits
    # at its tested site or at such an origin, so the two counts partition NGoldTestedRoot.
    def _tested(r):
        e = r["chain"][0].get("evidence") or {}
        return bool(e.get("causal_proof") or e.get("guard_site_proof"))

    m["NTestedAtOrigin"] = sum(
        _tested(r) and r["chain"][0].get("site_kind") == "origin-site" for r in gold
    )
    m["NTestedAtOriginMsan"] = sum(
        _tested(r)
        and r["chain"][0].get("site_kind") == "origin-site"
        and r["chain"][0].get("cwe_id") == 456
        for r in gold
    )
    m["NTestedAtOriginUaf"] = m["NTestedAtOrigin"] - m["NTestedAtOriginMsan"]
    _tested_sites = sum(
        _tested(r) and r["chain"][0].get("site_kind") == "tested-repair-site" for r in gold
    )
    assert _tested_sites + m["NTestedAtOrigin"] == tested, (_tested_sites, m["NTestedAtOrigin"])
    m["PctGoldUntestedRoot"] = pct((len(gold) - tested) / len(gold))
    m["NLocEligibleGold"] = sum(localization_eligible(r) for r in gold)
    m |= split_leakage(rows)
    m |= guard_off_stack(gold)
    m |= review_counts(rows, gold)
    m |= revision_counts(rows, gold)
    # The paper's input sentence (1.0.9), over every ARVO record.
    arvo = [r for r in rows if r["provenance"] != "syzbot" and r.get("docker_image_ref")]
    n_in = sum(str(r.get("pov_input") or "").startswith("data/evidence/arvo/") for r in arvo)
    m["NArvoInput"], m["NArvoRecords"] = n_in, len(arvo)
    m["ArvoInputPhrase"] = (
        "every ARVO record" if n_in == len(arvo) else f"{n_in} of the {len(arvo)} ARVO records"
    )

    # The most common GOLD chain shapes, named in the paper's Contents paragraph (detail: Table S2).
    def _chain(r):
        return r["chain"][0]["cwe_id"], r["chain"][-1]["cwe_id"]

    m["NChainUninit"] = sum(_chain(r) == (456, 457) for r in gold)
    m["NChainUafRead"] = sum(_chain(r) == (416, 125) for r in gold)
    m["NChainCheckRead"] = sum(
        _chain(r)[0] in (20, 1284, 1285) and _chain(r)[1] == 125 for r in gold
    )
    m["NChainCheckWrite"] = sum(
        _chain(r)[0] in (20, 1284, 1285) and _chain(r)[1] == 787 for r in gold
    )
    # Fig. 1's running example (pjsip STUN decoder): facts read from its record, not typed.
    ex = next((r for r in rows if r["id"] == "CHAINFORGE-0042519040"), None)
    if ex:
        words = [
            "zero",
            "one",
            "two",
            "three",
            "four",
            "five",
            "six",
            "seven",
            "eight",
            "nine",
            "ten",
            "eleven",
            "twelve",
        ]
        n = sum(1 for ln in (ex.get("patch_diff") or "").splitlines() if ln.startswith("@@"))
        m["ExHunks"] = words[n] if n < len(words) else str(n)
        m["ExRootCwe"] = f"\\cwe{{{ex['chain'][0]['cwe_id']}}}"
        m["ExSinkCwe"] = f"\\cwe{{{ex['chain'][-1]['cwe_id']}}}"
        assert (
            ex["label_confidence_tier"] == "gold"
            and ex["chain"][0]["site_kind"] == "tested-repair-site"
            and ex["chain"][0].get("evidence_kind") == "causally-proven"  # Fig. 1: "hunk-named"
        )
    # Tested roots whose fix has one code hunk: there the single-hunk test confirms that hunk
    # rather than choosing among several (disclosed in the paper).
    from split_hunks import split as split_fix

    from chainforge.evidence import is_non_guard_path

    tested = [
        r
        for r in gold
        if (r["chain"][0].get("evidence") or {}).get("causal_proof")
        or (r["chain"][0].get("evidence") or {}).get("guard_site_proof")
    ]
    one = sum(
        len([h for h in split_fix(r.get("patch_diff") or "") if not is_non_guard_path(h["file"])])
        == 1
        for r in tested
    )
    m["NGoldTestedOneHunk"] = one
    m["PctGoldTestedOneHunk"] = pct(one / len(tested)) if tested else "n/a"
    # Results not yet produced render visibly in the PDF, so a draft cannot ship a missing number.
    pending = {
        "IrrKappaSource": "irr",
        "IrrAcOneSource": "irr",
        "IrrN": "irr",
        "RerunCleanPct": "clean-host re-run",
        "RerunCleanN": "clean-host re-run",
        "RerunCleanCI": "clean-host re-run",
        "ScoreSmokeN": "score smoke test",
        "ScoreSmokeOK": "score smoke test",
        "DataURL": "public URL",
        "ResourceFigures": "score smoke test",
        "IrrBBackground": "second rater's background",  # used only once two sheets are scored
        "NKHostedFired": "kernel controls on hosted runners",
        "NKHostedRun": "kernel controls on hosted runners",
        "NKHostedTried": "kernel controls on hosted runners",
    }
    m["DataDOI"] = "Zenodo"  # the DOI replaces this at camera-ready
    import hashlib

    m["ReleaseID"] = hashlib.sha256((rel / "dataset.jsonl").read_bytes()).hexdigest()[:12]
    m["ReleaseVersion"] = re.search(
        r'^version = "([^"]+)"', Path("pyproject.toml").read_text(), re.M
    ).group(1)
    prec = Path("paper_artifacts/irr_precision.json")  # score_audit.py (PR-9)
    if prec.is_file():
        audit = json.loads(prec.read_text())
        raters = audit["raters"]
        # Raters in the order their sheets came back: the first rater's macros keep their names
        # when a second sheet arrives, and the second rater's carry a B (IrrBSinkCwe, ...).
        order = audit.get("order") or sorted(raters)
        pop = audit["gold_population"]
        kinds_all = ("tested-repair-site", "origin-site", "annotated-site")

        def apct(v):
            return f"{100 * v:.0f}\\%"

        def aci(q):
            v, (lo, hi) = q["value"], q["wilson95"]
            return f"{apct(v)} (95\\% CI {100 * lo:.0f}--{100 * hi:.0f}\\%)"

        def rater_macros(rt: dict, tag: str) -> dict:
            pg, loc, kinds = rt["gold"], rt["location_gold"], rt["gold_by_root_kind"]
            out = {
                f"Irr{tag}SinkCwe": aci(pg["sink_cwe"]["precision"]),
                f"Irr{tag}SinkCwePct": apct(pg["sink_cwe"]["precision"]["value"]),
                f"Irr{tag}SinkSite": apct(pg["sink_site"]["precision"]["value"]),
                f"Irr{tag}SrcCwe": aci(pg["source_cwe"]["precision"]),
                f"Irr{tag}SrcCwePct": apct(pg["source_cwe"]["precision"]["value"]),
                f"Irr{tag}SrcHier": apct(
                    pg["source_cwe"]["hierarchy_compatible"]["precision"]["value"]
                ),
                f"Irr{tag}SrcHierCur": apct(
                    pg["source_cwe"]["hierarchy_compatible_current"]["precision"]["value"]
                ),
                f"Irr{tag}SrcCweOther": apct(rt["not gold"]["source_cwe"]["precision"]["value"]),
            }
            for key, kind in (
                ("Tested", "tested-repair-site"),
                ("Origin", "origin-site"),
                ("Annot", "annotated-site"),
            ):
                out[f"NIrr{key}"] = loc[kind]["n"]  # the same items for every rater
                out[f"Irr{tag}Strict{key}"] = aci(loc[kind]["strict"])
                out[f"Irr{tag}PctStrict{key}"] = apct(loc[kind]["strict"]["value"])
                lo, hi = loc[kind]["strict"]["wilson95"]  # bare interval, for the two-rater text
                out[f"Irr{tag}Strict{key}CI"] = f"{100 * lo:.0f}--{100 * hi:.0f}\\%"
                out[f"NIrr{tag}Strict{key}"] = round(loc[kind]["strict"]["value"] * loc[kind]["n"])
            out[f"NIrr{tag}LenientMaxGain"] = max(
                round((loc[k]["lenient"]["value"] - loc[k]["strict"]["value"]) * loc[k]["n"])
                for k in kinds_all
            )
            o, t = kinds["origin-site"], kinds["tested-repair-site"]
            out[f"NIrr{tag}OriginCwe"] = o["source_cwe_exact"]
            out[f"NIrr{tag}OriginInFixFn"] = o.get("other_site_in_fix_function", 0)
            out[f"NIrr{tag}OriginInFixFile"] = o.get("other_site_in_fix_file_only", 0)
            out[f"NIrr{tag}TestedCwe"] = t["source_cwe_exact"]
            # Function-level match for tested roots, and the 1.0.7 moved roots (added 2026-11-09).
            fm = loc["tested-repair-site"]["function_match"]["value"]
            out[f"NIrr{tag}TestedFn"] = round(fm * loc["tested-repair-site"]["n"])
            mv = rt.get("moved_origin_roots")
            if mv:
                out["NIrrMoved"] = mv["n"]
                out["NIrrMovedDiffer"] = mv["n_functions_differ"]
                out[f"NIrr{tag}MovedTestedFn"] = mv["names_tested_function"]
                out[f"NIrr{tag}MovedOriginFn"] = mv["names_origin_function"]
                out[f"NIrr{tag}MovedOriginOnly"] = mv["names_origin_where_differ"]
                out[f"NIrr{tag}MovedViaCrash"] = mv["tested_match_via_crash_site"]
            out[f"NIrr{tag}TestedCweCompat"] = t["source_cwe_compatible"]
            # PR-9: a figure pooled over GOLD reweights each site kind to its population share.
            ks = [k for k in kinds_all if k in loc]
            tot = sum(pop.get(k, 0) for k in ks)
            out[f"Irr{tag}PooledStrict"] = apct(
                sum(pop.get(k, 0) / tot * loc[k]["strict"]["value"] for k in ks)
            )
            # Sensitivity: the same judgments against the current release's root sites, pooled
            # with the snapshot's weights and with the current release's.
            cur = rt.get("location_gold_current")
            if cur:
                ck = [k for k in kinds_all if k in cur]
                for name, w in (
                    (f"Irr{tag}PooledStrictCurSnapW", pop),
                    (f"Irr{tag}PooledStrictCur", audit.get("gold_population_current") or {}),
                ):
                    wt = sum(w.get(k, 0) for k in ck)
                    if wt:
                        out[name] = apct(
                            sum(w.get(k, 0) / wt * cur[k]["strict"]["value"] for k in ck)
                        )
                out[f"Irr{tag}StrictTestedCur"] = apct(cur["tested-repair-site"]["strict"]["value"])
            return out

        m["NIrrRaters"] = len(raters)
        for i, initials in enumerate(order[:2]):
            m |= rater_macros(raters[initials], "" if i == 0 else "B")
        # The pooled figure's weights: the snapshot's located GOLD records by root site kind.
        m["NIrrPopTested"] = pop.get("tested-repair-site", 0)
        m["NIrrPopOrigin"] = pop.get("origin-site", 0)
        m["NIrrPopAnnot"] = pop.get("annotated-site", 0)
        m["NIrrPop"] = m["NIrrPopTested"] + m["NIrrPopOrigin"] + m["NIrrPopAnnot"]
        m["NIrrLocated"] = m["NIrrTested"] + m["NIrrOrigin"] + m["NIrrAnnot"]
        if "NIrrBOriginCwe" in m:  # "50 of 51" when the raters agree, else "50 and 48 of 51"
            a, b = m["NIrrOriginCwe"], m["NIrrBOriginCwe"]
            pair = a if a == b else f"{a} and {b}"
            m["IrrOriginCwePair"] = f"{pair} of {m['NIrrOrigin']}"
            # "97% of items each" when the raters' sink-CWE agreement is equal (added 2026-11-09).
            sa, sb = m["IrrSinkCwePct"], m["IrrBSinkCwePct"]
            m["IrrSinkCweItems"] = f"{sa} of items each" if sa == sb else f"{sa} and {sb} of items"
            # "none of the 13 suggested sites" when neither rater judged one the defect.
            pa, pb = m["IrrPctStrictAnnot"], m["IrrBPctStrictAnnot"]
            m["IrrAnnotPair"] = (
                f"none of the {m['NIrrAnnot']} suggested sites"
                if pa == pb == "0\\%"
                else f"{pa} and {pb} of {m['NIrrAnnot']} suggested sites"
            )
    agree = Path("paper_artifacts/irr_agreement.json")  # score_audit.py, two sheets (PR-9)
    if agree.is_file():
        sc = json.loads(agree.read_text())

        def ci2(lo_hi):
            return f"{lo_hi[0]:.2f}--{lo_hi[1]:.2f}"

        m["IrrN"] = sc["n"]
        for key, field in (("Source", "source_cwe"), ("Sink", "sink_cwe"), ("Site", "source_site")):
            f = sc[field]
            m[f"IrrAgree{key}"] = f"{100 * f['agreement']:.0f}\\%"
            m[f"IrrKappa{key}"] = f"{f['kappa']:.2f}"
            m[f"IrrKappa{key}CI"] = ci2(f["kappa_ci"])
            m[f"IrrAcOne{key}"] = f"{f['ac1']:.2f}"
            m[f"IrrAcOne{key}CI"] = ci2(f["ac1_ci"])
        sd = sc.get("source_site_detail")  # added after scoring (rule log, 2026-11-08)
        if sd:
            m["IrrAgreeSiteFn"] = f"{100 * sd['function_agreement']:.0f}\\%"
            m["NIrrSiteBothUnclear"] = sd["as_written_both_unclear"]
            gaps = sd["blank_answers"] + sd["sites_without_role"]
            m["IrrBlankPhrase"] = (
                "Neither sheet left an answer or site role blank"
                if gaps == 0
                else f"The sheets left {gaps} answers or site roles blank, which count as unclear"
            )
    ai = Path("paper_artifacts/irr_ai.json")  # score_ai_raters.py (PR-9, exploratory)
    if ai.is_file():
        models = json.loads(ai.read_text())["models"]
        short = {"claude-opus-5-5": "Opus", "gemini-4-argon": "Gemini", "Qwen_Qwen3.8-27B": "Qwen"}
        m["NAiModels"] = len(models)
        full = [d for d in models.values() if d["answered"] == 150]

        def arange(vals):
            lo, hi = round(100 * min(vals)), round(100 * max(vals))
            return f"{lo}\\%" if lo == hi else f"{lo}--{hi}\\%"

        if full:
            for key, kind in (("Tested", "tested-repair-site"), ("Origin", "origin-site")):
                m[f"Ai{key}Range"] = arange(
                    [d["location_gold"][kind]["strict"]["value"] for d in full]
                )
            m["AiPooledRange"] = arange([d["pooled_strict"] for d in full])
            m["NAiModelsFull"] = len(full)
        site_agree = []  # each full model against each human sheet, for the paper's range
        for name, d in models.items():
            key = short.get(name)
            if not key or d["answered"] != 150:
                continue
            lg = d["location_gold"]
            m[f"Ai{key}Pooled"] = f"{100 * d['pooled_strict']:.0f}\\%"
            m[f"Ai{key}Tested"] = f"{100 * lg['tested-repair-site']['strict']['value']:.0f}\\%"
            m[f"Ai{key}Origin"] = f"{100 * lg['origin-site']['strict']['value']:.0f}\\%"
            m[f"NAi{key}Origin"] = round(
                lg["origin-site"]["strict"]["value"] * lg["origin-site"]["n"]
            )
            agree = d["agreement_with"]
            # Agreement with each human rater, in the order the sheets came back.
            humans = [h for h in (order if prec.is_file() else sorted(agree)) if h in agree]
            for i, initials in enumerate(humans[:2]):
                h, tag = agree[initials]["source_site"], "" if i == 0 else "B"
                m[f"Ai{key}SiteAgree{tag}"] = f"{100 * h['agreement']:.0f}\\%"
                m[f"Ai{key}SiteKappa{tag}"] = f"{h['kappa']:.2f}"
                site_agree.append(h["agreement"])
        if site_agree:
            m["AiSiteAgreeRange"] = arange(site_agree)
    smoke = Path("data/validation/score_smoke.json")  # score_patch.sh smoke test (runner)
    if smoke.is_file():
        sm = json.loads(smoke.read_text())
        ok = str(sm["as_expected"])
        if sm.get("not_run"):
            k = sm["not_run"]
            ok += "; the image of the remaining case" if k == 1 else f"; the images of {k} cases"
            ok += " could not be pulled"
        m |= {"ScoreSmokeN": sm["n"], "ScoreSmokeOK": ok}
    # Resources over every scored rebuild (PR-12 rl_scoring), not the five-case smoke test.
    secs = sorted(
        r["rl_scoring"]["build_seconds"]
        for r in rows
        if (r.get("rl_scoring") or {}).get("build_seconds")
    )
    mem = sorted(
        r["rl_scoring"]["peak_memory_bytes"] / 1e9
        for r in rows
        if (r.get("rl_scoring") or {}).get("peak_memory_bytes")
    )
    if secs and mem:
        p95 = lambda xs: xs[int(0.95 * (len(xs) - 1))]  # noqa: E731
        med, hi = secs[len(secs) // 2], round(p95(secs) / 60)
        mmed, mhi = mem[len(mem) // 2], p95(mem)
        m["ResourceFigures"] = (
            f"a scored rebuild took a median of {med}\\,s and used {mmed:.1f}\\,GB"
            f" (95th percentiles {hi}\\,min and {mhi:.0f}\\,GB)"
        )
    url = Path("data/release/URL")
    if url.is_file():
        m["DataURL"] = f"\\url{{{url.read_text().strip()}}}"
    doi = Path("data/release/DOI")
    if doi.is_file():
        m["DataDOI"] = f"\\url{{https://doi.org/{doi.read_text().strip()}}}"
    samp = Path("data/validation/clean_rerun_sample.json")
    if samp.is_file():  # what the clean-host sample covers, from the records it names
        ids = set(json.loads(samp.read_text())["record_ids"])
        by = {r["id"]: r for r in rows}
        got = [by[i] for i in ids if i in by]
        m |= {
            "RerunCleanProjects": len({codebase(r["project"]) for r in got}),
            "RerunCleanRoutes": len({r["provenance"] for r in got}),
            "RerunCleanTypes": len({r["chain_string"] for r in got}),
            "RerunCleanStillGold": sum(r["label_confidence_tier"] == "gold" for r in got),
        }
    clean = Path("data/validation/clean_rerun.json")
    if clean.is_file():
        cr = json.loads(clean.read_text())
        lo, hi = cr["wilson95"]
        m |= {
            "RerunCleanN": cr["returned"],
            "RerunCleanPct": f"{100 * cr['rate']:.0f}\\%",
            "RerunCleanCI": f"{100 * lo:.0f}--{100 * hi:.0f}\\%",
        }
    dup = Path("paper_artifacts/duplicate_audit.json")
    if dup.is_file():
        da = json.loads(dup.read_text())
        m["PctDupRows"] = pct(da["duplicate_rate"])
        m["NDupSpanning"] = da["clusters_spanning_splits"]
        n = m["NDupSpanning"]  # the paper's split sentence (added 2026-11-09)
        m["DupSpanPhrase"] = (
            "no duplicate group spans two"
            if n == 0
            else f"{n} duplicate group{'s' if n > 1 else ''} span{'' if n > 1 else 's'} two"
        )
    funnels = sorted(Path("data/validation").glob("pr7_*_funnel.json"))
    if funnels:  # PREREGISTRATION PR-7 execution-first mining, every batch summed
        steps = ["selected", "reproduced", "sink", "proof", "CWE derived", "admitted", "gold"]
        fs = [json.loads(f.read_text()) for f in funnels]
        for i, k in enumerate(steps):
            m[f"PrSeven{'ABCDEFG'[i]}"] = sum(f["funnel"][k] for f in fs)
        m["PrSevenProjects"] = len(
            {c["project"] for f in fs for c in f["cases"] if c["reached"] in ("admitted", "gold")}
        )
        m["PrSevenBatches"] = len(fs)
        sel = json.loads(Path("data/validation/pr7_pilot.json").read_text())
        m["PrSevenPool"] = f"{sum(sel['pool_by_stratum'].values()):,}"
    # PR-12: records whose scorer separates the vulnerable build from the developer's fix. The
    # ARVO figures stay ARVO-only; kernel readiness (release 1.0.4, item 3) is counted apart.
    kscored = [
        r for r in gold if r.get("rl_ready") is not None and r.get("project") == "linux-kernel"
    ]
    m["NRlReadyKernelGold"] = sum(r["rl_ready"] is True for r in kscored)
    # Of the ready kernel records also run on GitHub-hosted machines, how many controls booted and
    # reproduced syzbot's bug there (summarize_hosted_kernel.py; a failed build is no verdict).
    hosted_p = Path("data/validation/kernel_hosted.json")
    if hosted_p.is_file():
        hosted = json.loads(hosted_p.read_text())["by_extid"]
        ready_ext = [
            a.removeprefix("syzbot-")
            for r in kscored
            if r["rl_ready"] is True
            for a in r.get("aliases") or []
            if a.startswith("syzbot-")
        ]
        tried = [hosted[e] for e in ready_ext if e in hosted]
        m["NKHostedTried"] = len(tried)
        m["NKHostedRun"] = sum(h["control_ran"] for h in tried)
        m["NKHostedFired"] = sum(h["control_fired"] for h in tried)
        m["NKHostedNoBuild"] = sum(not h["control_built"] for h in tried)
        m["NKHostedNoBoot"] = sum(h["control_built"] and not h["control_ran"] for h in tried)
    m["NRlReadyAllGold"] = sum(r.get("rl_ready") is True for r in gold)
    scored = [
        r for r in gold if r.get("rl_ready") is not None and r.get("project") != "linux-kernel"
    ]
    m["NRlScoredGold"] = len(scored)
    m["NRlReadyGold"] = sum(r["rl_ready"] is True for r in scored)

    # Every scored GOLD record falls in exactly one of these outcomes.
    def _out(r):
        s = r.get("rl_scoring") or {}
        if r["rl_ready"] is True:
            return "ready"
        if s.get("nopatch") != "crash":
            return "nocrash"
        dev = s.get("devfix")
        if dev == "patch_fail":
            return "patchfail"
        if dev == "crash":
            return "fixcrash"
        if dev == "pass":
            return "fuzzonly"
        return "fixbuild"

    outs = collections.Counter(_out(r) for r in scored)
    m["NRlNoCrashGold"] = outs["nocrash"]
    m["NRlPatchFailGold"] = outs["patchfail"]
    m["NRlFixCrashGold"] = outs["fixcrash"]
    m["NRlFuzzOnlyGold"] = outs["fuzzonly"]
    m["NRlFixBuildGold"] = outs["fixbuild"]
    assert sum(outs.values()) == len(scored)
    # Coverage of the developer fix relative to the unmodified build, where the image ships a
    # libFuzzer target with a seed corpus (rl_scoring.corpus).
    ready = [r for r in scored if r["rl_ready"] is True]
    covr = [
        c["devfix_ft"] / c["nopatch_ft"]
        for r in ready
        if (c := (r["rl_scoring"].get("corpus") or {})).get("nopatch_ft") and c.get("devfix_ft")
    ]
    import inspect

    from chainforge.reward import shaped

    tol = inspect.signature(shaped).parameters["tolerance"].default
    m["CovTolPct"] = f"{round(100 * tol)}\\%"
    cov = Path("data/validation/pr12_coverage.json")  # coverage_calibration.py
    if cov.is_file():
        cv = json.loads(cov.read_text())
        m["NCovN"], m["NCovAccepted"] = cv["n"], cv["accepted_at"][str(tol)]
    m["NRlCovGold"] = len(covr)
    m["NRlCovKeptGold"] = sum(x >= tol for x in covr)
    env = Path("data/validation/env_probe.json")  # parse_env_probe.py (agent environment)
    if env.is_file():
        es = json.loads(env.read_text())["summary"]
        m["NEnvImages"], m["NEnvFixPresent"] = es["images"], es["fix_commit_present"]
        m["NEnvChecked"] = es["sanitized_checked"]
        m["NEnvFixGone"], m["NEnvBuildOk"] = (
            es["sanitized_fix_unreachable"],
            es["sanitized_build_ok"],
        )
    src = Path("data/validation/pr15_result.json")  # score_pr15.py (from-source reproduction)
    if src.is_file():
        fs15 = json.loads(src.read_text())
        k, n = fs15["reproduced_of_built"]
        lo, hi = fs15["wilson95"]
        m["NFromSrcN"], m["NFromSrcBuilt"], m["NFromSrcRepro"] = fs15["sampled"], n, k
        m["FromSrcCI"] = f"95\\% CI {100 * lo:.0f}--{100 * hi:.0f}\\%"
    path = Path("data/validation/pr14_result.json")  # attach_path_observed.py (PR-14)
    if path.is_file():
        po = json.loads(path.read_text())
        tot = collections.Counter()
        for v in po["by_site_kind"].values():
            tot.update(v)
        m["NPathN"] = po["supplied"]
        m["NPathLineHit"], m["NPathFnHit"] = tot["line-hit"], tot["function-hit"]
        m["NPathNotHit"], m["NPathInconclusive"] = tot["not-hit"], tot["inconclusive"]
    fz = Path("data/validation/fuzzcheck_result.json")  # apply_fuzz_check.py
    rt = Path("data/validation/fuzzcheck_retest.json")  # summarize_strict_retests.py
    if fz.is_file() and rt.is_file():
        fr, rr = json.loads(fz.read_text()), json.loads(rt.read_text())
        st = collections.Counter()
        for v in fr["by_kind"].values():
            for k, n in v.items():
                st[k.split(" ", 1)[1]] += n
        m["NFuzzTests"], m["NFuzzStrict"], m["NFuzzFuzzy"] = fr["tests"], st["strict"], st["fuzzy"]
        m["NFuzzHeld"] = rr["single_hunk"]["held_at_fuzz0"] + rr["pairs"]["held_at_fuzz0"]
        m["NFuzzUndet"] = fr.get("undetermined", 0)
        # Tests withdrawn by either check (the second covers tests added after the first).
        m["NFuzzWithdrawn"] = st["fuzzy"]
        f2 = Path("data/validation/fuzzcheck_result2.json")
        if f2.is_file():
            m["NFuzzWithdrawn"] += sum(
                n
                for v in json.loads(f2.read_text())["by_kind"].values()
                for k, n in v.items()
                if k.endswith(" fuzzy")
            )
        # The withdrawn count's base: tests from both checks (added 2026-11-09).
        m["NFuzzTestsAll"] = fr["tests"] + (
            json.loads(f2.read_text())["tests"] if f2.is_file() else 0
        )
    ru = Path("data/validation/retest_unresolved.json")  # strict re-tests of unresolved tests
    if ru.is_file():
        rc = json.loads(ru.read_text())["counts"]
        m["NRetestN"] = sum(rc.values())
        m["NRetestHeld"] = rc.get("held", 0)
        m["NRetestFailed"] = rc.get("not replicated", 0)
        m["NRetestNotRun"] = rc.get("not run", 0)
    fd = Path("data/validation/fixdist_result.json")  # summarize_fixdist.py
    if fd.is_file():
        g = json.loads(fd.read_text())["groups"]
        crash, ready = g["fix still crashes"], g["ready"]
        m["NFixDistCrashSampled"], m["NFixDistCrashN"] = crash["sampled"], crash["measured"]
        m["NFixDistCrashSame"] = crash["same_tree_as_scorer"]
        m["NFixDistCrashBehind"] = crash["vul_behind_fix_parent"] + crash["vul_not_ancestor"]
        m["NFixDistCrashMedian"] = int(crash["median_commits_behind"])
        m["NFixDistCrashFixMoved"] = crash["fix_image_measured"] - crash["fix_image_at_fix"]
        m["NFixDistCrashOther"] = crash["other_repos_differ"]
        m["NFixDistReadyN"], m["NFixDistReadySame"] = (
            ready["measured"],
            ready["same_tree_as_scorer"],
        )
        m["NFixDistReadyDiff"] = ready["measured"] - ready["same_tree_as_scorer"]
    # How each GOLD root's current single-hunk test is known to apply with exact context.
    app = collections.Counter()
    for r in gold:
        e = r["chain"][0].get("evidence") or {}
        for k in ("causal_proof", "guard_site_proof"):
            t = e.get(k)
            if t:
                app[
                    "kernel"
                    if t.get("application_basis")
                    else "checked"
                    if t.get("application") == "strict"
                    else "unchecked"
                ] += 1
    m["NGoldTestsChecked"] = app["checked"]
    m["NGoldTestsKernel"] = app["kernel"]
    m["NGoldTestsUnchecked"] = app["unchecked"]
    ac = Path("data/validation/agent_check.json")  # summarize_agent_check.py (wider sample)
    if ac.is_file():
        ag = json.loads(ac.read_text())
        m["NEnvChecked"], m["NEnvBuildOk"] = ag["checked"], ag["build_ok"]
        m["NEnvFixGone"] = ag["fix_unreachable"]
        m["NEnvNetFail"] = ag["build_failure_cause"].get("network", 0)
    audit = Path("data/irr/sample.json")  # the PR-9 audit draw
    if audit.is_file():
        drawn = json.loads(audit.read_text())
        # Audited GOLD records whose root or sink CWE PR-17 later remapped: raters judged the
        # snapshot label, so these mapped labels have no independent assessment.
        now = {r["id"]: r for r in rows}
        dg = [r for r in drawn if r["label_confidence_tier"] == "gold" and r["id"] in now]
        m["NIrrRemappedRoot"] = sum(
            r["chain"][0]["cwe_id"] != now[r["id"]]["chain"][0]["cwe_id"] for r in dg
        )
        m["NIrrRemappedSink"] = sum(
            r["chain"][-1]["cwe_id"] != now[r["id"]]["chain"][-1]["cwe_id"] for r in dg
        )
        # How the audited release differs from this one, for the paper's description of it.
        m["NIrrToMapped"] = sum(
            r["chain"][0]["cwe_id"] == 20 and now[r["id"]]["chain"][0]["cwe_id"] in (1284, 1285)
            for r in dg
        )
        m["NIrrNowTested"] = sum(
            r["chain"][0].get("site_kind") != "tested-repair-site"
            and now[r["id"]]["chain"][0].get("site_kind") == "tested-repair-site"
            for r in dg
        )
        # The same, split by the snapshot's root kind (1.0.7 moves origin roots by rule).
        m["NIrrNowTestedOrigin"] = sum(
            r["chain"][0].get("site_kind") == "origin-site"
            and now[r["id"]]["chain"][0].get("site_kind") == "tested-repair-site"
            for r in dg
        )
        m["NIrrNowTestedOther"] = m["NIrrNowTested"] - m["NIrrNowTestedOrigin"]
        m["NIrrDropped"] = sum(r["id"] not in now for r in drawn)
        snap = Path("data/irr/snapshot.json")
        if snap.is_file():
            m["IrrSnapshot"] = json.loads(snap.read_text())["drawn"]  # the audited release's date
        m["NIrrGold"] = sum(r["label_confidence_tier"] == "gold" for r in drawn)
        m["NIrrOther"] = len(drawn) - m["NIrrGold"]
        if "NIrrLocated" in m:  # Reproduced-tier items with no located root, outside precision
            m["NIrrGoldUnlocated"] = m["NIrrGold"] - m["NIrrLocated"]
    for k, what in pending.items():
        m.setdefault(k, f"\\textbf{{[pending: {what}]}}")
    lines = ["% Generated by infra/paper/build_macros.py - do not edit."]
    lines += [f"\\newcommand{{\\{k}}}{{{v}\\xspace}}" for k, v in m.items()]
    # The paper's audit text switches itself once a second sheet is scored (PR-9).
    lines.append("\\newif\\ifIrrTwoRaters")
    if Path("paper_artifacts/irr_agreement.json").is_file() and int(m.get("NIrrRaters", 0)) >= 2:
        lines.append("\\IrrTwoRaterstrue")
    Path(args.out).parent.mkdir(parents=True, exist_ok=True)
    Path(args.out).write_text("\n".join(lines) + "\n")
    out = Path(args.out).parent
    (out / "composition.tex").write_text(composition_table(gold, top=4))
    # Not an item the raters will label: the paper must not pre-teach a scored answer.
    rated = set()
    for f in ("data/irr/sample.json", "data/irr/practice/sample.json"):
        if Path(f).is_file():
            rated |= {r["id"] for r in json.loads(Path(f).read_text())}
    (out / "example.tex").write_text(example_record(gold, rated))
    print(f"{len(m)} macros -> {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
