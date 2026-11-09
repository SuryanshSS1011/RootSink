#!/usr/bin/env python3
"""Inter-rater agreement on chain labels: a seeded stratified sample, a blinded packet, a scorer.

The labels in this dataset are produced by a pipeline; the question a reviewer asks is whether a
person reading the same evidence would assign the same chain. Each annotator sees the evidence a
record carries - sanitizer excerpt, fix diff, per-link locations - and NOT our chain, tier or
evidence kinds, then answers three questions per record:

  source_cwe   which CWE the evidence supports as the enabling weakness (or "unclear")
  sink_cwe     which CWE the crash is (or "unclear")
  source_site  which listed site (its number) is where the source weakness is, `other:<file>:
               <function>` for a place not listed, "none" or "unclear"
  sink_site    which listed site (its number) is where the sink manifests, or "none"
  causal       does the evidence support that the source enabled the sink on this input? y/n/unclear
  site_roles   a role for every listed site, `<n>:<role>;...`, role one of defect, repair, crash,
               unrelated, unclear (PR-9 amendment of 2026-10-21)

Location is judged at function granularity: an answer matches a site when file and function are
the same. Line agreement (within three lines) is a secondary measure. A recorded root site counts
as correct strictly when the rater calls it the defect, and leniently when the rater calls it the
defect or an acceptable repair location (a place where a change removes the cause for every
input on this path, not only this crash). "unclear" is never counted as confirmed.

`precision` scores a sheet against the pipeline's labels (blind raters vs the release), giving
per-question precision with a Wilson 95% interval: the Croft et al. (ICSE'23) measure.

Agreement is reported as raw percentage, Cohen's kappa and Gwet's AC1 (kappa alone misleads
under class imbalance, which a CWE-20->CWE-125-heavy corpus has), with 95% bootstrap intervals.

Usage:
  irr.py sample  --n 150 --seed 2027 --out irr/sample.json
  irr.py packet  irr/sample.json --out irr/packet.md --sheet irr/sheet_template.csv
  irr.py score   irr/sheet_A.csv irr/sheet_B.csv

Items are numbered, never named: some record ids encode a CWE (`...525476`), which would unblind.
"""

from __future__ import annotations

import argparse
import collections
import csv
import json
import random
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))

FIELDS = ("source_cwe", "sink_cwe", "source_site", "sink_site", "causal")
ROLES = ("defect", "repair", "crash", "unrelated", "unclear")
CWE_FIELDS = ("source_cwe", "sink_cwe")

# One-line cues per answer, so two experts answer the same question. The vocabulary is the
# catalogue's own (chainforge.cwe); "other:<id>" stays open for anything outside it.
SOURCE_CUES = {
    20: "the fix validates an input-derived value (length, size, count, format) before use",
    129: "the fix bounds-checks an array index specifically",
    190: "the fix stops an arithmetic result wrapping (overflow-checked add/mul, wider type)",
    252: "the fix checks a function's return value that was ignored",
    362: "the fix adds locking/synchronisation around shared state",
    416: "the fix stops memory being used after it is freed (lifetime, refcount, dangling ptr)",
    456: "the fix initialises a variable or buffer that could be read uninitialised",
    476: "the fix adds a NULL check before a dereference",
    843: "the fix checks an object's type/tag before treating it as that type",
}
SINK_CUES = {
    119: "out-of-bounds access whose direction the report does not give",
    125: "out-of-bounds READ (the report says READ, e.g. heap-buffer-overflow READ)",
    787: "out-of-bounds WRITE (the report says WRITE)",
    190: "the report itself is an integer overflow (UBSan 'signed integer overflow')",
    415: "double free",
    416: "use of freed memory, only if the read/write convention below cannot apply",
    457: "use of an uninitialised value (MemorySanitizer use-of-uninitialized-value)",
    476: "NULL pointer dereference (SEGV on a near-zero address)",
}
CODEBOOK = """# Chain-label annotation packet

*Generated from release {release}, the audit snapshot (PREREGISTRATION PR-9, 2026-10-21).*

## What you are asked to do

Each item is one crash from a C/C++ project: the sanitizer report from running the crashing
input on the vulnerable revision, the developer's fix, and the code sites the pipeline recorded.
Read it, then fill one row of the sheet (`sheet_template.csv`). You do not see the dataset's
labels. Please do not look the item up, discuss it with the other annotator, or ask an AI tool.
Expect about 4-5 minutes per item once you are used to the format, so plan several sittings.

A *chain* is two weaknesses (MITRE CWE terminology, primary to resultant): a **source**, the
earlier weakness that makes the crash possible, and a **sink**, the weakness the crash itself
is. Example: a missing length check (CWE-20) lets a copy run past a buffer (CWE-787).

## The six answers

- `sink_cwe`: what weakness is the crash itself? Judge from the sanitizer report. Answer a
  CWE id from the list below, `other:<id>`, or `unclear`.
- `source_cwe`: what earlier weakness does the fix remove? Ask what the fix *enforces*. Same
  answers.
- `sink_site`: which numbered site is where the crash happens? A site number, or `none`.
- `source_site`: where is the source weakness? A site number, or `other:<file>:<function>` if it
  is in a function none of the listed sites is in, or `none`, or `unclear`. Answer at the level of
  the function; the exact line does not need to match.
- `site_roles`: give every listed site one role, as `1:defect;2:crash`. The roles are:
  - `defect`: the weakness itself is here, meaning the check that is missing or wrong, the
    computation that goes wrong, the variable or buffer that is created without being
    initialised, or the free that leaves a pointer dangling.
  - `repair`: the weakness is not here, but a change here would remove its cause for every input
    that reaches this path. A caller that validates a length before passing it on is an example.
  - `crash`: the crash happens here, and a change here would only stop the symptom, for example
    a check placed directly on the failing access.
  - `unrelated`: none of the above.
  - `unclear`: you cannot tell from the packet.
- `causal`: had the fix's check been in place, would this input have been stopped before the
  crash? `y`, `n`, or `unclear`.

Use `unclear` whenever the evidence does not let you decide. It is a valid answer, and a guess
is worse. Use the `note` column for anything that would help explain your answer.

Rules of thumb:
- The sink comes from the report: its error class and READ/WRITE line. The source comes from
  the fix: what condition it adds or what it changes.
- If the fix only adds a check exactly at the crashing access, with no earlier cause visible,
  choose the most specific source cue that fits.
- Ignore whitespace, comments, tests and build changes in the diff.
- An origin site (where a value was created or memory freed) is the `defect` only if the
  weakness is there, for example a declaration that should initialise. If the value should have
  been written later on another path, the origin is `unrelated` or `repair`, and the defect is
  where that write is missing.

Conventions of this dataset (declared modelling choices, so please follow them):
- A use-after-free is recorded as source **416** and sink **125** (if the freed memory is read)
  or **787** (if it is written). The freed-pointer reuse is what enables the access.
- A use of uninitialised memory is recorded as source **456** and sink **457**.
- A NULL dereference that crashes at the dereference itself is **476** as the sink.

## Answer vocabulary

Source:
{source}

Sink:
{sink}
"""


def sample_quota(
    rows: list[dict], quotas: dict[str, int], seed: int, floors: dict[str, int] | None = None
) -> list[dict]:
    """Per tier group (e.g. {"gold": 130, "other": 20}), a stratified sample within each.

    `floors` (GOLD only) first draws at least that many GOLD records per root site kind, so each
    kind's location precision has a usable interval; the rest of the GOLD quota is stratified as
    usual. Oversampled kinds are reweighted to their population share for any all-GOLD figure."""
    out = []
    for group, n in quotas.items():
        pool = [r for r in rows if (r["label_confidence_tier"] == "gold") == (group == "gold")]
        picked: list[dict] = []
        if group == "gold" and floors:
            for kind, k in sorted(floors.items()):
                sub_pool = [r for r in pool if r["chain"][0].get("site_kind") == kind]
                picked += sample(sub_pool, k, seed)
        taken = {r["id"] for r in picked}
        rest = [r for r in pool if r["id"] not in taken]
        picked += sample(rest, n - len(picked), seed)
        out += picked
    random.Random(seed).shuffle(out)
    return out


def sample(rows: list[dict], n: int, seed: int) -> list[dict]:
    """Stratify by tier x chain length x arm, proportional with a floor of one per stratum."""
    rng = random.Random(seed)
    strata = collections.defaultdict(list)
    for r in rows:
        strata[(r["label_confidence_tier"], len(r["chain"]), r["chain_string"])].append(r)
    keys = sorted(strata)
    if n < len(keys):  # fewer items than strata (a practice set): one each from n random strata
        keys = sorted(rng.sample(keys, n))
    alloc = {k: 1 for k in keys}
    rest = n - len(keys)
    total = sum(len(v) for v in strata.values())
    for k in keys:
        alloc[k] += max(0, round(rest * len(strata[k]) / total))
    picked = []
    for k in keys:
        pool = sorted(strata[k], key=lambda r: r["id"])
        picked += rng.sample(pool, min(alloc[k], len(pool)))
    # Rounding the per-stratum allocation can miss n by a few; top up (or trim) at random so the
    # sample has exactly the size the protocol fixes.
    if len(picked) < n:
        ids = {r["id"] for r in picked}
        left = sorted((r for r in rows if r["id"] not in ids), key=lambda r: r["id"])
        picked += rng.sample(left, min(n - len(picked), len(left)))
    picked = picked[:n]
    rng.shuffle(picked)
    return picked


def _excerpt(path: str | None, limit: int = 40) -> str:
    if not path or not Path(path).is_file():
        return "(log not available in the repository)"
    lines = Path(path).read_text(errors="replace").splitlines()
    i = next(
        (
            j
            for j, ln in enumerate(lines)
            if re.search(r"ERROR: \w+Sanitizer|BUG: KASAN|runtime error", ln)
        ),
        0,
    )
    # Our own build paths name the record id; a rater must not be able to look the item up.
    return re.sub(r"/\S*?/CHAINFORGE-[\w-]+/", "/src/", "\n".join(lines[i : i + limit]))


def _hunks_with_content(diff: str) -> str:
    """The diff minus hunks whose changed lines are all whitespace: they carry no evidence and
    cost an annotator time (one item opened on six whitespace-only hunks)."""
    out, hunk = [], []

    def flush():
        changed = [ln[1:] for ln in hunk if ln[:1] in "+-" and not ln.startswith(("+++", "---"))]
        if any(c.strip() for c in changed):
            out.extend(hunk)

    for ln in diff.splitlines():
        if ln.startswith("@@") or ln.startswith("diff --git"):
            flush()
            hunk = []
            if ln.startswith("diff --git"):
                out.append(ln)
                continue
        hunk.append(ln)
    flush()
    return "\n".join(out)


def release_digest() -> str:
    """The release the sample was drawn from, so a stale packet is recognisable."""
    import hashlib

    p = Path("data/release/dataset.jsonl")
    return hashlib.sha256(p.read_bytes()).hexdigest()[:12] if p.is_file() else "unknown"


def _vul_log(r: dict) -> str | None:
    return next(
        (
            s["log_ref"]
            for s in r.get("sanitizer_reports") or []
            if s.get("revision") == "vulnerable"
            and s.get("observed_by") != "upstream"
            and s.get("witnesses") != "intermediate"
            and Path(s.get("log_ref") or "").is_file()
        ),
        None,
    )


def packet(picked: list[dict]) -> str:
    from chainforge.cwe import CWE_NAMES

    def vocab(cues):
        return "\n".join(f"- **{c}** {CWE_NAMES.get(c, '')}: {cue}" for c, cue in cues.items())

    out = [
        CODEBOOK.format(source=vocab(SOURCE_CUES), sink=vocab(SINK_CUES), release=release_digest())
    ]
    for k, r in enumerate(picked, 1):
        vul = _vul_log(r)
        locs = [loc for loc in item_sites(r)]
        out += [
            f"\n---\n\n## Item {k}\n",
            f"Project: {r['project']} ({r['language']})\n",
            "### Sanitizer report (vulnerable revision)\n",
            "```",
            _excerpt(vul),
            "```\n",
            "### Fix diff (whitespace-only hunks removed; first 200 lines)\n",
            "```diff",
            "\n".join(_hunks_with_content(r.get("patch_diff") or "(none)").splitlines()[:200]),
            "```\n",
            "### Sites recorded by the pipeline (unlabelled)\n",
        ]
        out += [
            f"{i}. {loc.get('file')}:{loc.get('line')} ({loc.get('function')})"
            for i, loc in enumerate(locs, 1)
        ] or ["- (none)"]
    return "\n".join(out) + "\n"


def item_sites(r: dict) -> list[dict]:
    """The record's distinct link sites in a fixed but chain-order-free order (sorted), so the
    position of a site does not reveal which link it belongs to."""
    seen = {}
    for c in r["chain"]:
        loc = (c.get("evidence") or {}).get("location")
        if loc and loc.get("file"):
            seen[(loc["file"], loc.get("line"))] = loc
    return [seen[k] for k in sorted(seen, key=lambda k: (k[0], k[1] or 0))]


def truth(r: dict) -> dict:
    """What the pipeline claims, in the sheet's terms."""
    sites = item_sites(r)

    def site_no(c):
        loc = (c.get("evidence") or {}).get("location") or {}
        key = (loc.get("file"), loc.get("line"))
        return next(
            (str(i) for i, s in enumerate(sites, 1) if (s["file"], s.get("line")) == key), "none"
        )

    return {
        "root_kind": r["chain"][0].get("site_kind") or "none",
        "root_fn": _fn_key((r["chain"][0].get("evidence") or {}).get("location") or {}),
        "sites": [_fn_key(s) for s in sites],
        "source_cwe": str(r["chain"][0]["cwe_id"]),
        "sink_cwe": str(r["chain"][-1]["cwe_id"]),
        "source_site": site_no(r["chain"][0]),
        "sink_site": site_no(r["chain"][-1]),
        "causal": "y",
    }


def _fn_key(loc: dict) -> tuple[str, str] | None:
    """(file basename, bare function) for function-granularity matching, or None."""
    from chainforge.evidence import bare_function

    f, fn = loc.get("file"), bare_function(loc.get("function"))
    return (Path(f).name, fn) if f and fn else None


def _answer_fn(ans: str, sites: list) -> tuple[str, str] | None:
    """A source_site answer as (file basename, function): a listed number or other:<f>:<fn>."""
    a = ans.strip()
    if a.isdigit() and 1 <= int(a) <= len(sites):
        return sites[int(a) - 1]
    if a.lower().startswith("other:") and a.count(":") >= 2:
        _, f, fn = a.split(":", 2)
        return (Path(f.strip()).name, fn.strip().split("(")[0])
    return None


def _roles(cell: str) -> dict[int, str]:
    out = {}
    for part in (cell or "").split(";"):
        n, _, role = part.partition(":")
        if n.strip().isdigit() and role.strip().lower() in ROLES:
            out[int(n)] = role.strip().lower()
    return out


def location_precision(sheet: list[dict], picked: list[dict], gold: bool | None = None) -> dict:
    """PR-9 amendment (2026-10-21): is the recorded root site right, by root site kind?

    function_match  the rater's source_site names the same (file, function) as the recorded root
    strict          the rater's role for the recorded root site is `defect`
    lenient         ... is `defect` or `repair`
    unclear_rate    the rater's role for it is `unclear`, or no role was given
    Every rate has a Wilson 95% interval; unclear never counts as confirmed."""
    truths = {
        f"item-{k}": truth(r)
        for k, r in enumerate(picked, 1)
        if gold is None or (r["label_confidence_tier"] == "gold") == gold
    }
    groups: dict[str, list[tuple[dict, dict]]] = collections.defaultdict(list)
    for s in sheet:
        t = truths.get(s["id"])
        if t and t["root_fn"]:
            groups[t["root_kind"]].append((s, t))
            groups["all located roots"].append((s, t))
    out = {}
    for kind, items in groups.items():
        fm = st = le = un = 0
        for s, t in items:
            fm += _answer_fn(s.get("source_site", ""), t["sites"]) == t["root_fn"]
            idx = next((i for i, f in enumerate(t["sites"], 1) if f == t["root_fn"]), None)
            role = _roles(s.get("site_roles", "")).get(idx, "unclear") if idx else "unclear"
            st += role == "defect"
            le += role in ("defect", "repair")
            un += role == "unclear"
        n = len(items)
        out[kind] = {
            "n": n,
            "function_match": _rate(fm, n),
            "strict": _rate(st, n),
            "lenient": _rate(le, n),
            "unclear_rate": _rate(un, n),
        }
    return out


def wilson(k: int, n: int, z: float = 1.96) -> tuple[float, float]:
    if not n:
        return (0.0, 0.0)
    p = k / n
    d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    h = z * ((p * (1 - p) / n + z * z / (4 * n * n)) ** 0.5) / d
    return (round(c - h, 3), round(c + h, 3))


def precision(sheet: list[dict], picked: list[dict], current: dict | None = None) -> dict:
    """Per question: share of items where a blind rater agrees with the pipeline, Wilson CI.
    "unclear" counts as disagreement - a label a reader cannot confirm is not confirmed.

    Primary measures use the snapshot labels in `picked` (PR-9 amendment of 2026-10-24). With
    `current` (record id -> current release record), the CWE questions also report
    hierarchy-compatible agreement with the current label, which differs where PR-17 remapped."""
    by_item = {f"item-{k}": truth(r) for k, r in enumerate(picked, 1)}
    now = {
        f"item-{k}": truth(current[r["id"]])
        for k, r in enumerate(picked, 1)
        if current and r["id"] in current
    }
    tier = {f"item-{k}": r["label_confidence_tier"] for k, r in enumerate(picked, 1)}
    out = {}
    for group in ("all", "gold", "not gold"):
        g = {}
        for f in FIELDS:
            rows = [
                s
                for s in sheet
                if s["id"] in by_item
                and s[f].strip()
                and (group == "all" or (tier[s["id"]] == "gold") == (group == "gold"))
            ]
            k = sum(_answer(s[f]) == by_item[s["id"]][f] for s in rows)
            g[f] = {"n": len(rows), "agree": k, "precision": _rate(k, len(rows))}
            if f in CWE_FIELDS:  # PR-9 secondary: same CWE line (one is-a the other)
                h = sum(compatible(_answer(s[f]), by_item[s["id"]][f]) for s in rows)
                g[f]["hierarchy_compatible"] = {"agree": h, "precision": _rate(h, len(rows))}
                if now:
                    cur = [s for s in rows if s["id"] in now]
                    hc = sum(compatible(_answer(s[f]), now[s["id"]][f]) for s in cur)
                    g[f]["hierarchy_compatible_current"] = {
                        "agree": hc,
                        "precision": _rate(hc, len(cur)),
                    }
        out[group] = g
    out["location"] = location_precision(sheet, picked)
    # PR-9 sets its site-kind floors on GOLD, so site precision is reported per tier group too.
    out["location_gold"] = location_precision(sheet, picked, gold=True)
    out["location_not_gold"] = location_precision(sheet, picked, gold=False)
    out["gold_by_root_kind"] = by_root_kind(sheet, picked)
    if current is not None:
        out["location_gold_current"] = location_precision_current(sheet, picked, current)
    return out


def location_precision_current(sheet: list[dict], picked: list[dict], current: dict) -> dict:
    """Sensitivity: the same judgments scored against the current release's root sites.

    Only items that are GOLD in both the snapshot and the current release count. The role is read
    at the site number the rater saw (the snapshot's list) that names the current root, so a
    root that moved or changed kind is scored where it now stands. Strict = `defect`."""
    groups: dict[str, list[str]] = collections.defaultdict(list)
    for k, r in enumerate(picked, 1):
        c = current.get(r["id"])
        if r["label_confidence_tier"] != "gold" or not c or c["label_confidence_tier"] != "gold":
            continue
        ts, tc = truth(r), truth(c)
        if not tc["root_fn"]:
            continue
        s = next((x for x in sheet if x["id"] == f"item-{k}"), None)
        if s is None:
            continue
        idx = next((i for i, f in enumerate(ts["sites"], 1) if f == tc["root_fn"]), None)
        role = _roles(s.get("site_roles", "")).get(idx, "unclear") if idx else "unclear"
        groups[tc["root_kind"]].append(role)
        groups["all located roots"].append(role)
    return {
        kind: {
            "n": len(roles),
            "strict": _rate(sum(x == "defect" for x in roles), len(roles)),
            "lenient": _rate(sum(x in ("defect", "repair") for x in roles), len(roles)),
        }
        for kind, roles in groups.items()
    }


def by_root_kind(sheet: list[dict], picked: list[dict]) -> dict:
    """GOLD only, per root site kind: source-CWE agreement (exact, hierarchy-compatible), and for
    a rater who placed the source in an unlisted function, whether the fix edits that function or
    its file (hunk headers and file headers of the record's own diff)."""
    rows = {s["id"]: s for s in sheet}
    out: dict[str, collections.Counter] = collections.defaultdict(collections.Counter)
    for k, r in enumerate(picked, 1):
        s = rows.get(f"item-{k}")
        if not s or r["label_confidence_tier"] != "gold":
            continue
        t = truth(r)
        c = out[t["root_kind"] if t["root_fn"] else "unlocated"]
        c["n"] += 1
        c["source_cwe_exact"] += _answer(s["source_cwe"]) == t["source_cwe"]
        c["source_cwe_compatible"] += compatible(_answer(s["source_cwe"]), t["source_cwe"])
        ans = s.get("source_site", "").strip()
        if ans.startswith("other:") and ans.count(":") >= 2:
            _, f, fn = ans.split(":", 2)
            diff = r.get("patch_diff") or ""
            fns = {
                m.group(1).split("::")[-1]
                for m in re.finditer(r"^@@[^@]*@@.*?([A-Za-z_][\w:~]*)\s*\(", diff, re.M)
            }
            files = set(re.findall(r"^diff --git a/(\S+)", diff, re.M))
            if fn.split("::")[-1] in fns:
                c["other_site_in_fix_function"] += 1
            elif any(f.endswith(x) or x.endswith(f) for x in files):
                c["other_site_in_fix_file_only"] += 1
            else:
                c["other_site_elsewhere"] += 1
    return {k: dict(v) for k, v in out.items()}


def _answer(cell: str) -> str:
    v = cell.strip().lower().removeprefix("cwe-").removeprefix("other:").strip()
    return v.removeprefix("cwe-")


def _rate(k: int, n: int) -> dict:
    return {"value": round(k / n, 3) if n else None, "wilson95": wilson(k, n)}


def compatible(a: str, b: str) -> bool:
    """Same CWE, or one is an ancestor of the other in MITRE View-1000 (ChildOf). 125 vs 119
    agrees (125 is-a 119); 125 vs 787 does not."""
    from chainforge.mitre_chains import _ancestors

    if a == b:
        return True
    if not (a.isdigit() and b.isdigit()):
        return False
    x, y = int(a), int(b)
    return x in _ancestors(y) or y in _ancestors(x)


def _kappa(a: list, b: list) -> float:
    n = len(a)
    po = sum(x == y for x, y in zip(a, b, strict=True)) / n
    ca, cb = collections.Counter(a), collections.Counter(b)
    pe = sum(ca[c] * cb[c] for c in set(a) | set(b)) / (n * n)
    return 1.0 if pe == 1 else (po - pe) / (1 - pe)


def _ac1(a: list, b: list) -> float:
    n, cats = len(a), set(a) | set(b)
    po = sum(x == y for x, y in zip(a, b, strict=True)) / n
    if len(cats) < 2:
        return 1.0
    pi = {c: (a.count(c) + b.count(c)) / (2 * n) for c in cats}
    pe = sum(p * (1 - p) for p in pi.values()) / (len(cats) - 1)
    return (po - pe) / (1 - pe)


def _ci(a: list, b: list, stat, reps: int = 2000, seed: int = 0) -> tuple[float, float]:
    rng, idx, vals = random.Random(seed), range(len(a)), []
    for _ in range(reps):
        s = [rng.choice(idx) for _ in idx]
        vals.append(stat([a[i] for i in s], [b[i] for i in s]))
    vals.sort()
    return vals[int(0.025 * reps)], vals[int(0.975 * reps) - 1]


def score(sheet_a: list[dict], sheet_b: list[dict]) -> dict:
    a = {r["id"]: r for r in sheet_a}
    b = {r["id"]: r for r in sheet_b}
    ids = sorted(set(a) & set(b))
    out = {"n": len(ids)}
    for f in FIELDS:
        x = [_answer(a[i][f]) for i in ids]
        y = [_answer(b[i][f]) for i in ids]
        pct = lambda p, q: sum(u == v for u, v in zip(p, q, strict=True)) / len(p)  # noqa: E731
        out[f] = {
            "agreement": round(pct(x, y), 3),
            "agreement_ci": [round(v, 3) for v in _ci(x, y, pct)],
            "kappa": round(_kappa(x, y), 3),
            "kappa_ci": [round(v, 3) for v in _ci(x, y, _kappa)],
            "ac1": round(_ac1(x, y), 3),
            "ac1_ci": [round(v, 3) for v in _ci(x, y, _ac1)],
        }
    return out


def site_detail(sheet_a: list[dict], sheet_b: list[dict], picked: list[dict]) -> dict:
    """How `score`'s source_site agreement is made up, and the same agreement at function level.

    `score` compares answers as written, so `3` and `other:<file>:<function>` naming site 3's
    function disagree, and two `unclear` answers agree. Here an answer that names a function (a
    listed number or other:<file>:<function>) is resolved to (file basename, function), the
    granularity precision uses; any other answer (none, unclear) is compared as written. Added
    after scoring (rule log, 2026-11-08), so it is a descriptive figure, not a planned measure.
    Also counts blank answers and listed sites left without a role, which precision treats as
    unclear."""
    a = {r["id"]: r for r in sheet_a}
    b = {r["id"]: r for r in sheet_b}
    ids = sorted(set(a) & set(b))
    fn_agree = both_unclear = blank = no_role = 0
    for i in ids:
        r = picked[int(i.split("-")[1]) - 1]
        listed = item_sites(r)
        sites = [_fn_key(loc) for loc in listed]
        x, y = a[i]["source_site"].strip().lower(), b[i]["source_site"].strip().lower()
        fx, fy = _answer_fn(x, sites), _answer_fn(y, sites)
        fn_agree += (fx == fy) if fx is not None and fy is not None else (_answer(x) == _answer(y))
        both_unclear += _answer(x) == _answer(y) == "unclear"
        for s in (a[i], b[i]):
            blank += sum(not s.get(f, "").strip() for f in (*FIELDS, "site_roles"))
            roles = _roles(s.get("site_roles", ""))
            no_role += sum(k not in roles for k in range(1, len(listed) + 1))
    n = len(ids)
    return {
        "n": n,
        "function_agreement": round(fn_agree / n, 3) if n else None,
        "function_agree_n": fn_agree,
        "as_written_both_unclear": both_unclear,
        "blank_answers": blank,
        "sites_without_role": no_role,
    }


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("sample")
    s.add_argument("--release", default="data/release/dataset.jsonl")
    s.add_argument("--n", type=int, default=150)
    s.add_argument("--gold", type=int, default=None, help="quota: GOLD records")
    s.add_argument("--other", type=int, default=None, help="quota: non-GOLD records")
    s.add_argument(
        "--floor",
        action="append",
        default=[],
        help="GOLD floor per root site kind, as kind:n (repeatable)",
    )
    s.add_argument("--seed", type=int, default=2027)
    s.add_argument("--exclude", help="a sample whose records may not be drawn (practice items)")
    s.add_argument("--out", required=True)
    p = sub.add_parser("packet")
    p.add_argument("sample")
    p.add_argument("--out", required=True)
    p.add_argument("--sheet", required=True)
    q = sub.add_parser("precision")
    q.add_argument("sheet")
    q.add_argument("sample")
    q.add_argument("--current", help="current release, for agreement with remapped labels")
    c = sub.add_parser("score")
    c.add_argument("sheet_a")
    c.add_argument("sheet_b")
    args = ap.parse_args(argv)

    if args.cmd == "sample":
        with open(args.release) as fh:
            rows = [json.loads(line) for line in fh]
        # An item an expert cannot judge from the packet is not a test of the label: draw only
        # records whose vulnerable-side report is archived here.
        rows = [r for r in rows if _vul_log(r)]
        if args.exclude:
            taken = {r["id"] for r in json.loads(Path(args.exclude).read_text())}
            rows = [r for r in rows if r["id"] not in taken]
        picked = (
            sample_quota(
                rows,
                {"gold": args.gold, "other": args.other},
                args.seed,
                {k: int(v) for k, v in (f.split(":") for f in args.floor)},
            )
            if args.gold is not None
            else sample(rows, args.n, args.seed)
        )
        Path(args.out).parent.mkdir(parents=True, exist_ok=True)
        Path(args.out).write_text(json.dumps(picked))
        print(f"{len(picked)} records -> {args.out}")
    elif args.cmd == "packet":
        picked = json.loads(Path(args.sample).read_text())
        Path(args.out).write_text(packet(picked))
        with open(args.sheet, "w", newline="") as fh:
            w = csv.writer(fh)
            w.writerow(["id", *FIELDS, "site_roles", "note"])
            w.writerows(
                [[f"item-{k}", *[""] * len(FIELDS), "", ""] for k in range(1, len(picked) + 1)]
            )
        print(f"packet -> {args.out}; blank sheet -> {args.sheet}")
    elif args.cmd == "precision":
        with open(args.sheet) as fh:
            sheet = list(csv.DictReader(fh))
        picked = json.loads(Path(args.sample).read_text())
        cur = None
        if args.current:
            with open(args.current) as fh:
                cur = {r["id"]: r for r in map(json.loads, fh)}
        print(json.dumps(precision(sheet, picked, cur), indent=1))
    else:
        load = lambda p: list(csv.DictReader(open(p)))  # noqa: E731, SIM115
        print(json.dumps(score(load(args.sheet_a), load(args.sheet_b)), indent=1))
    return 0


if __name__ == "__main__":
    sys.exit(main())
