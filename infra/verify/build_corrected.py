#!/usr/bin/env python3
"""Build the authority-grounded corrected dataset from the 2618 consolidated base.

Corrections (all grounded in MITRE v4.20 / NVD / reproduced crash witness):
  ARVO (crash witness):
    - buffer-overflow READ/WRITE  -> sink 125 / 787 (fix 6 direction errors)
    - use-after-free WRITE        -> keep ->787  (MITRE 416 CanPrecede 123/120)
    - use-after-free READ         -> terminal CWE-416 (MITRE gives 416 no read successor)
  osv-git (NVD authority; distrust the over-assigned 416 source):
    - chain kept iff NVD attests an admissible pair, or a non-416 dataflow source is
      admissible with NVD's memory-safety sink; else single-weakness (NVD sink) or drop.

Outputs (nothing overwritten): out/corrected_chains.jsonl, out/single_weakness.jsonl,
out/dropped.jsonl, out/changelog.jsonl, and prints a composition report.

Paths default to the local pull; override via argv: <dataset> <artifact_dir> <repo_src> <out_dir>
"""

import collections
import json
import os
import re
import sys

DATASET = sys.argv[1] if len(sys.argv) > 1 else "scratchpad/roar/dataset.jsonl"
ART = sys.argv[2] if len(sys.argv) > 2 else "scratchpad/roar"
SRC = sys.argv[3] if len(sys.argv) > 3 else "src"
OUT = sys.argv[4] if len(sys.argv) > 4 else "scratchpad/roar/out"
sys.path.insert(0, SRC)
from chainforge.cwe import ADMISSIBLE_PAIRS, CWE_NAMES, validate_chain  # noqa: E402

os.makedirs(OUT, exist_ok=True)
CATALOG = set(CWE_NAMES)
MS = {125, 787, 416, 476, 119, 415}
OOB = {
    "heap-buffer-overflow",
    "stack-buffer-overflow",
    "global-buffer-overflow",
    "dynamic-stack-buffer-overflow",
}


def loadl(p):
    with open(p) as fh:
        return [json.loads(x) for x in fh]


def load(p):
    with open(p) as fh:
        return json.load(fh)


rows = loadl(DATASET)
facts = load(f"{ART}/facts_by_id.json")
nvd = load(f"{ART}/nvd_cache.json")


def seq(r):
    return [
        c.get("cwe_id") for c in (r.get("chain") or []) if isinstance(c, dict) and c.get("cwe_id")
    ]


def arvo_id(r):
    """Recover the ARVO/OSS-Fuzz local id for a record.

    Must check the aliases too, not just docker_image_ref: 93 records (arvo-len3,
    arvo-newarm) are ARVO-backed but ship an EMPTY docker_image_ref, carrying only an
    `OSS-Fuzz-<id>` alias. Matching on the image ref alone silently skipped them, so
    they were never sink-corrected or patch-joined - two shipped as ->787 when the
    reproduced witness was a READ (CWE-125).
    """
    m = re.search(r"arvo:(\d+)-", json.dumps(r.get("docker_image_ref") or {}))
    if m:
        return m.group(1)
    m = re.search(r"OSS-Fuzz-(\d+)", json.dumps(r.get("aliases") or []))
    return m.group(1) if m else None


def cves_of(r):
    return set(re.findall(r"CVE-\d{4}-\d+", json.dumps(r.get("aliases") or []) + str(r["id"])))


def nvd_set(r):
    n = set()
    for c in cves_of(r):
        n |= set(nvd.get(c, {}).get("all", []))
    return {c for c in n if c in CATALOG}


def set_chain(r, cwes):
    """Rewrite r['chain'] to the given cwe list, preserving each hop's evidence where possible."""
    old = r.get("chain") or []
    roles = (
        ["source"] + ["intermediate"] * (len(cwes) - 2) + ["sink"] if len(cwes) > 1 else ["sink"]
    )
    newch = []
    for i, c in enumerate(cwes):
        ev = old[i].get("evidence") if i < len(old) and isinstance(old[i], dict) else None
        newch.append({"cwe_id": c, "role": roles[i], "evidence": ev})
    r = dict(r)
    r["chain"] = newch
    r["chain_string"] = "->".join(f"CWE-{c}" for c in cwes)
    return r


def relabel_osv(r):
    N = nvd_set(r)
    S = (seq(r) or [None])[0]
    if not N:
        return None, "drop-no-inscope"
    prs = sorted(
        [(a, b) for a in N for b in N if (a, b) in ADMISSIBLE_PAIRS],
        key=lambda p: (p[1] not in MS,),
    )
    if prs:
        return list(prs[0]), "chain-nvd-pair"
    ms = [c for c in N if c in MS]
    if S and S != 416 and ms:
        for k in ms:
            if (S, k) in ADMISSIBLE_PAIRS:
                return [S, k], "chain-dataflow-src"
    for k in (787, 416, 125, 476, 119, 415):
        if k in ms:
            return [k], "single-weakness"
    return None, f"drop-nonMS-{sorted(N)}"


chains, singles, dropped, changelog = [], [], [], []
stat = collections.Counter()

for r in rows:
    prov = r.get("provenance")
    rid = r["id"]
    s = seq(r)
    # --- ARVO crash-witness corrections ---
    aid = arvo_id(r)
    f = facts.get(aid) if aid else None
    if f and f.get("bug_class"):
        cls, d = f["bug_class"], f.get("direction")
        if cls in OOB and d in ("READ", "WRITE"):
            want = 125 if d == "READ" else 787
            if s and s[-1] != want:
                r = set_chain(r, s[:-1] + [want])
                changelog.append(
                    {
                        "id": rid,
                        "op": "oob-direction",
                        "from": "->".join(map(str, s)),
                        "to": r["chain_string"],
                    }
                )
                stat["arvo-oob-direction-fixed"] += 1
            chains.append(r)
            stat["arvo-chain"] += 1
            continue
        if cls in ("heap-use-after-free", "use-after-free"):
            if d == "WRITE":
                chains.append(r)
                stat["arvo-uaf-write-keep"] += 1
            else:  # UAF READ -> terminal 416
                r2 = set_chain(r, [416])
                changelog.append(
                    {
                        "id": rid,
                        "op": "uaf-read-collapse",
                        "from": "->".join(map(str, s)),
                        "to": "416",
                    }
                )
                singles.append(r2)
                stat["arvo-uaf-read-collapsed"] += 1
            continue
        chains.append(r)
        stat["arvo-other-keep"] += 1
        continue
    # --- osv-git NVD relabel ---
    if prov in ("osv-git", "osv-git-len3"):
        ch, kind = relabel_osv(r)
        if ch is None:
            dropped.append({"id": rid, "reason": kind, "was": "->".join(map(str, s))})
            stat["osv-drop"] += 1
        elif len(ch) == 1:
            r2 = set_chain(r, ch)
            if "->".join(map(str, ch)) != "->".join(map(str, s)):
                changelog.append(
                    {
                        "id": rid,
                        "op": "osv-single",
                        "from": "->".join(map(str, s)),
                        "to": r2["chain_string"],
                    }
                )
            singles.append(r2)
            stat["osv-single-weakness"] += 1
        else:
            r2 = set_chain(r, ch)
            if "->".join(map(str, ch)) != "->".join(map(str, s)):
                changelog.append(
                    {
                        "id": rid,
                        "op": "osv-rechain",
                        "from": "->".join(map(str, s)),
                        "to": r2["chain_string"],
                    }
                )
            chains.append(r2)
            stat["osv-chain"] += 1
        continue
    # --- everything else unchanged ---
    chains.append(r)
    stat[f"keep-{prov}"] += 1


# Final admissibility guard: any chain rendered inadmissible by a correction
# (e.g. a 476-source dual-view whose sink flipped to 125) is superseded by its
# primary view -> route to dropped rather than ship an inadmissible chain.
_valid = []
for r in chains:
    cseq = seq(r)
    if len(cseq) >= 2 and validate_chain(cseq).admissible:
        _valid.append(r)
    else:
        dropped.append(
            {"id": r["id"], "reason": "inadmissible-after-correction", "was": r.get("chain_string")}
        )
        stat["dropped-inadmissible"] += 1
chains = _valid


def dumpl(p, items):
    with open(p, "w") as fh:
        for x in items:
            fh.write(json.dumps(x) + "\n")


dumpl(f"{OUT}/corrected_chains.jsonl", chains)
dumpl(f"{OUT}/single_weakness.jsonl", singles)
dumpl(f"{OUT}/dropped.jsonl", dropped)
dumpl(f"{OUT}/changelog.jsonl", changelog)


def tier(x):
    return (x.get("label_confidence_tier") or "").lower()


print("=== INPUT ===", len(rows), "records")
print("=== OUTPUT ===")
print(
    f"  corrected_chains : {len(chains):5d}  (gold {sum(1 for r in chains if tier(r) == 'gold')})"
)
print(
    f"  single_weakness  : {len(singles):5d}  (gold {sum(1 for r in singles if tier(r) == 'gold')})"
)
print(f"  dropped          : {len(dropped):5d}")
print(f"  changelog entries: {len(changelog)}")
print("\n=== ops ===")
for k, c in stat.most_common():
    print(f"  {c:5d}  {k}")
print("\n=== corrected chain arms (top) ===")
arms = collections.Counter("->".join(map(str, seq(r))) for r in chains)
for a, c in arms.most_common(14):
    print(f"  {c:5d}  {a}")
