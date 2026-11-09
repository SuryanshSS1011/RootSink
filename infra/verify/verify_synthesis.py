#!/usr/bin/env python3
"""Synthesize label verification for the 2618 dataset against three authorities:
  1. MITRE v4.20 CWE catalog (CanPrecede/CanFollow/ChildOf) -- chain admissibility
  2. NVD REST API CVE->CWE assignments                      -- CVE-bearing records
  3. Reproduced sanitizer crash class+direction             -- ARVO records with logs
Emits a report + a grounded relabel proposal. Mutates nothing.
"""

import collections
import json
import re
import xml.etree.ElementTree as ET

R = "scratchpad/roar"


def load(p):
    with open(p) as fh:
        return json.load(fh)


def loadl(p):
    with open(p) as fh:
        return [json.loads(x) for x in fh]


# ---- MITRE relations ----
root = ET.parse(f"{R}/cwec_v4.20.xml").getroot()
NS = root.tag.split("}")[0].strip("{")
canprecede, canfollow, childof = set(), set(), set()
for w in root.iter(f"{{{NS}}}Weakness"):
    wid = int(w.get("ID"))
    rw = w.find(f"{{{NS}}}Related_Weaknesses")
    if rw is None:
        continue
    for rel in rw.findall(f"{{{NS}}}Related_Weakness"):
        t = rel.get("CWE_ID")
        if not t:
            continue
        t = int(t)
        n = rel.get("Nature")
        if n == "CanPrecede":
            canprecede.add((wid, t))
        elif n == "CanFollow":
            canfollow.add((wid, t))
        elif n == "ChildOf":
            childof.add((wid, t))
precede = canprecede | {(y, x) for x, y in canfollow}


def ancestors(c, seen=None):
    seen = seen if seen is not None else set()
    for x, y in childof:
        if x == c and y not in seen:
            seen.add(y)
            ancestors(y, seen)
    return seen


def mitre_edge(x, y):
    if (x, y) in precede:
        return "direct"
    if any((x, a) in precede for a in (ancestors(y) | {y})):
        return "transitive"
    if (x, y) in childof or (y, x) in childof:
        return "hierarchy"
    return "catalog-only"


# ---- data ----
rows = loadl(f"{R}/dataset.jsonl")
facts = load(f"{R}/facts_by_id.json")
nvd = load(f"{R}/nvd_cache.json")
IN = {20, 119, 125, 190, 416, 476, 787, 362, 129, 843, 252, 415}


def seq(r):
    return [
        c.get("cwe_id") for c in (r.get("chain") or []) if isinstance(c, dict) and c.get("cwe_id")
    ]


def arvo_id(r):
    m = re.search(r"arvo:(\d+)-", json.dumps(r.get("docker_image_ref") or {}))
    return m.group(1) if m else None


def cves_of(r):
    blob = (
        json.dumps(r.get("aliases") or [])
        + json.dumps(r.get("related_records") or [])
        + str(r.get("id"))
    )
    return set(re.findall(r"CVE-\d{4}-\d+", blob))


OOB = {
    "heap-buffer-overflow",
    "stack-buffer-overflow",
    "global-buffer-overflow",
    "dynamic-stack-buffer-overflow",
}
mitre_stat = collections.Counter()
witness_stat = collections.Counter()
nvd_stat = collections.Counter()
relabels = []
flags = []

for r in rows:
    s = seq(r)
    rid = r["id"]
    tier = (r.get("label_confidence_tier") or "").lower()
    # 1. MITRE grounding of the chain
    kinds = [mitre_edge(a, b) for a, b in zip(s, s[1:], strict=False)]
    key = (
        "len-1"
        if not kinds
        else ("all-mitre" if all(k != "catalog-only" for k in kinds) else "has-catalog-only")
    )
    mitre_stat[key] += 1

    # 2. crash witness (ARVO)
    aid = arvo_id(r)
    f = facts.get(aid) if aid else None
    if f and f.get("bug_class"):
        cls, d = f["bug_class"], f.get("direction")
        cur_sink = s[-1] if s else None
        if cls in OOB:
            want = 125 if d == "READ" else 787 if d == "WRITE" else None
            if want and cur_sink != want:
                witness_stat[f"OOB sink {cur_sink}->{want}"] += 1
                relabels.append(
                    {
                        "id": rid,
                        "kind": "oob-direction",
                        "from": s,
                        "to": s[:-1] + [want],
                        "why": f"witness {cls} {d} -> CWE-{want}",
                        "tier": tier,
                    }
                )
            else:
                witness_stat["OOB sink already correct"] += 1
        elif cls in ("heap-use-after-free", "use-after-free"):
            src = s[0] if s else None
            if d == "WRITE":
                witness_stat["UAF-WRITE keep ->787 (MITRE 416->123/120)"] += 1
            elif src == 362:
                relabels.append(
                    {
                        "id": rid,
                        "kind": "uaf-read->362-416",
                        "from": s,
                        "to": [362, 416],
                        "why": "UAF-READ; 362->416 is MITRE-direct",
                        "tier": tier,
                    }
                )
                witness_stat["UAF-READ -> 362->416 (MITRE-direct)"] += 1
            else:
                why = f"UAF-READ; no MITRE source->416 for CWE-{src}; collapse to terminal 416"
                relabels.append(
                    {
                        "id": rid,
                        "kind": "uaf-read->terminal-416",
                        "from": s,
                        "to": [416],
                        "why": why,
                        "tier": tier,
                    }
                )
                witness_stat["UAF-READ -> terminal 416 (collapse)"] += 1

    # 3. NVD (CVE-bearing)
    cs = cves_of(r)
    ncwes = set()
    for cve in cs:
        ncwes |= set(nvd.get(cve, {}).get("all", []))
    if cs:
        if not ncwes:
            nvd_stat["NVD has no CWE (noinfo)"] += 1
        elif set(s) & ncwes:
            nvd_stat["AGREE (>=1 chain CWE in NVD)"] += 1
        elif ncwes & IN:
            nvd_stat["DISAGREE (NVD in-scope CWE not in chain)"] += 1
            flags.append(
                {
                    "id": rid,
                    "kind": "nvd-disagree",
                    "chain": s,
                    "nvd_cwes": sorted(ncwes & IN),
                    "tier": tier,
                }
            )
        else:
            nvd_stat["NVD only out-of-scope"] += 1

    # 476-as-source flag (MITRE: 476 terminal)
    if s and s[0] == 476:
        flags.append({"id": rid, "kind": "476-source-not-mitre", "chain": s, "tier": tier})

with open(f"{R}/relabel_proposal.json", "w") as fh:
    json.dump(relabels, fh, indent=0)
with open(f"{R}/flags.json", "w") as fh:
    json.dump(flags, fh, indent=0)

print("=== 1. MITRE chain grounding (2618) ===")
for k, c in mitre_stat.most_common():
    print(f"  {c:5d}  {k}")
print("\n=== 2. crash-witness sink check (ARVO w/ logs) ===")
for k, c in witness_stat.most_common():
    print(f"  {c:5d}  {k}")
print("\n=== 3. NVD agreement (CVE records) ===")
for k, c in nvd_stat.most_common():
    print(f"  {c:5d}  {k}")
print(f"\nproposed relabels: {len(relabels)}  | flags: {len(flags)}")
print("  relabels by kind:", dict(collections.Counter(x["kind"] for x in relabels)))
print("  flags by kind:", dict(collections.Counter(x["kind"] for x in flags)))
