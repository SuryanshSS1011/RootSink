"""Map the 25 SILVER race CVEs -> syzbot bugs (via fix-commit SHA) to find C reproducers.

A race is GOLD-reproducible only if syzbot has a bug for it WITH a C reproducer. Match by
fix-commit SHA (the strongest key: my NVD fix_refs carry the commit; syzbot fixed-bugs lists
fix-commits per bug). Report which of the 25 map to a syzbot extid + whether it has a repro.
"""

from __future__ import annotations

import json
import os
import re

HERE = os.path.dirname(os.path.abspath(__file__))


def shas_from_refs(refs: list[str]) -> set[str]:
    out = set()
    for u in refs:
        for m in re.finditer(r"[0-9a-f]{12,40}", u):
            out.add(m.group(0)[:12])  # 12-char prefix for robust matching
    return out


# my SILVER race CVEs + their fix-commit SHAs
with open(f"{HERE}/race_arm_tiered.jsonl") as fh:
    rows = [json.loads(x) for x in fh]
silver = {}
for r in rows:
    if r.get("tier") == "SILVER":
        silver.setdefault(r["cve"], set()).update(shas_from_refs(r.get("fix_refs", [])))

# syzbot fixed bugs: build sha-prefix -> (extid, has_repro)
with open(f"{HERE}/syz_fixed.json") as fh:
    syz = json.load(fh)

sha_to_bug = {}
for bug in syz.get("Bugs", []):
    link = bug.get("link", "")
    m = re.search(r"extid=([a-f0-9]+)", link)
    extid = m.group(1) if m else None
    # repro availability flags vary by schema version; check common keys
    has_c = bool(
        bug.get("c-repro") or bug.get("c_repro") or bug.get("has-c-repro") or bug.get("repro-c")
    )
    for fc in bug.get("fix-commits", []) or []:
        h = fc.get("hash") or fc.get("hash-full") or ""
        title = fc.get("title", "")
        for m2 in re.finditer(r"[0-9a-f]{12,40}", h):
            sha_to_bug[m2.group(0)[:12]] = (extid, has_c, title)

print(f"syzbot fixed bugs: {len(syz.get('Bugs', []))}, indexed fix-commit SHAs: {len(sha_to_bug)}")
print(f"SILVER race CVEs: {len(silver)}\n")

matched = 0
for cve, shas in sorted(silver.items()):
    hit = None
    for s in shas:
        if s in sha_to_bug:
            hit = sha_to_bug[s]
            break
    if hit:
        matched += 1
        extid, has_c, title = hit
        print(f"  {cve}: syzbot extid={extid} c-repro={has_c}  [{title[:40]}]")
    else:
        print(f"  {cve}: no syzbot fix-commit match ({len(shas)} shas)")

print(f"\nMATCHED to syzbot: {matched}/{len(silver)}")
