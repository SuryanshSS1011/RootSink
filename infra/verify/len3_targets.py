"""List the length-3 chain cases and their ARVO build metadata.

Run on ROAR (needs arvo.db + dataset_patched.jsonl). Emits len3_targets.json, the
work-list for the Docker-only UBSan rebuild that witnesses the CWE-190 middle link.
"""

import collections
import json
import re
import sqlite3


def read_jsonl(path):
    with open(path) as fh:
        return [json.loads(line) for line in fh]


def arvo_id(rec):
    m = re.search(r"arvo:(\d+)-", json.dumps(rec.get("docker_image_ref") or {}))
    return m.group(1) if m else None


def chain_len(rec):
    return len([c for c in (rec.get("chain") or []) if isinstance(c, dict)])


rows = read_jsonl("dataset_patched.jsonl")
len3 = [r for r in rows if chain_len(r) >= 3]
tiers = collections.Counter((r.get("label_confidence_tier") or "").lower() for r in len3)
print(f"len-3+ records: {len(len3)} tiers={dict(tiers)}")

targets = set()
have_img = 0
for rec in len3:
    a = arvo_id(rec)
    if a:
        have_img += 1
        targets.add(a)
print(f"len-3 with ARVO image: {have_img} | unique ids: {len(targets)}")

# Which sanitizer was each case built with? ASan-built cases cannot witness CWE-190
# without a UBSan rebuild, which is the Docker-only step.
con = sqlite3.connect("arvo.db")
cur = con.cursor()
marks = ",".join("?" * len(targets))
cur.execute(
    f"SELECT localId,project,sanitizer,crash_type,patch_url FROM arvo "
    f"WHERE CAST(localId AS TEXT) IN ({marks})",
    sorted(targets),
)
info = {
    str(r[0]): {"project": r[1], "sanitizer": r[2], "crash_type": r[3], "patch_url": r[4]}
    for r in cur.fetchall()
}
print("sanitizer distribution:", dict(collections.Counter(v["sanitizer"] for v in info.values())))
print("crash_type distribution:", dict(collections.Counter(v["crash_type"] for v in info.values())))

with open("len3_targets.json", "w") as fh:
    json.dump({"targets": sorted(targets), "info": info}, fh)

print("\nsamples:")
for k, v in list(info.items())[:6]:
    print(" ", k, v["project"], v["sanitizer"], "|", v["crash_type"])
