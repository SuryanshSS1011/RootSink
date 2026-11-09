"""Fill patch_diff from arvo.db patch_url for records that already hold a clean
differential witness (vul crash + fix clean), then re-tier to GOLD where the
schema invariant is satisfied. Writes a new dataset + a changelog.

Run on ROAR from $CF_HOME (needs dataset.jsonl, patch_urls.json,
reproduced_status.json and the repo checkout at repo/src).
"""

import collections
import json
import re
import sys

sys.path.insert(0, "repo/src")

from chainforge.schema import ChainRecord  # noqa: E402  (needs sys.path above)

DS = "dataset.jsonl"


def read_json(path):
    with open(path) as fh:
        return json.load(fh)


def read_jsonl(path):
    with open(path) as fh:
        return [json.loads(line) for line in fh]


def arvo_id(rec):
    """ARVO local id from the image ref, falling back to the OSS-Fuzz alias.

    93 ARVO-backed records (arvo-len3, arvo-newarm) carry an empty docker_image_ref and
    only an `OSS-Fuzz-<id>` alias; matching on the image ref alone skipped them entirely.
    """
    m = re.search(r"arvo:(\d+)-", json.dumps(rec.get("docker_image_ref") or {}))
    if m:
        return m.group(1)
    m = re.search(r"OSS-Fuzz-(\d+)", json.dumps(rec.get("aliases") or []))
    return m.group(1) if m else None


def triggered(rec):
    return any((s or {}).get("triggered") for s in (rec.get("sanitizer_reports") or []))


purls = read_json("patch_urls.json")
status = read_json("reproduced_status.json")
rows = read_jsonl(DS)

filled = promoted = 0
log = []
for rec in rows:
    a = arvo_id(rec)
    if not a or rec.get("patch_diff"):
        continue
    st = status.get(a)
    patch_url = (purls.get(a) or {}).get("patch_url")
    if not (st and st["repro"] and patch_url):
        continue
    rec["patch_diff"] = patch_url
    filled += 1
    entry = {"id": rec["id"], "op": "patch_join", "patch_url": patch_url}
    # GOLD requires: >=1 triggered sanitizer report + patch_diff + not synthetic
    tier = (rec.get("label_confidence_tier") or "").lower()
    if tier != "gold" and triggered(rec) and not rec.get("synthetic"):
        entry["tier"] = f"{tier} -> gold"
        rec["label_confidence_tier"] = "gold"
        promoted += 1
    log.append(entry)

with open("dataset_patched.jsonl", "w") as fh:
    for rec in rows:
        fh.write(json.dumps(rec) + "\n")
with open("patch_join_changelog.jsonl", "w") as fh:
    for entry in log:
        fh.write(json.dumps(entry) + "\n")

print(f"patch_diff filled: {filled} | promoted to GOLD: {promoted}")
tiers = collections.Counter((r.get("label_confidence_tier") or "").lower() for r in rows)
print("tiers now:", dict(tiers))

ok = err = 0
errs = collections.Counter()
for rec in rows:
    try:
        ChainRecord.model_validate(rec)
        ok += 1
    except Exception as exc:  # noqa: BLE001 - tally and continue
        err += 1
        errs[str(exc).splitlines()[-2][:60]] += 1
print(f"schema: ok={ok} err={err}")
for msg, count in errs.most_common(3):
    print("   ", count, msg)
