"""Schema-validate a corrected chain dataset and report tier/duplicate counts.

Run on ROAR from $CF_HOME (repo checkout at repo/src).
"""

import collections
import json
import sys

sys.path.insert(0, "repo/src")

from chainforge.schema import ChainRecord  # noqa: E402  (needs sys.path above)

PATH = "out_corrected/corrected_chains.jsonl"

with open(PATH) as fh:
    rows = [json.loads(line) for line in fh]

ok = err = 0
errmsg = collections.Counter()
for rec in rows:
    try:
        ChainRecord.model_validate(rec)
        ok += 1
    except Exception as exc:  # noqa: BLE001 - tally and continue
        err += 1
        errmsg[str(exc).splitlines()[-2][:60]] += 1

tiers = collections.Counter((r.get("label_confidence_tier") or "").lower() for r in rows)
ids = [r["id"] for r in rows]
dup = len(ids) - len(set(ids))
print(f"corrected_chains: {len(rows)} rows | schema ok={ok} err={err} | dup_ids={dup}")
print("tiers:", dict(tiers))
for msg, count in errmsg.most_common(5):
    print("  ", count, msg)
