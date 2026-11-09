"""Emit arvo.db patch_url (+ crash metadata) as JSON for the ids that need a patch join.

Run on ROAR from $CF_HOME; pipe stdout to patch_urls.json.
"""

import json
import sqlite3


def read_json(path):
    with open(path) as fh:
        return json.load(fh)


ids = sorted(set(read_json("need_patch_ids.json")) | set(read_json("need_patch_len3_ids.json")))
con = sqlite3.connect("arvo.db")
cur = con.cursor()
marks = ",".join("?" * len(ids))
cur.execute(
    f"SELECT localId, patch_url, patch_located, crash_type, sanitizer FROM arvo "
    f"WHERE CAST(localId AS TEXT) IN ({marks})",
    ids,
)
out = {
    str(lid): {"patch_url": purl, "patch_located": ploc, "crash_type": ctype, "sanitizer": san}
    for lid, purl, ploc, ctype, san in cur.fetchall()
}
print(json.dumps(out))
