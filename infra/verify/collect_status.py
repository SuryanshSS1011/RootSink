import glob
import json
import os

out = {}
for f in glob.glob("**/result.json", recursive=True):
    try:
        with open(f) as fh:
            d = json.load(fh)
    except Exception:
        continue
    lid = d.get("local_id")
    if lid is None:
        # fall back to the directory name
        base = os.path.basename(os.path.dirname(f))
        if base.isdigit():
            lid = int(base)
    if lid is None:
        continue
    out[str(lid)] = {
        "vul": bool(d.get("vul_crashed")),
        "fix": bool(d.get("fix_crashed")),
        "repro": bool(d.get("reproduced")),
        "san": d.get("vul_sanitizer") or "",
    }
print(json.dumps(out))
