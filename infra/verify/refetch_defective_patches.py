#!/usr/bin/env python3
"""Re-fetch GOLD patch evidence that is present but cannot carry a guard.

`rescue_reference_patches.py` replaced pointers with patches. A second defect survived that:
the patch can be real, well-formed and still unable to back the claim - cut mid-hunk by a
naive 200,000-byte slice, or resolved to a commit that touches only a Makefile or a fuzz
harness. `guard_evidence_defect` names each case; this re-fetches from the fix commit ARVO
itself recorded, which is the authority we already trust for reproduction.

Records whose defect survives a correct fetch are NOT recoverable this way: ARVO's own fix
commit is harness-only for 64 of them, which is a labelling question (is a harness change a
fix?) rather than a fetch failure, and must be settled by demotion or re-resolution, never by
keeping the record and relaxing the check.

`--resolutions` is {id: {patch_url, fix_commit}}, exported from arvo.db.

Usage: refetch_defective_patches.py --resolutions res.json [--dataset ...] [--out ...]
"""

from __future__ import annotations

import argparse
import base64
import collections
import json
import re
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))
from chainforge.evidence import clip_patch, guard_evidence_defect  # noqa: E402
from chainforge.mining.arvo import diff_needs_base64, raw_diff_url  # noqa: E402

MAX_PATCH_BYTES = 2_000_000
SHA = re.compile(r"[0-9a-f]{40}")


def fetch(url: str, timeout: float = 30.0) -> str | None:
    req = urllib.request.Request(url, headers={"User-Agent": "chainforge/0.1"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read(MAX_PATCH_BYTES + 1)
    except (urllib.error.URLError, OSError, ValueError):
        return None
    if len(raw) > MAX_PATCH_BYTES:
        return None  # oversized: a slice here is what produced the mid-hunk cuts
    if diff_needs_base64(url):
        try:
            raw = base64.b64decode(raw)
        except (ValueError, TypeError):
            return None
    return raw.decode("utf-8", "replace")


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--dataset", default="data/release/dataset.jsonl")
    ap.add_argument("--resolutions", required=True)
    ap.add_argument("--out", default="data/interim/refetched_patches.json")
    ap.add_argument("--sleep", type=float, default=0.3)
    a = ap.parse_args(argv)

    with open(a.resolutions) as fh:
        res = json.load(fh)
    with open(a.dataset) as fh:
        rows = [json.loads(x) for x in fh if x.strip()]

    st = collections.Counter()
    fixed_map: dict[str, str] = {}
    unrecoverable = []

    for rec in rows:
        if rec.get("label_confidence_tier") != "gold":
            continue
        sha_m = SHA.search((rec.get("commit_range") or {}).get("fixed") or "")
        before = guard_evidence_defect(rec.get("patch_diff"), sha_m.group(0) if sha_m else "")
        if not before:
            continue
        st["defective"] += 1
        r = res.get(rec["id"]) or {}
        url = raw_diff_url(r.get("patch_url") or "")
        if not url:
            st["no mappable patch_url"] += 1
            unrecoverable.append({"id": rec["id"], "was": before, "why": "no mappable patch_url"})
            continue
        body = fetch(url)
        time.sleep(a.sleep)
        if body is None:
            st["fetch failed or oversized"] += 1
            unrecoverable.append({"id": rec["id"], "was": before, "why": "fetch failed"})
            continue
        want = SHA.search(r.get("fix_commit") or "")
        after = guard_evidence_defect(body, want.group(0) if want else "")
        if after:
            st[f"still defective: {after.split(' (')[0]}"] += 1
            unrecoverable.append({"id": rec["id"], "was": before, "why": after, "url": url})
            continue
        fixed_map[rec["id"]] = clip_patch(body, MAX_PATCH_BYTES)
        st["RECOVERED"] += 1

    out = Path(a.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    with open(out, "w") as fh:
        json.dump(fixed_map, fh)
    rej = out.with_name(out.stem + "_unrecoverable.json")
    with open(rej, "w") as fh:
        json.dump(unrecoverable, fh, indent=1)

    for k, v in st.most_common():
        print(f"  {k:36s} {v}")
    print(f"\nwrote {len(fixed_map)} to {out}")
    print(f"wrote {len(unrecoverable)} to {rej} — these need demotion or re-resolution")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
