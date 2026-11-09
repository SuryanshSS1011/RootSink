#!/usr/bin/env python3
"""Check that every pinned ARVO image is still on Docker Hub, without pulling anything.

For each `docker_image_ref` digest (vulnerable and patched) this sends a registry HEAD request for
the manifest by digest and by tag; Docker Hub does not count HEAD requests as pulls. Raw results
go to --raw (resumable); the dated summary goes to infra/repro/image_availability.json.

Usage: check_image_digests.py [--release data/release] [--raw heads.jsonl] [--ca CA_BUNDLE]
"""

from __future__ import annotations

import argparse
import collections
import concurrent.futures as cf
import datetime
import json
import threading
import time
from pathlib import Path

import httpx

ACCEPT = ", ".join(
    [
        "application/vnd.docker.distribution.manifest.v2+json",
        "application/vnd.docker.distribution.manifest.list.v2+json",
        "application/vnd.oci.image.manifest.v1+json",
        "application/vnd.oci.image.index.v1+json",
    ]
)


def pinned_refs(dataset: Path) -> list[str]:
    refs = set()
    with open(dataset) as fh:
        for line in fh:
            d = json.loads(line).get("docker_image_ref") or {}
            refs.update(v for v in (d.get("vulnerable"), d.get("patched")) if v and "@sha256:" in v)
    return sorted(refs)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--release", default="data/release")
    ap.add_argument("--raw", default="image_heads.jsonl")
    ap.add_argument("--ca", default=None)
    ap.add_argument("--out", default="infra/repro/image_availability.json")
    args = ap.parse_args(argv)
    refs = pinned_refs(Path(args.release) / "dataset.jsonl")
    done: dict[str, dict] = {}
    if Path(args.raw).exists():
        for line in Path(args.raw).read_text().splitlines():
            j = json.loads(line)
            done[j["ref"]] = j
    todo = [r for r in refs if done.get(r, {}).get("digest_status") not in (200, 404)]
    cli = httpx.Client(verify=args.ca or True, timeout=30)
    lock, tok = threading.Lock(), {"t": None, "at": 0.0}

    def token(repo: str) -> str:
        with lock:
            if time.time() - tok["at"] > 240:
                url = "https://auth.docker.io/token?service=registry.docker.io"
                tok["t"] = cli.get(f"{url}&scope=repository:{repo}:pull").json()["token"]
                tok["at"] = time.time()
            return tok["t"]

    def head(repo: str, ref: str):
        for attempt in range(4):
            try:
                r = cli.head(
                    f"https://registry-1.docker.io/v2/{repo}/manifests/{ref}",
                    headers={"Authorization": f"Bearer {token(repo)}", "Accept": ACCEPT},
                )
            except httpx.HTTPError:
                time.sleep(5 * (attempt + 1))
                continue
            if r.status_code == 429:
                time.sleep(30 * (attempt + 1))
                continue
            if r.status_code == 401:
                tok["at"] = 0.0
                continue
            return r.status_code, r.headers.get("docker-content-digest")
        return None, None  # no answer: never counted as missing (R10)

    def check(ref: str) -> dict:
        name, dig = ref.split("@")
        repo, tag = name.rsplit(":", 1)
        s, _ = head(repo, dig)
        ts, tdig = head(repo, tag)
        return {
            "ref": ref,
            "digest_status": s,
            "tag_status": ts,
            "tag_digest_matches": (tdig == dig) if tdig else None,
        }

    with open(args.raw, "a") as fh, cf.ThreadPoolExecutor(8) as ex:
        for res in ex.map(check, todo):
            done[res["ref"]] = res
            fh.write(json.dumps(res) + "\n")
    rows = [done[r] for r in refs if r in done]
    summary = {
        "checked": datetime.date.today().isoformat(),
        "method": "registry HEAD of each pinned manifest digest and of its tag (no pulls)",
        "pinned_digests": len(refs),
        "digest_resolves": sum(r["digest_status"] == 200 for r in rows),
        "digest_missing": sum(r["digest_status"] == 404 for r in rows),
        "no_answer": sum(r["digest_status"] not in (200, 404) for r in rows),
        "tag_still_points_at_pinned_digest": sum(r["tag_digest_matches"] is True for r in rows),
        "tag_moved": sum(r["tag_digest_matches"] is False for r in rows),
        "tag_status": dict(collections.Counter(str(r["tag_status"]) for r in rows)),
        "missing": sorted(r["ref"] for r in rows if r["digest_status"] == 404),
    }
    Path(args.out).write_text(json.dumps(summary, indent=1) + "\n")
    print(json.dumps({k: v for k, v in summary.items() if k != "missing"}))
    return 0 if not summary["digest_missing"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
