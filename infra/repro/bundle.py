#!/usr/bin/env python3
"""Generate ChainForge Reproduction Bundles (CRB) — one self-contained, executable
recipe per record, so any third party can reproduce a chain end-to-end.

Design follows ARVO's insight (freeze the whole build environment, not a binary) and
fixes three things ARVO leaves open:

  1. ARVO pins images by TAG, which is mutable and can be retagged or deleted. A CRB
     pins the registry DIGEST, so a bundle either resolves to bit-identical content or
     fails loudly. Digests are resolved over the registry API — no daemon required.
  2. ARVO records "it crashed". A CRB records the EXPECTED WITNESS (sanitizer, bug
     class, read/write direction, crash site), so verification is a comparison rather
     than a human eyeballing a log.
  3. ARVO is single-weakness. A CRB carries PER-LINK witnesses, including the alternate
     sanitizer build needed to witness an intermediate link (e.g. CWE-190 under UBSan),
     which is what makes a *chain* reproducible rather than just a crash.

Usage:
  bundle.py <dataset.jsonl> --out infra/repro/bundles [--facts facts_by_id.json]
            [--limit N] [--no-digest]
"""

import argparse
import json
import os
import re
import sys
import time
import urllib.error
import urllib.request

REGISTRY = "https://registry-1.docker.io"
AUTH = "https://auth.docker.io/token?service=registry.docker.io&scope=repository:{repo}:pull"
ACCEPT = ",".join(
    [
        "application/vnd.docker.distribution.manifest.v2+json",
        "application/vnd.oci.image.manifest.v1+json",
        "application/vnd.docker.distribution.manifest.list.v2+json",
        "application/vnd.oci.image.index.v1+json",
    ]
)
CRB_VERSION = "1.0"


def read_jsonl(path):
    with open(path) as fh:
        return [json.loads(line) for line in fh if line.strip()]


class DigestResolver:
    """Resolve image tag -> content digest over the registry API, with an on-disk cache."""

    def __init__(self, cache_path, enabled=True):
        self.cache_path = cache_path
        self.enabled = enabled
        self.cache = {}
        if os.path.exists(cache_path):
            with open(cache_path) as fh:
                self.cache = json.load(fh)
        self._tokens = {}

    def _token(self, repo):
        if repo not in self._tokens:
            with urllib.request.urlopen(AUTH.format(repo=repo), timeout=30) as r:
                self._tokens[repo] = json.load(r)["token"]
        return self._tokens[repo]

    def resolve(self, ref):
        """ref like 'n132/arvo:42477544-vul' -> 'sha256:...' or None.

        Anonymous Docker Hub rate-limits hard (HTTP 429) well before a full run of
        ~2 lookups per record completes, so back off and retry rather than silently
        recording None - an unpinned bundle is a real loss of reproducibility. Set
        DOCKERHUB_USER/DOCKERHUB_TOKEN to authenticate and raise the limit.
        """
        if not self.enabled:
            return None
        if ref in self.cache and self.cache[ref]:
            return self.cache[ref]
        repo, tag = ref.rsplit(":", 1)
        for attempt in range(5):
            try:
                # HEAD carries the digest header and, unlike GET, does not count as a pull
                # against Docker Hub's rate limit, which the replays themselves need.
                req = urllib.request.Request(f"{REGISTRY}/v2/{repo}/manifests/{tag}", method="HEAD")
                req.add_header("Authorization", f"Bearer {self._token(repo)}")
                req.add_header("Accept", ACCEPT)
                with urllib.request.urlopen(req, timeout=30) as r:
                    digest = r.headers.get("Docker-Content-Digest")
                self.cache[ref] = digest
                return digest
            except urllib.error.HTTPError as e:
                if e.code == 429:
                    self._tokens.pop(repo, None)  # force a fresh token
                    time.sleep(min(60, 5 * (2**attempt)))
                    continue
                break
            except Exception:
                time.sleep(2)
        self.cache[ref] = None
        return None

    def save(self):
        with open(self.cache_path, "w") as fh:
            json.dump(self.cache, fh, indent=0)


def arvo_id(rec):
    m = re.search(r"arvo:(\d+)-", json.dumps(rec.get("docker_image_ref") or {}))
    if m:
        return m.group(1)
    m = re.search(r"OSS-Fuzz-(\d+)", json.dumps(rec.get("aliases") or []))
    return m.group(1) if m else None


def chain_cwes(rec):
    return [c.get("cwe_id") for c in (rec.get("chain") or []) if isinstance(c, dict)]


def expected_witness(facts, aid):
    """The sink witness we expect to observe at the vulnerable revision."""
    f = (facts or {}).get(aid) or {}
    if not f.get("bug_class"):
        return None
    return {
        "sanitizer": f.get("sanitizer") or "address",
        "bug_class": f.get("bug_class"),
        "direction": f.get("direction"),
        "crash_site": f.get("crash_site"),
        "implies_sink_cwe": f.get("suggested_sink_cwe"),
    }


def pinned_digest(rec, side):
    """The digest the record pins in docker_image_ref (`ref@sha256:...`), or None."""
    ref = (rec.get("docker_image_ref") or {}).get(side) or ""
    return ref.split("@", 1)[1] if "@sha256:" in ref else None


def build_bundle(rec, aid, resolver, facts):
    vul_ref = f"n132/arvo:{aid}-vul"
    fix_ref = f"n132/arvo:{aid}-fix"
    cwes = chain_cwes(rec)
    sink_witness = expected_witness(facts, aid)

    links = []
    for i, cwe in enumerate(cwes):
        role = "source" if i == 0 else ("sink" if i == len(cwes) - 1 else "intermediate")
        link = {"cwe_id": cwe, "role": role}
        if role == "sink" and sink_witness:
            link["witness"] = {
                "method": "asan-replay",
                "sanitizer": sink_witness["sanitizer"],
                "bug_class": sink_witness["bug_class"],
                "direction": sink_witness["direction"],
                "site": sink_witness["crash_site"],
            }
            link["witnessed"] = True
        elif cwe == 190:
            # Intermediate integer overflow is only observable under a UBSan rebuild of
            # the SAME pinned source; recorded as a recipe so a verifier can obtain it.
            link["witness"] = {
                "method": "ubsan-rebuild",
                "recipe": "SANITIZER=undefined compile && $ENTRYPOINT",
                "ubsan_options": "print_stacktrace=1:halt_on_error=0:"
                "silence_unsigned_overflow=0:symbolize=1",
            }
            link["witnessed"] = False
        else:
            link["witnessed"] = False
        links.append(link)

    return {
        "crb_version": CRB_VERSION,
        "record_id": rec["id"],
        "chain": rec.get("chain_string"),
        "project": rec.get("project"),
        "tier": (rec.get("label_confidence_tier") or "").lower(),
        "repro_kind": "oss-fuzz-container",
        "source": {
            "upstream": "ARVO / OSS-Fuzz",
            "local_id": aid,
            "commit_range": rec.get("commit_range"),
            "patch": rec.get("patch_diff"),
        },
        "images": {
            # The record's pin wins: a tag looked up now may have moved, or fail and give None.
            "vulnerable": {
                "ref": vul_ref,
                "digest": pinned_digest(rec, "vulnerable") or resolver.resolve(vul_ref),
            },
            "patched": {
                "ref": fix_ref,
                "digest": pinned_digest(rec, "patched") or resolver.resolve(fix_ref),
            },
        },
        # The in-image `arvo` helper replays the baked-in PoV. Note it forces
        # silence_unsigned_overflow=1, so a UBSan witness must invoke the target directly.
        "entrypoint": {"command": ["arvo"], "pov_path": "/tmp/poc"},
        "expected": {
            "vulnerable": {"crashes": True, "witness": sink_witness},
            "patched": {"crashes": False},
        },
        "links": links,
        "verify": "infra/repro/verify.sh <bundle.json>",
    }


def main(argv):
    ap = argparse.ArgumentParser()
    ap.add_argument("dataset")
    ap.add_argument("--out", default="infra/repro/bundles")
    ap.add_argument("--facts", default=None, help="facts_by_id.json of parsed witnesses")
    ap.add_argument("--limit", type=int, default=0)
    ap.add_argument("--no-digest", action="store_true", help="skip registry digest lookups")
    args = ap.parse_args(argv)

    rows = read_jsonl(args.dataset)
    facts = {}
    if args.facts and os.path.exists(args.facts):
        with open(args.facts) as fh:
            facts = json.load(fh)

    os.makedirs(args.out, exist_ok=True)
    resolver = DigestResolver(os.path.join(args.out, "_digests.json"), enabled=not args.no_digest)

    made = skipped = pinned = witnessed = 0
    for rec in rows:
        aid = arvo_id(rec)
        if not aid:
            skipped += 1
            continue
        b = build_bundle(rec, aid, resolver, facts)
        if b["images"]["vulnerable"]["digest"]:
            pinned += 1
        if b["expected"]["vulnerable"]["witness"]:
            witnessed += 1
        with open(os.path.join(args.out, f"{rec['id']}.json"), "w") as fh:
            json.dump(b, fh, indent=2)
        made += 1
        # Checkpoint the digest cache: a full run is ~2 network lookups per record, and
        # losing them all to one interruption would make regeneration needlessly slow.
        if made % 50 == 0:
            resolver.save()
        if args.limit and made >= args.limit:
            break
    resolver.save()

    print(f"bundles written : {made}  -> {args.out}")
    print(f"  digest-pinned : {pinned}")
    print(f"  sink witness  : {witnessed}")
    print(f"not ARVO-backed : {skipped} (need a different repro_kind)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
