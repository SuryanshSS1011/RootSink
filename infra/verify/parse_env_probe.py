#!/usr/bin/env python3
"""Summarise the runner's ARVO image probes into data/validation/env_probe.json.

Inputs: the `probe_arvo` log (per image: whether the developer's fix commit is reachable in any
repository under /src, and which seed corpora the build produces) and, optionally, the
`agentenv` JSON lines (the same images after infra/repro/agent_env.sh: fix still reachable?
network? does `arvo compile` still succeed?). The paper's figures come from this file.

Usage: parse_env_probe.py <probe.log> [--agentenv agentenv.jsonl]
       [--out data/validation/env_probe.json]
"""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path


def parse_probe(text: str) -> list[dict]:
    out = []
    for block in re.split(r"^######## ", text, flags=re.M)[1:]:
        head = block.splitlines()[0].strip()
        aid, _, fix = head.partition(":")
        out.append(
            {
                "arvo_id": aid,
                "fix": fix or None,
                "fix_commit_present": "FIX_COMMIT_PRESENT" in block,
                "seed_corpora": len(re.findall(r"^corpus /out/\S+_seed_corpus\.zip", block, re.M)),
                "compiled": "compile rc=0" in block,
            }
        )
    return out


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("probe_log")
    ap.add_argument("--agentenv")
    ap.add_argument("--out", default="data/validation/env_probe.json")
    a = ap.parse_args(argv)
    images = parse_probe(Path(a.probe_log).read_text(errors="replace"))
    after = {}
    if a.agentenv and Path(a.agentenv).is_file():
        for line in Path(a.agentenv).read_text().splitlines():
            if line.startswith("{"):
                d = json.loads(line)
                after[d["arvo_id"]] = d
    for im in images:
        if im["arvo_id"] in after:
            im["sanitized"] = after[im["arvo_id"]]
    summary = {
        "images": len(images),
        "fix_commit_present": sum(i["fix_commit_present"] for i in images),
        "with_seed_corpus": sum(i["seed_corpora"] > 0 for i in images),
        "sanitized_checked": sum("sanitized" in i for i in images),
        "sanitized_fix_unreachable": sum(
            i.get("sanitized", {}).get("fix_reachable_in_repos") == 0 for i in images
        ),
        "sanitized_build_ok": sum(i.get("sanitized", {}).get("build_rc") == 0 for i in images),
        "sanitized_network_down": sum(
            i.get("sanitized", {}).get("network") == "down" for i in images
        ),
    }
    Path(a.out).write_text(json.dumps({"summary": summary, "images": images}, indent=1) + "\n")
    print(json.dumps(summary))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
