#!/usr/bin/env python3
"""Summarise the runner's agent-environment check (`agentenv2` workflow, agent_env.sh --check).

Per image: is the developer's fix reachable in any repository after the rewrite, is the network
down, and does the project build. A failed build is attributed by the two diagnostic builds of the
unmodified image: `network` when it fails offline but builds online (the build fetches something),
`image` when it fails online too, and `rewrite` when the unmodified image builds offline, so the
repository rewrite is what broke it. Writes data/validation/agent_check.json, which the paper's
macros read, and keeps the raw lines in data/validation/agent_check.jsonl.

Usage: summarize_agent_check.py <agentenv.jsonl>...
       [--sample data/validation/env_probe_sample2.json]
"""

from __future__ import annotations

import argparse
import collections
import json
from pathlib import Path


def cause(d: dict) -> str | None:
    if d.get("build_rc") == 0:
        return None
    off, on = d.get("plain_offline_build_rc"), d.get("plain_online_build_rc")
    if off == 0:
        return "rewrite"
    if on == 0:
        return "network"
    return "image"


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("results", nargs="+")
    ap.add_argument("--sample", default="data/validation/env_probe_sample2.json")
    ap.add_argument("--out", default="data/validation/agent_check.json")
    args = ap.parse_args(argv)
    rows = {}
    for f in args.results:
        for line in Path(f).read_text().splitlines():
            if line.strip():
                d = json.loads(line)
                rows[d["arvo_id"]] = d
    sample = [c["arvo_id"] for c in json.loads(Path(args.sample).read_text())["cases"]]
    got = [rows[a] for a in sample if a in rows]
    causes = collections.Counter(cause(d) for d in got if cause(d))
    out = {
        "rule": "agent environment check (agent_env.sh --check)",
        "sampled": len(sample),
        "checked": len(got),
        "fix_unreachable": sum(d.get("fix_reachable_in_repos") == 0 for d in got),
        "network_down": sum(d.get("network") == "down" for d in got),
        "build_ok": sum(d.get("build_rc") == 0 for d in got),
        "build_failure_cause": dict(causes),
        "not_checked": [a for a in sample if a not in rows],
    }
    Path(args.out).write_text(json.dumps(out, indent=1) + "\n")
    raw = Path(args.out).with_suffix(".jsonl")
    raw.write_text(
        "".join(json.dumps({k: v for k, v in d.items() if k != "build_tail"}) + "\n" for d in got)
    )
    print(json.dumps(out))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
