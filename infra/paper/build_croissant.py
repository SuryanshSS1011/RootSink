#!/usr/bin/env python3
"""Emit Croissant (MLCommons, v1.0) JSON-LD metadata for the release, generated from the files.

Checksums and counts are computed here, never typed, so the metadata cannot describe a different
release than the one it ships with. Validate with `uvx mlcroissant validate --jsonld <out>`.

Usage: build_croissant.py [--release data/release] [--out data/release/croissant.json]
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path

CONTEXT = {
    "@language": "en",
    "@vocab": "https://schema.org/",
    "citeAs": "cr:citeAs",
    "column": "cr:column",
    "conformsTo": "dct:conformsTo",
    "cr": "http://mlcommons.org/croissant/",
    "data": {"@id": "cr:data", "@type": "@json"},
    "dataType": {"@id": "cr:dataType", "@type": "@vocab"},
    "dct": "http://purl.org/dc/terms/",
    "equivalentProperty": "cr:equivalentProperty",
    "fileSet": "cr:fileSet",
    "rai": "http://mlcommons.org/croissant/RAI/",
    "samplingRate": "cr:samplingRate",
    "examples": {"@id": "cr:examples", "@type": "@json"},
    "extract": "cr:extract",
    "field": "cr:field",
    "fileObject": "cr:fileObject",
    "fileProperty": "cr:fileProperty",
    "format": "cr:format",
    "includes": "cr:includes",
    "isLiveDataset": "cr:isLiveDataset",
    "jsonPath": "cr:jsonPath",
    "key": "cr:key",
    "md5": "cr:md5",
    "parentField": "cr:parentField",
    "path": "cr:path",
    "recordSet": "cr:recordSet",
    "references": "cr:references",
    "regex": "cr:regex",
    "repeated": "cr:repeated",
    "replace": "cr:replace",
    "sc": "https://schema.org/",
    "separator": "cr:separator",
    "source": "cr:source",
    "subField": "cr:subField",
    "transform": "cr:transform",
}

# (name, dataType, jsonPath, description)
FIELDS = [
    ("id", "sc:Text", "$.id", "Record identifier."),
    ("chain_string", "sc:Text", "$.chain_string", "Ordered chain, e.g. CWE-20->CWE-190->CWE-787."),
    (
        "label_confidence_tier",
        "sc:Text",
        "$.label_confidence_tier",
        "gold | gold-upstream | silver | bronze (a reproduction contract; see SPECIFICATION R5).",
    ),
    ("evidence_floor", "sc:Text", "$.evidence_floor", "Weakest per-link evidence kind."),
    ("project", "sc:Text", "$.project", "Upstream project (harness-only: leaks the label)."),
    ("language", "sc:Text", "$.language", "C or C++."),
    ("provenance", "sc:Text", "$.provenance", "Pipeline arm (harness-only: leaks the label)."),
    ("split", "sc:Text", "$.split", "Project-disjoint split: train | validation | test."),
    (
        "differential_complete",
        "sc:Boolean",
        "$.differential_complete",
        "True only with a clean, demonstrably executed patched-revision run.",
    ),
    ("license", "sc:Text", "$.license", "Upstream project's SPDX license, or NOASSERTION."),
    ("patch_diff", "sc:Text", "$.patch_diff", "The developer's fix as a unified diff."),
    (
        "sampling_weight",
        "sc:Float",
        "$.sampling_weight",
        "Optional project-balancing weight for sampling, mean 1 per tier and split (harness-only).",
    ),
]


def sha256(p: Path) -> str:
    return hashlib.sha256(p.read_bytes()).hexdigest()


def public_url(rel: Path) -> str:
    f, doi = rel / "URL", rel / "DOI"
    if doi.is_file():
        return "https://doi.org/" + doi.read_text().strip()
    return f.read_text().strip() if f.is_file() else "https://github.com/SuryanshSS1011/RootSink"


def read_cff(path: Path) -> dict:
    """The few CITATION.cff keys this needs (title, version, date, authors), without a YAML
    dependency: CITATION.cff is the single source of the release version."""
    out: dict = {"authors": []}
    for line in path.read_text().splitlines():
        m = re.match(r'^(title|version|date-released):\s*"?(.*?)"?\s*$', line)
        if m:
            out[m.group(1)] = m.group(2)
        m = re.match(r"^\s+-?\s*(family-names|given-names):\s*(.+)$", line)
        if m:
            if m.group(1) == "family-names":
                out["authors"].append({})
            out["authors"][-1][m.group(1)] = m.group(2).strip()
    return out


def cite_as(cff: dict) -> str:
    names = " and ".join(f"{a['family-names']}, {a['given-names']}" for a in cff["authors"])
    return (
        f"@misc{{rootsink, title = {{{{{cff['title']}}}}}, author = {{{names}}}, "
        f"year = {{{cff['date-released'][:4]}}}, version = {{{cff['version']}}}}}"
    )


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--release", default="data/release")
    ap.add_argument("--out", default="data/release/croissant.json")
    args = ap.parse_args(argv)
    rel = Path(args.release)
    man = json.loads((rel / "dataset.manifest.json").read_text())
    cff = read_cff(Path(__file__).resolve().parents[2] / "CITATION.cff")
    ds = rel / "dataset.jsonl"
    meta = {
        "@context": CONTEXT,
        "@type": "sc:Dataset",
        "conformsTo": "http://mlcommons.org/croissant/1.0",
        "name": "RootSink",
        "description": (
            "Reproducible C/C++ crashes: each record pairs a sanitizer-witnessed sink with a "
            "candidate root cause, ordered CWE instances with an evidence category each, the fix "
            "and sanitizer logs. GOLD certifies the sink and its two-sided reproduction, not the "
            "root. Record ids keep the working name CHAINFORGE. "
            f"{man['total']} records; tiers {man['by_tier']}."
        ),
        "license": "https://creativecommons.org/licenses/by/4.0/",
        # The public repository, once data/release/URL names it (the paper reads the same file).
        "url": public_url(rel),
        "citeAs": cite_as(cff),
        "creator": [
            {"@type": "sc:Person", "name": f"{a['given-names']} {a['family-names']}"}
            for a in cff["authors"]
        ],
        "version": cff["version"],
        "datePublished": cff["date-released"],
        "distribution": [
            {
                "@type": "cr:FileObject",
                "@id": "dataset.jsonl",
                "name": "dataset.jsonl",
                # Relative to this file, which sits beside dataset.jsonl in data/release/.
                "contentUrl": "dataset.jsonl",
                "encodingFormat": "application/jsonlines",
                "sha256": sha256(ds),
            }
        ],
        "recordSet": [
            {
                "@type": "cr:RecordSet",
                "@id": "records",
                "name": "records",
                "field": [
                    {
                        "@type": "cr:Field",
                        "@id": f"records/{name}",
                        "name": name,
                        "description": desc,
                        "dataType": dtype,
                        "source": {
                            "fileObject": {"@id": "dataset.jsonl"},
                            # JSON Lines are read as a table: a top-level key is a column.
                            "extract": {"column": path.removeprefix("$.")},
                        },
                    }
                    for name, dtype, path, desc in FIELDS
                ],
            }
        ],
    }
    Path(args.out).write_text(json.dumps(meta, indent=1) + "\n")
    print(f"croissant -> {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
