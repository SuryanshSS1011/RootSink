"""CHAINFORGE command-line entrypoint.

Thin wrappers over the Phase 0 harvesters so the mining tools are runnable end-to-end.
Heavy work (reproduction, dataflow) runs on ROAR, not here.
"""

from __future__ import annotations

import argparse
import json
import sys

from .mining.arvo import ArvoMetaClient
from .mining.arvo_index import ArvoIndex
from .mining.debian import parse_cve_list
from .mining.nvd import NvdClient
from .mining.osv import OsvClient
from .mining.redhat import seeds_from_notation
from .mining.syzbot import SyzbotClient
from .pilot import assemble_batch, evidence_from_json
from .schema import ChainRecord
from .synthetic import generate_length3


def _cmd_redhat(args: argparse.Namespace) -> int:
    seeds = seeds_from_notation(args.cve, args.notation)
    for s in seeds:
        print(json.dumps({"cve": s.cve, "chain_string": s.chain_string}))
    if not seeds:
        print("no admissible chain in notation", file=sys.stderr)
    return 0


def _cmd_osv(args: argparse.Namespace) -> int:
    with OsvClient() as client:
        rec = client.get_vuln(args.vuln_id)
    ranges = [
        {"introduced": r.introduced, "fixed": r.fixed, "repo": r.repo} for r in rec.commit_ranges
    ]
    print(json.dumps({"id": rec.id, "aliases": rec.aliases, "commit_ranges": ranges}, indent=2))
    return 0


def _cmd_syzbot(args: argparse.Namespace) -> int:
    with SyzbotClient() as client:
        rows = client.fixed_bugs(args.namespace)[: args.limit]
        for row in rows:
            art = client.bug_artifacts(row.extid)
            print(
                json.dumps(
                    {
                        "extid": row.extid,
                        "title": row.title,
                        "has_c_repro": art.has_c_reproducer,
                        "has_syz_repro": art.has_syz_reproducer,
                    }
                )
            )
    return 0


def _cmd_debian(args: argparse.Namespace) -> int:
    with open(args.list_path, encoding="utf-8", errors="replace") as fh:
        for entry in parse_cve_list(fh):
            if args.cve and entry.cve != args.cve:
                continue
            if args.package and args.package not in entry.source_packages:
                continue
            fixed = [
                {"package": p.package, "release": p.release, "version": p.version}
                for p in entry.packages
                if p.fixed
            ]
            if not (fixed or entry.fix_commits):
                continue
            print(json.dumps({"cve": entry.cve, "fixed": fixed, "fix_commits": entry.fix_commits}))
    return 0


def _cmd_nvd(args: argparse.Namespace) -> int:
    with NvdClient(api_key=args.api_key) as client:
        seeds = client.seeds_for_source_cwe(
            args.source_cwe, max_pages=args.max_pages, per_page=args.per_page
        )
    for s in seeds:
        print(
            json.dumps(
                {
                    "cve": s.cve,
                    "chain_string": s.chain_string,
                    "cwe_sequence": s.cwe_sequence,
                    "all_catalog_cwes": s.all_catalog_cwes,
                }
            )
        )
    if not seeds:
        print("no multi-CWE admissible seeds found", file=sys.stderr)
    return 0


def _load_evidences(evidence_dirs: list[str], db_path: str) -> list:
    """Load and hydrate evidence.json files from one or more dirs against arvo.db."""
    import glob
    import os

    evidences = []
    with ArvoIndex(db_path) as idx:
        rows = idx.all_rows()
        for ed in evidence_dirs:
            pattern = os.path.join(ed, "**", "evidence.json")
            for path in sorted(glob.glob(pattern, recursive=True)):
                with open(path) as fh:
                    ev_json = json.load(fh)
                row = rows.get(int(ev_json["local_id"]))
                if row is None:
                    print(f"skip {path}: localId not in index", file=sys.stderr)
                    continue
                evidences.append(evidence_from_json(row, ev_json))
    return evidences


def _cmd_pilot_assemble(args: argparse.Namespace) -> int:
    """Assemble ChainRecords from pilot_case.sh evidence JSONs + arvo.db, print metrics.

    Reads every evidence.json under --evidence-dir (recursively), looks up its ARVO row by
    localId, assembles a tiered ChainRecord, and reports GATE-1 metrics.
    """
    evidences = _load_evidences([args.evidence_dir], args.db)
    records, metrics = assemble_batch(evidences, id_start=args.id_start)

    if args.out:
        with open(args.out, "w") as fh:
            for rec in records:
                fh.write(rec.model_dump_json() + "\n")

    print(
        json.dumps(
            {
                "total": metrics.total,
                "gold": metrics.gold,
                "silver": metrics.silver,
                "bronze": metrics.bronze,
                "silver_or_better_frac": round(metrics.silver_or_better_frac, 3),
                "passes_gate1": metrics.passes_gate1,
                "records_written": args.out or None,
            },
            indent=2,
        )
    )
    return 0


def _cmd_consolidate(args: argparse.Namespace) -> int:
    """Merge evidence from MANY batch dirs into one deduplicated, stable-id dataset.

    Assembles records from every --evidence-dir, deduplicates by ARVO localId (keeping the
    best record per case — corrected lifecycle/overflow labels supersede early CWE-20
    mislabels), assigns stable localId-based ids, and writes dataset.jsonl + manifest.json.
    """
    from .consolidate import consolidate

    evidences = _load_evidences(args.evidence_dir, args.db)
    raw_records, _ = assemble_batch(evidences)
    records, manifest = consolidate(raw_records)

    with open(args.out, "w") as fh:
        for rec in records:
            fh.write(rec.model_dump_json() + "\n")
    manifest_path = args.manifest or (args.out.rsplit(".", 1)[0] + ".manifest.json")
    with open(manifest_path, "w") as fh:
        json.dump(manifest.to_dict(), fh, indent=2)

    print(
        json.dumps({**manifest.to_dict(), "dataset": args.out, "manifest": manifest_path}, indent=2)
    )
    return 0


def _cmd_synthesize(args: argparse.Namespace) -> int:
    """Generate the synthetic length-3 stratum from a real length-2 dataset.

    Composes tier-flagged (synthetic, never GOLD) CWE-20->CWE-190->sink spines anchored to
    real records in --dataset, and writes them (or the real+synthetic union) as JSONL.
    """
    with open(args.dataset) as fh:
        real = [ChainRecord.model_validate_json(line) for line in fh]
    synth = generate_length3(real)

    with open(args.out, "w") as fh:
        if args.union:
            for rec in real:
                fh.write(rec.model_dump_json() + "\n")
        for rec in synth:
            fh.write(rec.model_dump_json() + "\n")

    print(
        json.dumps(
            {
                "real_input": len(real),
                "synthetic_generated": len(synth),
                "spines": [r.chain_string for r in synth],
                "written": args.out,
                "union": args.union,
            },
            indent=2,
        )
    )
    return 0


def _cmd_arvo(args: argparse.Namespace) -> int:
    with ArvoMetaClient() as client:
        case = client.get_case(args.local_id)
    print(
        json.dumps(
            {
                "local_id": case.local_id,
                "project": case.project,
                "sanitizer": case.sanitizer,
                "crash_type": case.crash_type,
                "vul_image": case.vul_image,
                "fix_image": case.fix_image,
                "cwe_hints": list(case.cwe_hints),
                "fix_commit_url": case.fix_commit_url,
            },
            indent=2,
        )
    )
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="chainforge", description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)

    p_rh = sub.add_parser("redhat", help="expand Red Hat chain notation into admissible seeds")
    p_rh.add_argument("cve")
    p_rh.add_argument("notation", help="e.g. 'CWE-20->(CWE-125|CWE-787)'")
    p_rh.set_defaults(func=_cmd_redhat)

    p_osv = sub.add_parser("osv", help="fetch OSV metadata for a vuln id")
    p_osv.add_argument("vuln_id", help="e.g. CVE-2021-3156 or a GHSA id")
    p_osv.set_defaults(func=_cmd_osv)

    p_syz = sub.add_parser("syzbot", help="list fixed bugs with reproducer availability")
    p_syz.add_argument("--namespace", default="upstream")
    p_syz.add_argument("--limit", type=int, default=20)
    p_syz.set_defaults(func=_cmd_syzbot)

    p_deb = sub.add_parser("debian", help="parse a Debian security-tracker data/CVE/list file")
    p_deb.add_argument("list_path", help="path to a cloned data/CVE/list")
    p_deb.add_argument("--cve", help="filter to one CVE id")
    p_deb.add_argument("--package", help="filter to one source package")
    p_deb.set_defaults(func=_cmd_debian)

    p_arvo = sub.add_parser("arvo", help="fetch ARVO-Meta case metadata by localId")
    p_arvo.add_argument("local_id", type=int, help="OSS-Fuzz issue id, e.g. 10012")
    p_arvo.set_defaults(func=_cmd_arvo)

    p_nvd = sub.add_parser("nvd", help="harvest multi-CWE chain seeds from NVD for a source CWE")
    p_nvd.add_argument("source_cwe", type=int, help="source CWE, e.g. 190")
    p_nvd.add_argument("--max-pages", type=int, default=1, dest="max_pages")
    p_nvd.add_argument("--per-page", type=int, default=200, dest="per_page")
    p_nvd.add_argument("--api-key", default=None, dest="api_key", help="NVD API key (optional)")
    p_nvd.set_defaults(func=_cmd_nvd)

    p_pa = sub.add_parser(
        "pilot-assemble",
        help="assemble ChainRecords from pilot evidence JSONs + arvo.db, report GATE-1",
    )
    p_pa.add_argument("evidence_dir", help="dir containing per-case evidence.json files")
    p_pa.add_argument("--db", required=True, help="path to arvo.db")
    p_pa.add_argument("--out", default=None, help="write records as JSONL to this path")
    p_pa.add_argument("--id-start", type=int, default=1, dest="id_start")
    p_pa.set_defaults(func=_cmd_pilot_assemble)

    p_con = sub.add_parser(
        "consolidate",
        help="merge many batch evidence dirs into one deduplicated stable-id dataset",
    )
    p_con.add_argument(
        "evidence_dir", nargs="+", help="one or more dirs of per-case evidence.json files"
    )
    p_con.add_argument("--db", required=True, help="path to arvo.db")
    p_con.add_argument("--out", required=True, help="write canonical dataset JSONL here")
    p_con.add_argument(
        "--manifest", default=None, help="manifest.json path (default: <out>.manifest.json)"
    )
    p_con.set_defaults(func=_cmd_consolidate)

    p_syn = sub.add_parser(
        "synthesize",
        help="generate the synthetic length-3 stratum from a real length-2 dataset",
    )
    p_syn.add_argument("dataset", help="real length-2 dataset JSONL (the anchor corpus)")
    p_syn.add_argument("--out", required=True, help="write synthetic (or union) records here")
    p_syn.add_argument(
        "--union",
        action="store_true",
        help="write real + synthetic union (default: synthetic only)",
    )
    p_syn.set_defaults(func=_cmd_synthesize)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
