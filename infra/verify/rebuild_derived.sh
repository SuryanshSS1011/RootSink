#!/usr/bin/env bash
# Regenerate everything derived from data/release/dataset.jsonl, then gate the release.
# Run after ANY change to the dataset and before any freeze or commit: the manifest, paper
# numbers, Croissant checksum and bundles are all stale the moment the dataset changes.
set -euo pipefail
cd "$(dirname "$0")/../.."
mkdir -p paper_artifacts  # absent in a fresh clone of the public release
uv run python infra/verify/apply_license_overrides.py >/dev/null
uv run python infra/verify/normalize_fix_commits.py >/dev/null
uv run python infra/verify/locate_tested_sites.py >/dev/null
uv run python infra/verify/move_origin_roots.py >/dev/null  # 1.0.7: tested site becomes the root
uv run python infra/verify/relabel_freed_msan.py >/dev/null  # 1.0.7: freed-memory MSan origins
uv run python infra/verify/fix_library_origins.py >/dev/null  # 1.0.8: origins off libc++ frames
uv run python infra/verify/stamp_probed_site.py >/dev/null  # 1.0.8: the site PR-14 probed
uv run python infra/verify/stamp_kernel_application.py >/dev/null
uv run python infra/verify/apply_pr17.py >/dev/null
uv run python infra/verify/reground_mitre.py >/dev/null
uv run python infra/verify/repair_function_names.py >/dev/null
uv run python infra/verify/restamp_evidence_kinds.py >/dev/null
uv run python infra/verify/retier_all.py >/dev/null
uv run python infra/verify/stamp_attribution.py >/dev/null
uv run python infra/verify/stamp_difficulty.py >/dev/null
uv run python infra/verify/dedup_groups.py >/dev/null
uv run python infra/verify/split_components.py >/dev/null  # R9: kernel subsystems whole (1.0.3)
uv run python infra/verify/baselines.py >/dev/null  # after every split move
uv run python infra/verify/stamp_sampling_weight.py >/dev/null
uv run python infra/verify/build_manifest.py >/dev/null
uv run python infra/verify/duplicate_audit.py >/dev/null
uv run python infra/paper/build_artifacts.py >/dev/null
uv run python infra/paper/build_croissant.py >/dev/null
uv run python infra/verify/score_audit.py >/dev/null
uv run python infra/verify/score_ai_raters.py >/dev/null  # PR-9 exploratory AI raters
uv run python infra/paper/build_macros.py >/dev/null
uv run python infra/paper/build_supplement.py >/dev/null
if [ -d paper ]; then  # the paper sources live only in the development repo
  mkdir -p paper/generated && cp paper_artifacts/macros.tex paper_artifacts/composition.tex paper/generated/
fi
uv run python infra/repro/facts_from_logs.py --out infra/repro/facts_by_id.json >/dev/null
rm -f infra/repro/bundles/CHAINFORGE-*.json  # dropped records must not keep a bundle
uv run python infra/repro/bundle.py data/release/dataset.jsonl --out infra/repro/bundles \
  --facts infra/repro/facts_by_id.json >/dev/null
uv run python infra/verify/conformance.py
