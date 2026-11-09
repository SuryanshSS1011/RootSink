"""Duplicates and split leakage: one codebase under several names, one fix under two projects."""

import importlib.util
import json
from pathlib import Path

from chainforge.field_policy import canonical_project

ROOT = Path(__file__).resolve().parents[1]


def _load(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / f"infra/verify/{name}.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


dedup = _load("dedup_groups")
audit = _load("duplicate_audit")


def test_canonical_project_folds_aliases_and_forks():
    for name in ("imagemagick", "imagemagick/imagemagick", "ImageMagick/ImageMagick.git"):
        assert canonical_project(name) == "imagemagick"
    assert canonical_project("vadz/libtiff") == canonical_project("libtiff")
    assert canonical_project("php-src") != canonical_project("php")


def _rec(i, project, split, fix=None, crash=None):
    return {
        "id": f"CHAINFORGE-{i}",
        "project": project,
        "split": split,
        "aliases": [crash] if crash else [],
        "commit_range": {"fixed": f"https://x/commit/{fix}" if fix else None},
    }


def _run(tmp_path, rows):
    (tmp_path / "dataset.jsonl").write_text("".join(json.dumps(r) + "\n" for r in rows))
    (tmp_path / "corrections_changelog.jsonl").write_text("")
    dedup.main(["--release", str(tmp_path)])
    out = [json.loads(line) for line in (tmp_path / "dataset.jsonl").read_text().splitlines()]
    log = [
        json.loads(line)
        for line in (tmp_path / "corrections_changelog.jsonl").read_text().splitlines()
    ]
    return {r["id"]: r for r in out}, log


def test_aliased_project_moves_to_its_majority_split(tmp_path):
    rows = [
        _rec(1, "php-src", "train"),
        _rec(2, "php-src", "train"),
        _rec(3, "php/php-src", "test"),
        _rec(4, "linux-kernel", "test"),
        _rec(5, "linux-kernel", "train"),
    ]
    out, log = _run(tmp_path, rows)
    assert out["CHAINFORGE-3"]["split"] == "train"
    assert [e["op"] for e in log] == ["project-alias-split"]
    # linux-kernel is split by subsystem on purpose and must not be consolidated
    assert {out["CHAINFORGE-4"]["split"], out["CHAINFORGE-5"]["split"]} == {"test", "train"}


def test_one_fix_under_two_project_names_is_one_group(tmp_path):
    sha = "a" * 40
    rows = [
        _rec(1, "linux-kernel", "validation", fix=sha, crash="syzbot-1"),
        _rec(2, "linux", "train", fix=sha, crash="syzbot-2"),
    ]
    out, _ = _run(tmp_path, rows)
    assert out["CHAINFORGE-1"]["duplicate_group"] == out["CHAINFORGE-2"]["duplicate_group"]
    assert out["CHAINFORGE-1"]["split"] == out["CHAINFORGE-2"]["split"]


def test_changed_lines_ignore_whitespace_headers_and_boilerplate():
    a = "--- a/x.c\n+++ b/x.c\n@@ -1 +1 @@\n+  if (n > len)\n+    return -1;\n }\n"
    b = "--- a/y.c\n+++ b/y.c\n@@ -9 +9 @@\n+if(n>len)\n+return -1;\n"
    assert audit.changed_lines(a) == audit.changed_lines(b) == ["+if(n>len)"]
