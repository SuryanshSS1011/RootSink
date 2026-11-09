import sqlite3

import pytest

from chainforge.mining.arvo_index import ArvoIndex

# Mirrors the real arvo.db `arvo` table shape (subset of columns the reader uses).
_ROWS = [
    # localId, project, fix_commit, patch_url, sanitizer, crash_type, lang, repo, reproduced
    (
        10012,
        "curl",
        "86b1e94ae72bc0e49745ed33d4b923ac8e6b8366",
        "url1",
        "ubsan",
        "Null-dereference READ",
        "c",
        "repo1",
        1,
    ),
    (
        40096184,
        "skia",
        "07afa23bd0fa74d18fb7faee898b2a876536a170",
        "url2",
        "asan",
        "Heap-buffer-overflow WRITE 4",
        "c++",
        "repo2",
        1,
    ),
    (
        50000001,
        "libfoo",
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "url3",
        "asan",
        "Heap-buffer-overflow READ 8",
        "c",
        "repo3",
        1,
    ),
]


@pytest.fixture
def db_path(tmp_path):
    p = tmp_path / "arvo.db"
    conn = sqlite3.connect(p)
    conn.execute(
        "CREATE TABLE arvo (localId INT, project TEXT, fix_commit TEXT, patch_url TEXT,"
        " sanitizer TEXT, crash_type TEXT, language TEXT, repo_addr TEXT, reproduced INT)"
    )
    conn.executemany("INSERT INTO arvo VALUES (?,?,?,?,?,?,?,?,?)", _ROWS)
    conn.commit()
    conn.close()
    return str(p)


def test_count(db_path):
    with ArvoIndex(db_path) as idx:
        assert idx.count() == 3


def test_by_fix_commit_match(db_path):
    with ArvoIndex(db_path) as idx:
        row = idx.by_fix_commit("07afa23bd0fa74d18fb7faee898b2a876536a170")
    assert row is not None
    assert row.local_id == 40096184
    assert row.project == "skia"
    assert row.vul_image == "n132/arvo:40096184-vul"


def test_by_fix_commit_case_insensitive(db_path):
    with ArvoIndex(db_path) as idx:
        row = idx.by_fix_commit("07AFA23BD0FA74D18FB7FAEE898B2A876536A170")
    assert row is not None and row.local_id == 40096184


def test_by_fix_commit_no_match(db_path):
    with ArvoIndex(db_path) as idx:
        assert idx.by_fix_commit("deadbeef" * 5) is None


def test_sink_cwes_from_crash_type(db_path):
    with ArvoIndex(db_path) as idx:
        skia = idx.by_fix_commit("07afa23bd0fa74d18fb7faee898b2a876536a170")
    # "Heap-buffer-overflow WRITE" -> CWE-787
    assert skia.sink_cwes == (787,)


def test_candidates_by_sink_cwe(db_path):
    with ArvoIndex(db_path) as idx:
        # CWE-787 (OOB write) -> only the skia WRITE case
        writes = idx.candidates_by_sink_cwe(787)
        assert [r.local_id for r in writes] == [40096184]
        # CWE-125 (OOB read) -> the libfoo READ case
        reads = idx.candidates_by_sink_cwe(125)
        assert [r.local_id for r in reads] == [50000001]


def test_candidates_language_filter(db_path):
    with ArvoIndex(db_path) as idx:
        c_reads = idx.candidates_by_sink_cwe(125, language="c")
        assert [r.local_id for r in c_reads] == [50000001]
        cpp_reads = idx.candidates_by_sink_cwe(125, language="c++")
        assert cpp_reads == []
