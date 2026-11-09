"""Each task's input must not contain its target: the fix, the chain, the sites or the labels."""

from chainforge.field_policy import (
    annotation_view,
    labeling_view,
    localization_view,
    model_view,
    policy_view,
    task_target,
)

RECORD = {
    "id": "CHAINFORGE-0000000001",
    "project": "wireshark",
    "language": "C",
    "chain": [
        {
            "cwe_id": 20,
            "evidence": {
                "location": {"file": "epan/quic.c", "line": 4211, "function": "dissect_cid"},
                "patch_hunk_ref": "CAUSALLY PROVEN: guard establishes CWE-20",
            },
        },
        {
            "cwe_id": 787,
            "evidence": {"location": {"file": "epan/tvb.c", "line": 77, "function": "memcpy_x"}},
        },
    ],
    "chain_string": "CWE-20->CWE-787",
    "locality": "cross-function",
    "patch_diff": "+ if (dcil <= QUIC_MAX_CID_LENGTH)",
    "pov_input": "pov.bin",
    "docker_image_ref": {
        "vulnerable": "n132/arvo:1-vul@sha256:a",
        "patched": "n132/arvo:1-fix@sha256:b",
    },
    "sanitizer_reports": [
        {"revision": "vulnerable", "log_ref": "vul.txt", "triggered": True},
        {"revision": "vulnerable", "log_ref": "ubsan.vul.txt", "witnesses": "intermediate"},
        {"revision": "patched", "log_ref": "fix1.txt", "triggered": False},
    ],
}


def test_policy_view_withholds_everything_the_reward_uses():
    v = policy_view(RECORD)
    flat = repr(v)
    assert "patch_diff" not in v and "chain" not in v and "chain_string" not in v
    assert "QUIC_MAX_CID_LENGTH" not in flat and "fix@" not in flat and "fix1.txt" not in flat
    assert v["vulnerable_image"].endswith("sha256:a")
    assert [s["log_ref"] for s in v["sanitizer_reports"]] == ["vul.txt"]
    assert "project" not in v  # identity fields leak the label


def test_localization_input_hides_the_source_site_and_the_fix():
    v, flat = localization_view(RECORD), repr(localization_view(RECORD))
    assert task_target(RECORD, "localize") == {
        "file": "epan/quic.c",
        "line": 4211,
        "function": "dissect_cid",
        "site_kind": None,  # the fixture predates site_kind; the release stamps every link
    }
    assert "quic.c" not in flat and "4211" not in flat and "dissect_cid" not in flat
    assert "QUIC_MAX_CID_LENGTH" not in flat and "locality" not in v and "CWE-20" not in flat
    assert v["sink"] == {"cwe_id": 787, "file": "epan/tvb.c", "line": 77, "function": "memcpy_x"}
    assert "QUIC_MAX_CID_LENGTH" in repr(localization_view(RECORD, with_fix=True))


def test_labeling_input_hides_every_cwe():
    v, flat = labeling_view(RECORD), repr(labeling_view(RECORD))
    assert task_target(RECORD, "label") == [20, 787]
    assert "cwe_id" not in flat and "CWE-" not in flat and "chain_string" not in v
    assert [s["file"] for s in v["sites"]] == ["epan/quic.c", "epan/tvb.c"]
    assert "patch_diff" not in v


def test_annotation_view_carries_labels_and_is_not_a_task_input():
    assert model_view is annotation_view
    a = annotation_view(RECORD)
    assert a["chain_string"] == "CWE-20->CWE-787" and "patch_diff" in a


def test_canonical_project_folds_aliases_and_branch_projects():
    from chainforge.field_policy import canonical_project

    assert canonical_project("ImageMagick/ImageMagick.git") == "imagemagick"
    for n in ("libjpeg-turbo", "libjpeg-turbo.2.0.x", "libjpeg-turbo.dev", "libjpeg-turbo.main"):
        assert canonical_project(n) == "libjpeg-turbo"
    assert canonical_project("freetype2") == canonical_project("freetype")
    assert canonical_project("cpython3") == canonical_project("python/cpython")
    assert canonical_project("ggml-org/llama") == canonical_project("llama.cpp")
    # Distinct projects that only share a prefix, and a dotted name that is not a branch.
    assert canonical_project("libssh2") != canonical_project("libssh")
    assert canonical_project("re2") != canonical_project("re")
    assert canonical_project("proj.4") == "proj.4"
