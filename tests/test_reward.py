from chainforge.reward import coverage_kept, replay, root_site, shaped

REC = {
    "chain": [
        {
            "cwe_id": 20,
            "evidence": {"location": {"file": "lib/parse.c", "line": 120, "function": "parse_hdr"}},
        },
        {"cwe_id": 787, "evidence": {"location": {"file": "/src/p/lib/copy.c", "line": 9}}},
    ]
}


def patch(file: str, start: int, ctx: str = "") -> str:
    return (
        f"diff --git a/{file} b/{file}\n--- a/{file}\n+++ b/{file}\n"
        f"@@ -{start},3 +{start},4 @@ {ctx}\n a\n+if (n > max) return -1;\n b\n c\n"
    )


def test_replay_never_scores_an_environment_failure():
    assert replay({"outcome": "pass"}) == 1.0
    assert replay({"outcome": "build_fail"}) == 0.0
    assert replay({"outcome": "not_run"}) is None


def test_a_pass_that_needed_fuzz_earns_nothing_unless_lenient():
    fuzzed = {"outcome": "pass", "apply": {"mode": "per-file", "fuzz": 2}}
    assert replay(fuzzed) == 0.0
    assert replay(fuzzed, strict=False) == 1.0
    assert replay({"outcome": "pass", "apply": {"mode": "whole", "fuzz": 0}}) == 1.0


def test_root_site_levels():
    assert root_site(patch("lib/parse.c", 115), REC) == 1.0
    assert root_site(patch("lib/parse.c", 900, "static int parse_hdr(ctx *c)"), REC) == 1.0
    assert root_site(patch("lib/parse.c", 900), REC) == 0.5
    assert root_site(patch("lib/copy.c", 9), REC) == 0.0


def test_coverage_loss_zeroes_a_passing_patch():
    rec = REC | {"rl_scoring": {"corpus": {"nopatch_ft": 1000}}}
    res = {"outcome": "pass", "corpus": {"ft": 400}}
    assert coverage_kept(res, rec) == 0.4
    assert shaped(res, patch("lib/parse.c", 115), rec) == 0.0
    ok = {"outcome": "pass", "corpus": {"ft": 998}}
    assert shaped(ok, patch("lib/parse.c", 115), rec) == 1.25
    assert coverage_kept(ok, REC) is None
    assert shaped({"outcome": "crash"}, "", REC) == 0.0
