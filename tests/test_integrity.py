"""PR-3's GOLD contract: the rules that assign a tier are the rules that check it."""

from pathlib import Path

from chainforge.integrity import crash_facts, gold_violations, source_contradiction, tier_for

ASAN_HBO = "==1==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x6\nWRITE of size 4 at"
ASAN_NULL = "==1==ERROR: AddressSanitizer: SEGV on unknown address 0x000000000010 (pc 0x5"
KASAN_UAF = "BUG: KASAN: slab-use-after-free in iowarrior_write_callback+0x1c/0x40\nWrite of size 4"


def rec(src: int, sink: int) -> dict:
    return {"chain": [{"cwe_id": src}, {"cwe_id": sink}]}


def test_crash_facts_reads_asan_and_kasan():
    assert crash_facts(ASAN_HBO) == {
        "class": "heap-buffer-overflow",
        "null_deref": False,
        "access": "WRITE",
    }
    assert crash_facts(KASAN_UAF)["class"] == "slab-use-after-free"
    assert crash_facts(KASAN_UAF)["access"] == "WRITE"
    assert crash_facts(ASAN_NULL)["null_deref"]


def test_static_source_contradicted_by_its_own_crash():
    # a CWE-416 source on a heap-buffer-overflow is the shape 271 GOLD records had
    assert source_contradiction(rec(416, 787), crash_facts(ASAN_HBO))
    assert source_contradiction(rec(476, 787), crash_facts(ASAN_HBO))
    assert source_contradiction(rec(416, 787), crash_facts(KASAN_UAF)) is None
    assert source_contradiction(rec(476, 787), crash_facts(ASAN_NULL)) is None
    assert source_contradiction(rec(20, 787), crash_facts(ASAN_HBO)) is None


def test_upstream_only_witness_is_gold_upstream_never_gold():
    r = rec(416, 787) | {
        "commit_range": {"fixed": "a" * 40, "fix_commits": ["a" * 40]},
        "patch_diff": "diff --git a/k.c b/k.c\n@@ -1 +1,2 @@\n+ lock();\n",
        "sanitizer_reports": [
            {
                "revision": "vulnerable",
                "triggered": True,
                "observed_by": "upstream",
                "log_ref": "https://syzkaller.appspot.com/text?tag=CrashReport&x=1",
            }
        ],
    }
    v = gold_violations(r, Path("."), facts=crash_facts(KASAN_UAF))
    assert v == {"I5": "upstream"}
    assert tier_for(r, v) == "gold-upstream"
    assert tier_for(r, {"I5": "upstream", "I3": "x"}) == "silver"
    assert tier_for(r, {}) == "gold"


def test_gold_needs_a_recorded_fix_commit():
    # Criterion (d): the fix is a real patch under the recorded commit id.
    r = rec(416, 787) | {"patch_diff": "diff --git a/k.c b/k.c\n@@ -1 +1,2 @@\n+ lock();\n"}
    v = gold_violations(r, Path("."), facts=crash_facts(KASAN_UAF))
    assert v.get("I3") == "no recorded fix commit"


def test_a_patched_run_is_clean_only_if_the_input_ran():
    from chainforge.integrity import ran_clean

    assert ran_clean("Running: /tmp/poc\nExecuted /tmp/poc in 3 ms\n")  # libFuzzer
    assert ran_clean("Reading 33 bytes from /tmp/poc\nExecution successful\n")  # AFL
    assert ran_clean("Accepting input from '/tmp/poc'\nUsage for fuzzing: honggfuzz -P\n")
    # 32-bit ASan that aborted before main: no crash line, and it never ran
    assert not ran_clean("==1==Shadow memory range interleaves with an existing memory mapping.")
    assert not ran_clean("Running: /tmp/poc\n")  # started, never finished
    assert not ran_clean(
        "Executed /tmp/poc in 3 ms\nSUMMARY: AddressSanitizer: heap-buffer-overflow"
    )


def test_segv_access_direction_contradicts_a_write_sink():
    from chainforge.integrity import sink_contradiction

    segv = (
        "==1==ERROR: UndefinedBehaviorSanitizer: SEGV on unknown address 0x000000000000\n"
        "==1==The signal is caused by a READ memory access.\n"
    )
    assert crash_facts(segv)["access"] == "READ"
    assert sink_contradiction(rec(476, 787), crash_facts(segv))
    assert sink_contradiction(rec(20, 125), crash_facts(segv)) is None


def test_a_rebuild_witnessing_an_intermediate_is_not_the_sink_replay(tmp_path):
    for name in ("ubsan.vul.txt", "fix1.txt", "fix2.txt"):
        (tmp_path / name).write_text("Executed /tmp/poc in 3 ms\n")
    (tmp_path / "ubsan.vul.txt").write_text("a.c:3:5: runtime error: signed integer overflow\n")
    r = {
        "chain": [{"cwe_id": 20}, {"cwe_id": 190}, {"cwe_id": 125}],
        "differential_complete": True,
        "sanitizer_reports": [
            {
                "revision": "vulnerable",
                "triggered": True,
                "observed_by": "self",
                "log_ref": "ubsan.vul.txt",
                "witnesses": "intermediate",
            },
        ]
        + [
            {"revision": "patched", "triggered": False, "observed_by": "self", "log_ref": f}
            for f in ("fix1.txt", "fix2.txt")
        ],
    }
    assert gold_violations(r, tmp_path)["I5"] == "no triggered vulnerable-side report"


def test_kernel_boot_banner_is_not_a_crash():
    from chainforge.integrity import ran_clean

    boot = "[0.16] kasan: KernelAddressSanitizer initialized\n[9.0] [init] environment up\n"
    assert ran_clean(boot)
    assert not ran_clean(boot + "[12.0] BUG: KASAN: slab-out-of-bounds in f+0x1/0x2\n")


def test_use_after_free_sink_needs_a_416_link_before_it():
    from chainforge.integrity import sink_contradiction

    uaf = crash_facts(
        "==1==ERROR: AddressSanitizer: heap-use-after-free on address\nWRITE of size 4"
    )
    assert sink_contradiction(rec(20, 787), uaf)
    assert sink_contradiction(rec(416, 787), uaf) is None
    three = {"chain": [{"cwe_id": 362}, {"cwe_id": 416}, {"cwe_id": 787}]}
    assert sink_contradiction(three, uaf) is None
