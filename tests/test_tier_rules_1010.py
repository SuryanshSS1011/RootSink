"""Release 1.0.10 tier rules: an Upstream record our fixed kernel refutes is Partial, a record no
run of ours reached is Candidate when its root CWE rests only on an advisory or the catalogue's
default, and kernel call traces place a root on the crash stack."""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "infra" / "verify"))
import stamp_attribution  # noqa: E402
import stamp_kernel_attempts  # noqa: E402

from chainforge.integrity import _two_sided_self_run, reached, tier_for, unreached_tier

UPSTREAM = [
    {
        "revision": "vulnerable",
        "triggered": True,
        "observed_by": "upstream",
        "log_ref": "https://syzkaller.appspot.com/text?tag=CrashReport&x=1",
    }
]


def test_fixed_kernel_that_still_crashes_is_not_upstream(tmp_path):
    rec = {"sanitizer_reports": UPSTREAM}
    assert _two_sided_self_run(rec, tmp_path) == "upstream"
    assert tier_for(rec, {"I5": "upstream"}) == "gold-upstream"
    rec["kernel_attempt"] = {"status": "fix_still_crashes"}
    why = _two_sided_self_run(rec, tmp_path)
    assert why != "upstream" and tier_for(rec, {"I5": why}) == "silver"
    rec["kernel_attempt"] = {"status": "vul_no_repro"}  # no confirmation is no refutation (R10)
    assert _two_sided_self_run(rec, tmp_path) == "upstream"


def test_reached_needs_a_run_not_just_an_attempt(tmp_path):
    rec = {"sanitizer_reports": UPSTREAM, "kernel_attempt": {"status": "no_crepro"}}
    assert not reached(rec, tmp_path)
    rec["kernel_attempt"] = {"status": "vul_build_failed"}
    assert not reached(rec, tmp_path)
    rec["kernel_attempt"] = {"status": "vul_no_repro", "detail": "did not trip (no_boot)"}
    assert not reached(rec, tmp_path)  # the kernel never booted, so nothing ran (R10)
    rec["kernel_attempt"] = {"status": "vul_no_repro", "detail": "did not trip (clean)"}
    assert reached(rec, tmp_path)
    own = {"sanitizer_reports": [{"revision": "vulnerable", "triggered": False}]}
    assert reached(own, tmp_path)


def test_unreached_record_with_only_an_advisory_root_is_candidate():
    advisory = {"role": "source", "cwe_id": 20, "evidence": {"patch_hunk_ref": "NVD lists CWE-20"}}
    rec = {"provenance": "nvd-mined", "chain": [advisory, {"role": "sink", "cwe_id": 787}]}
    assert unreached_tier(rec) == "bronze"
    flow = {"role": "source", "cwe_id": 20, "evidence": {"dataflow_path": ["a", "b"]}}
    rec["chain"][0] = flow
    assert unreached_tier(rec) == "silver"
    default = {"role": "source", "cwe_id": 20, "evidence": {}}
    rec["chain"][0] = default
    assert unreached_tier(rec) == "bronze"


def test_latest_attempt_that_ran_is_stamped(tmp_path):
    log = [
        {
            "id": "K1",
            "op": "kernel-differential-attempt",
            "status": "vul_no_repro",
            "detail": "(clean)",
        },
        {"id": "K1", "op": "kernel-differential-attempt", "status": "vul_build_failed"},
    ]
    (tmp_path / "corrections_changelog.jsonl").write_text(
        "".join(json.dumps(e) + "\n" for e in log)
    )
    (tmp_path / "dataset.jsonl").write_text(json.dumps({"id": "K1"}) + "\n")
    stamp_kernel_attempts.main(["--release", str(tmp_path)])
    rec = json.loads((tmp_path / "dataset.jsonl").read_text())
    assert (
        rec["kernel_attempt"]["status"] == "vul_no_repro" and rec["kernel_attempt"]["attempts"] == 2
    )


def test_last_attempt_is_stamped_once(tmp_path):
    log = [
        {"id": "K1", "op": "kernel-differential-attempt", "status": "vul_other_bug", "detail": "x"},
        {"id": "K1", "op": "kernel-differential-attempt", "status": "fix_still_crashes"},
    ]
    (tmp_path / "corrections_changelog.jsonl").write_text(
        "".join(json.dumps(e) + "\n" for e in log)
    )
    (tmp_path / "dataset.jsonl").write_text(json.dumps({"id": "K1"}) + "\n")
    stamp_kernel_attempts.main(["--release", str(tmp_path)])
    rec = json.loads((tmp_path / "dataset.jsonl").read_text())
    assert rec["kernel_attempt"]["status"] == "fix_still_crashes"
    assert rec["kernel_attempt"]["attempts"] == 2
    n = len((tmp_path / "corrections_changelog.jsonl").read_text().splitlines())
    stamp_kernel_attempts.main(["--release", str(tmp_path)])
    assert len((tmp_path / "corrections_changelog.jsonl").read_text().splitlines()) == n


KASAN = """[  138.7][T3] BUG: KASAN: slab-use-after-free in number+0x954/0xa50
[  138.7][T3] Call Trace:
[  138.7][T3]  <TASK>
[  138.7][T3]  dump_stack_lvl+0x78/0xe0
[  138.7][T3]  ? number+0x954/0xa50
[  138.7][T3]  number+0x954/0xa50
[  138.7][T9]  other_task_frame+0x1/0x2
[  138.7][T9] executing program
[  138.7][T3]  ? fd_install+0x1d0/0x3d0
[  138.7][T3]  media_request_alloc.constprop.0+0x32a/0x5a0
[  138.7][T3]  </TASK>
[  138.7][T3] RIP: 0033:0x41d74d
[  138.8][T3] Allocated by task 3:
[  138.8][T3]  kmalloc_trace+0x1/0x2
"""


def test_kernel_call_trace_frames_are_read():
    names = stamp_attribution.kernel_crash_stack(KASAN)
    assert names == ["dump_stack_lvl", "number", "media_request_alloc"]


def test_no_crash_log_gives_no_stack_relation(tmp_path):
    rec = {
        "chain": [
            {"evidence": {"location": {"file": "a.c", "line": 1, "function": "f"}}},
            {"evidence": {"location": {"file": "b.c", "line": 9, "function": "g"}}},
        ],
        "sanitizer_reports": UPSTREAM,
    }
    assert stamp_attribution.site_relation(rec, tmp_path) is None
