"""A multi-shot KASAN console holds several reports; the excerpt must be syzbot's bug."""

import importlib.util
from pathlib import Path

spec = importlib.util.spec_from_file_location(
    "akd", Path(__file__).resolve().parents[1] / "infra/verify/attach_kernel_differentials.py"
)
akd = importlib.util.module_from_spec(spec)
spec.loader.exec_module(akd)

CONSOLE = "\n".join(
    [
        "[    0.0] Linux version 6.8.0",
        "[    9.1] BUG: KASAN: slab-out-of-bounds in other_fn+0x10/0x20",  # different function
        "[    9.1] Read of size 4 at addr ffff",
        "[   10.1] BUG: KASAN: slab-out-of-bounds in target_fn+0x10/0x20",  # right fn, wrong class
        "[   10.1] Read of size 8 at addr ffff",
        "[   11.1] BUG: KASAN: slab-use-after-free in target_fn.part.0+0x7f/0xaa",  # right, but Read
        "[   11.1] Read of size 8 at addr ffff",
        "[   12.1] BUG: KASAN: slab-use-after-free in target_fn.part.0+0xa5/0xaa",  # syzbot's bug
        "[   12.1] Write of size 8 at addr ffff",
        "[   12.2] ==================================================================",
    ]
)


def test_excerpt_is_the_report_matching_class_function_and_access():
    out = akd.kasan_excerpt(CONSOLE, "slab-use-after-free:target_fn", "Write")
    assert "0xa5/0xaa" in out and "Write of size 8" in out
    assert "other_fn" not in out


def test_without_an_access_hint_the_first_class_and_function_match_wins():
    out = akd.kasan_excerpt(CONSOLE, "slab-use-after-free:target_fn")
    assert "0x7f/0xaa" in out


def test_pr6_matches_syzbot_function_in_the_reports_call_trace():
    console = "\n".join(
        [
            "[ 1.0] BUG: KASAN: slab-use-after-free in __list_del_entry_valid_or_report+0x14c/0x1c0",
            "[ 1.0] Write of size 8 at addr ffff",
            "[ 1.0] Call Trace:",
            "[ 1.0]  dump_stack_lvl+0x6a/0x9b",
            "[ 1.0]  l2tp_session_delete.part.0+0x7f9/0xaa0",
            "[ 1.1] ==================================================================",
            "[ 2.0] BUG: KASAN: slab-use-after-free in other_fn+0x10/0x20",
            "[ 2.0] Write of size 8 at addr ffff",
        ]
    )
    out = akd.kasan_excerpt(console, "slab-use-after-free:l2tp_session_delete", "Write")
    assert "__list_del_entry_valid_or_report" in out and "other_fn" not in out
    # a same-class report whose trace lacks syzbot's function is a different bug
    assert "other_fn" not in akd.kasan_excerpt(console, "slab-use-after-free:missing_fn", "Write")


def test_same_bug_needs_class_and_function_or_trace():
    from chainforge.integrity import kasan_same_bug

    uaf = ["BUG: KASAN: use-after-free in ext4_write_inline_data_end+0x1/0x2"]
    assert kasan_same_bug(uaf, "slab-out-of-bounds:ext4_write_inline_data") == []
    oob = [
        "BUG: KASAN: slab-out-of-bounds in memcpy+0x1/0x2",
        "Call Trace:",
        " hci_inquiry_evt+0x10/0x20",
    ]
    assert kasan_same_bug(oob, "slab-out-of-bounds:hci_inquiry_evt") == [0]
