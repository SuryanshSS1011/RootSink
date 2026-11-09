from chainforge.mining.syzbot_chains import parse_kasan_report

# Real syzbot report shape (bch2_dirent_init_name OOB write), trimmed.
OOB_WRITE = """\
==================================================================
BUG: KASAN: slab-out-of-bounds in bch2_dirent_init_name+0x396/0x8b0 fs/bcachefs/dirent.c:273
Write of size 1985 at addr ffff8881496a3041 by task syz-executor478/5839

Call Trace:
 <TASK>
 dump_stack_lvl+0x189/0x250 lib/dump_stack.c:120
 __asan_memset+0x22/0x50 mm/kasan/shadow.c:84
 bch2_dirent_init_name+0x396/0x8b0 fs/bcachefs/dirent.c:273
 bch2_dirent_create+0xc5/0xc80 fs/bcachefs/dirent.c:358
 bch2_link_trans+0x39e/0x560 fs/bcachefs/namei.c:241
 vfs_link+0x4ea/0x6e0 fs/namei.c:4863
 __x64_sys_link+0x82/0x90 fs/namei.c:4965
 do_syscall_64+0xfa/0x3b0 arch/x86/entry/syscall_64.c:94
 entry_SYSCALL_64_after_hwframe+0x77/0x7f
RIP: 0033:0x7f5e63959b19
==================================================================
"""

UAF_READ = """\
BUG: KASAN: slab-use-after-free in hidraw_report_event+0x100/0x200 drivers/hid/hidraw.c:520
Read of size 8 at addr ffff8881 by task syz/1
Call Trace:
 <TASK>
 hidraw_report_event+0x100/0x200 drivers/hid/hidraw.c:520
 __x64_sys_ioctl+0x82/0x90 fs/ioctl.c:100
 do_syscall_64+0xfa/0x3b0 arch/x86/entry/syscall_64.c:94
"""

NULL_WRITE = """\
BUG: KASAN: null-ptr-deref in io_uring_register+0x50/0x100 io_uring/register.c:10
Write of size 4 at addr 0000000000000000 by task syz/1
Call Trace:
 io_uring_register+0x50/0x100 io_uring/register.c:10
 __x64_sys_io_uring_register+0x10/0x20 io_uring/register.c:99
"""


def test_oob_write_is_787():
    k = parse_kasan_report(OOB_WRITE)
    assert k.sink_cwe == 787
    assert k.kasan_type == "out-of-bounds"
    assert k.access_kind == "Write"
    assert k.access_size == 1985
    assert k.fault_func == "bch2_dirent_init_name"
    assert k.fault_file == "fs/bcachefs/dirent.c"
    assert k.fault_line == 273


def test_oob_write_call_trace_and_syscall():
    k = parse_kasan_report(OOB_WRITE)
    funcs = [f.func for f in k.call_trace]
    assert "bch2_dirent_init_name" in funcs
    assert "__x64_sys_link" in funcs
    sc = k.syscall_entry
    assert sc is not None and sc.func == "__x64_sys_link"
    # trace stops before register dump
    assert not any(f.func.startswith("RIP") for f in k.call_trace)


def test_uaf_read_source_416_sink_125():
    # PR-2: use-after-free Read -> source CWE-416 (freed-ptr reuse), sink CWE-125 (OOB read).
    k = parse_kasan_report(UAF_READ)
    assert k.source_cwe == 416
    assert k.sink_cwe == 125
    assert k.kasan_type == "use-after-free"
    assert k.syscall_entry.func == "__x64_sys_ioctl"


def test_uaf_write_source_416_sink_787():
    w = UAF_READ.replace("Read of size 8", "Write of size 8")
    k = parse_kasan_report(w)
    assert k.source_cwe == 416
    assert k.sink_cwe == 787


def test_null_deref_excluded():
    # PR-2: null-ptr-deref does not decompose into a chain -> no sink, no source.
    k = parse_kasan_report(NULL_WRITE)
    assert k.sink_cwe is None
    assert k.source_cwe is None
    assert k.kasan_type == "null-ptr-deref"


def test_oob_read_is_125():
    r = OOB_WRITE.replace("Write of size 1985", "Read of size 8")
    k = parse_kasan_report(r)
    assert k.sink_cwe == 125
    assert k.access_kind == "Read"


def test_ordered_link_summary_is_syscall_first_and_stripped():
    k = parse_kasan_report(OOB_WRITE)
    s = k.ordered_link_summary
    assert "__x64_sys_link" in s and "bch2_dirent_init_name" in s
    # syscall entry comes BEFORE the fault site (control-flow order)
    assert s.index("__x64_sys_link") < s.index("bch2_dirent_init_name")
    # KASAN machinery stripped
    assert "__asan_memset" not in s and "kasan_report" not in s and "dump_stack" not in s


def test_bug_path_strips_prologue():
    k = parse_kasan_report(OOB_WRITE)
    funcs = [f.func for f in k.bug_path]
    assert "dump_stack_lvl" not in funcs
    assert "__asan_memset" not in funcs
    assert "bch2_dirent_init_name" in funcs  # the real fault site survives
    assert funcs[0] == "__x64_sys_link"  # syscall first


def test_unrecognized_report():
    k = parse_kasan_report("some kernel log with no KASAN diagnosis")
    assert k.sink_cwe is None
    assert k.kasan_type == "unknown"
