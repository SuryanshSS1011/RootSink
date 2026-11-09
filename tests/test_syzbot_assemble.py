from chainforge.mining.syzbot_assemble import assemble_syzbot_chain
from chainforge.schema import ChainRecord, ConfidenceTier

OOB_WRITE = """\
BUG: KASAN: slab-out-of-bounds in bch2_dirent_init_name+0x396/0x8b0 fs/bcachefs/dirent.c:273
Write of size 1985 at addr ffff8881496a3041 by task syz/1
Call Trace:
 <TASK>
 __asan_memset+0x22/0x50 mm/kasan/shadow.c:84
 bch2_dirent_init_name+0x396/0x8b0 fs/bcachefs/dirent.c:273
 __x64_sys_link+0x82/0x90 fs/namei.c:4965
"""

OOB_READ = OOB_WRITE.replace("Write of size 1985", "Read of size 8")

OVERFLOW_FIX = "+++ b/f.c\n@@\n+    if (len > SIZE_MAX / n)\n+        return -EOVERFLOW;\n"
VALIDATION_FIX = "+++ b/f.c\n@@\n+    if (count > MAX)\n+        return -EINVAL;\n"
NEUTRAL_FIX = "+++ b/f.c\n@@\n+    x = 1;\n"


def test_overflow_fix_gives_silver_190_chain():
    rec = assemble_syzbot_chain("abc", "CHAINFORGE-0000000001", OOB_WRITE, OVERFLOW_FIX)
    assert rec is not None
    assert rec.chain_string == "CWE-190->CWE-787"
    assert rec.label_confidence_tier == ConfidenceTier.SILVER
    assert rec.ecosystem == "linux-kernel"
    assert "syzbot-abc" in rec.aliases
    assert rec.license == "GPL-2.0"
    # KASAN sink witness present
    assert any(r.triggered for r in rec.sanitizer_reports)


def test_validation_fix_gives_silver_20_chain():
    rec = assemble_syzbot_chain("abc", "CHAINFORGE-0000000002", OOB_WRITE, VALIDATION_FIX)
    assert rec.chain_string == "CWE-20->CWE-787"
    assert rec.label_confidence_tier == ConfidenceTier.SILVER


def test_overflow_beats_validation_when_both():
    both = OVERFLOW_FIX + VALIDATION_FIX
    rec = assemble_syzbot_chain("abc", "CHAINFORGE-0000000003", OOB_WRITE, both)
    assert rec.chain[0].cwe_id == 190  # overflow is the proximate root


def test_no_source_signal_is_bronze_candidate():
    rec = assemble_syzbot_chain("abc", "CHAINFORGE-0000000004", OOB_WRITE, NEUTRAL_FIX)
    assert rec.label_confidence_tier == ConfidenceTier.BRONZE
    # falls back to first admissible source for 787 (=20)
    assert rec.chain[0].cwe_id == 20


def test_oob_read_sink_is_125():
    rec = assemble_syzbot_chain("abc", "CHAINFORGE-0000000005", OOB_READ, OVERFLOW_FIX)
    assert rec.chain_string == "CWE-190->CWE-125"


def test_unrecognized_report_returns_none():
    assert assemble_syzbot_chain("abc", "CHAINFORGE-0000000006", "no kasan here", None) is None


def test_record_revalidates_and_carries_callpath():
    rec = assemble_syzbot_chain("abc", "CHAINFORGE-0000000007", OOB_WRITE, OVERFLOW_FIX)
    ChainRecord.model_validate_json(rec.model_dump_json())  # round-trip
    assert "__x64_sys_link" in rec.dataflow_evidence
    assert rec.locality is None  # derived from witnessed locations later, never assumed


UAF_READ = """\
BUG: KASAN: slab-use-after-free in foo_read+0x10/0x20 fs/foo.c:42
Read of size 8 at addr ffff8881 by task syz/1
Call Trace:
 <TASK>
 foo_read+0x10/0x20 fs/foo.c:42
 __x64_sys_read+0x82/0x90 fs/read_write.c:100
"""

NULL_DEREF = """\
BUG: KASAN: null-ptr-deref in bar+0x50/0x100 io/bar.c:10
Write of size 4 at addr 0000000000000000 by task syz/1
Call Trace:
 bar+0x50/0x100 io/bar.c:10
"""


def test_uaf_read_is_416_to_125_silver():
    # PR-2: KASAN witnesses the free->use link -> 416->125 SILVER, no patch needed.
    rec = assemble_syzbot_chain("uaf1", "CHAINFORGE-0000000010", UAF_READ, None)
    assert rec is not None
    assert rec.chain_string == "CWE-416->CWE-125"
    assert rec.label_confidence_tier == ConfidenceTier.SILVER
    assert rec.chain[0].cwe_id == 416


def test_uaf_write_is_416_to_787():
    w = UAF_READ.replace("Read of size 8", "Write of size 8")
    rec = assemble_syzbot_chain("uaf2", "CHAINFORGE-0000000011", w, None)
    assert rec.chain_string == "CWE-416->CWE-787"
    assert rec.label_confidence_tier == ConfidenceTier.SILVER


def test_null_deref_dropped():
    # PR-2: null-ptr-deref excluded -> assembler returns None.
    assert assemble_syzbot_chain("nd", "CHAINFORGE-0000000012", NULL_DEREF, None) is None
