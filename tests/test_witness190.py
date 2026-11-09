from chainforge.witness190 import classify_witness

# A combined ASan+UBSan-recover trace where the overflow is reported BEFORE the OOB write.
ORDERED_TRACE = """\
calc.c:42:15: runtime error: unsigned integer overflow: 4294967295 * 8 cannot be represented
==1234==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x602000000010
WRITE of size 8 at 0x602000000010 thread T0
"""

# Overflow reported AFTER the memory error (not the enabling order).
REVERSED_TRACE = """\
==1==ERROR: AddressSanitizer: heap-buffer-overflow on address 0xdead
calc.c:42:15: runtime error: signed integer overflow
"""

SINK_ONLY = "==1==ERROR: AddressSanitizer: heap-buffer-overflow WRITE of size 4\n"
OVERFLOW_ONLY = "x.c:1:1: runtime error: unsigned integer overflow: a * b\n"


def test_gold_requires_all_five_conditions():
    w = classify_witness(42480000, ORDERED_TRACE, reproduced=True, has_patch=True)
    assert w.witnessed_overflow and w.witnessed_sink and w.ordered
    assert w.tier == "gold" and w.gold_eligible
    assert w.sink_kind == "heap-buffer-overflow"
    assert "overflow" in (w.overflow_snippet or "")


def test_not_reproduced_downgrades_to_silver():
    # ordered witness but no differential (vul/patched) -> not GOLD.
    w = classify_witness(1, ORDERED_TRACE, reproduced=False, has_patch=True)
    assert w.tier == "silver" and not w.gold_eligible


def test_no_patch_downgrades_to_silver():
    w = classify_witness(1, ORDERED_TRACE, reproduced=True, has_patch=False)
    assert w.tier == "silver"


def test_wrong_order_is_not_gold():
    # overflow AFTER the sink is not an enabling chain.
    w = classify_witness(1, REVERSED_TRACE, reproduced=True, has_patch=True)
    assert w.witnessed_overflow and w.witnessed_sink
    assert not w.ordered
    assert w.tier == "silver"  # overflow seen, but chain not ordered


def test_overflow_only_is_silver():
    w = classify_witness(1, OVERFLOW_ONLY, reproduced=True, has_patch=True)
    assert w.witnessed_overflow and not w.witnessed_sink
    assert w.tier == "silver"


def test_sink_only_no_overflow_is_bronze():
    # ASan-only (no UBSan overflow) is exactly the case that can't witness 190 -> not a 190 GOLD.
    w = classify_witness(1, SINK_ONLY, reproduced=True, has_patch=True)
    assert not w.witnessed_overflow
    assert w.tier == "bronze"
