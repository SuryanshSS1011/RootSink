from chainforge.triage import (
    patch_signals_overflow,
    sanitizer_signals_overflow,
    triage_case,
)

# A realistic overflow-guard patch: adds a SIZE_MAX/n division check before malloc.
OVERFLOW_DIFF = """\
--- a/foo.c
+++ b/foo.c
@@ -10,6 +10,9 @@
     size_t n = read_count(input);
+    if (n > SIZE_MAX / sizeof(elem_t)) {
+        return ERR_OVERFLOW;
+    }
     buf = malloc(n * sizeof(elem_t));
"""

# A builtin-overflow-guard patch.
BUILTIN_DIFF = """\
+++ b/bar.c
@@
-    total = a * b;
+    if (__builtin_mul_overflow(a, b, &total))
+        return -1;
"""

# An unrelated patch (off-by-one fix, no overflow guard).
UNRELATED_DIFF = """\
+++ b/baz.c
@@
-    for (i = 0; i <= len; i++)
+    for (i = 0; i < len; i++)
"""


def test_patch_size_max_guard_detected():
    ok, matched = patch_signals_overflow(OVERFLOW_DIFF)
    assert ok
    assert matched  # some pattern matched


def test_patch_builtin_overflow_detected():
    ok, _ = patch_signals_overflow(BUILTIN_DIFF)
    assert ok


def test_patch_unrelated_not_detected():
    ok, _ = patch_signals_overflow(UNRELATED_DIFF)
    assert not ok


def test_added_lines_only():
    # An overflow guard that is REMOVED (a '-' line) should not count as adding a guard.
    removed = "+++ b/x.c\n@@\n-    if (n > SIZE_MAX / size) return -1;\n+    foo();\n"
    ok, _ = patch_signals_overflow(removed)
    assert not ok


def test_sanitizer_overflow_signal():
    assert sanitizer_signals_overflow("Integer-overflow", "ubsan")
    assert sanitizer_signals_overflow(None, "unsigned-integer-overflow")
    assert not sanitizer_signals_overflow("Heap-buffer-overflow WRITE", "asan")


def test_triage_patch_is_high_confidence():
    r = triage_case(100, diff_text=OVERFLOW_DIFF, crash_type="Heap-buffer-overflow WRITE")
    assert r.is_candidate
    assert r.patch_signal
    assert r.confidence == "high"


def test_triage_sanitizer_only_is_low_confidence():
    r = triage_case(101, diff_text=UNRELATED_DIFF, crash_type="Integer-overflow", sanitizer="ubsan")
    assert r.is_candidate
    assert not r.patch_signal
    assert r.confidence == "low"


def test_triage_no_signal():
    r = triage_case(102, diff_text=UNRELATED_DIFF, crash_type="Heap-buffer-overflow WRITE")
    assert not r.is_candidate
    assert r.confidence == "none"


def test_input_validation_bounds_check():
    from chainforge.triage import patch_signals_input_validation
    diff = "+++ b/x.c\n@@\n+    if (len > sizeof(buf))\n+        return -EINVAL;\n"
    ok, matched = patch_signals_input_validation(diff)
    assert ok and matched


def test_input_validation_kernel_user_input_guard():
    from chainforge.triage import patch_signals_input_validation
    diff = "+++ b/y.c\n@@\n+    if (copy_from_user(&n, arg, sizeof(n)))\n+        return -EFAULT;\n"
    ok, _ = patch_signals_input_validation(diff)
    assert ok


def test_input_validation_none_on_unrelated():
    from chainforge.triage import patch_signals_input_validation
    diff = "+++ b/z.c\n@@\n+    x = y + 1;\n+    foo(x);\n"
    ok, _ = patch_signals_input_validation(diff)
    assert not ok


# --- Strategy C: length-3 patch co-signal ---
from chainforge.triage import patch_signals_length3  # noqa: E402

_LEN3_DIFF = """\
--- a/parse.c
+++ b/parse.c
@@ -10,6 +10,10 @@
+    if (len > MAX_INPUT_LEN)
+        return -EINVAL;
+    if (check_mul_overflow(count, size, &total))
+        return -EOVERFLOW;
     buf = malloc(total);
+    memcpy(buf, src, total);
"""

_OVERFLOW_ONLY_DIFF = """\
+++ b/x.c
+    if (check_mul_overflow(a, b, &n))
+        return -1;
+    p = malloc(n);
"""

_INPUT_ONLY_DIFF = """\
+++ b/y.c
+    if (len > MAX)
+        return -EINVAL;
+    process(data);
"""


def test_patch_len3_requires_both_guards():
    r = patch_signals_length3(_LEN3_DIFF)
    assert r["is_len3"] is True
    assert r["sink_cwe"] == 787  # memcpy present -> write sink
    assert r["input_patterns"] and r["overflow_patterns"]


def test_patch_len3_overflow_only_is_not_chain():
    r = patch_signals_length3(_OVERFLOW_ONLY_DIFF)
    assert r["is_len3"] is False
    assert r["sink_cwe"] is None


def test_patch_len3_input_only_is_not_chain():
    assert patch_signals_length3(_INPUT_ONLY_DIFF)["is_len3"] is False


def test_patch_len3_sink_defaults_to_bounds_when_only_alloc():
    diff = """\
+    if (size > LIMIT) return -1;
+    if (check_add_overflow(a, b, &s)) return -1;
+    p = kmalloc(s, GFP_KERNEL);
"""
    r = patch_signals_length3(diff)
    assert r["is_len3"] is True
    assert r["sink_cwe"] == 119  # only an allocation -> buffer-bounds sink


# --- CWE-362 race arm patch co-signal ---
_RACE_DIFF = """\
--- a/net/packet/af_packet.c
+++ b/net/packet/af_packet.c
@@ -4200,6 +4200,8 @@ static int packet_set_ring(struct sock *sk)
+    mutex_lock(&po->pg_vec_lock);
     if (closing || atomic_read(&po->mapped) == 0) {
         do_stuff(po);
     }
+    mutex_unlock(&po->pg_vec_lock);
"""

_RCU_DIFF = """\
+    rcu_read_lock();
+    p = rcu_dereference(shared->ptr);
+    if (p) use(p);
+    rcu_read_unlock();
"""

_NO_LOCK_DIFF = """\
+    x = compute(y);
+    return x + 1;
"""


def test_patch_race_signal_mutex():
    from chainforge.triage import patch_signals_race

    ok, matched = patch_signals_race(_RACE_DIFF)
    assert ok
    assert matched


def test_patch_race_signal_rcu():
    from chainforge.triage import patch_signals_race

    ok, _ = patch_signals_race(_RCU_DIFF)
    assert ok


def test_patch_race_no_signal():
    from chainforge.triage import patch_signals_race

    ok, matched = patch_signals_race(_NO_LOCK_DIFF)
    assert not ok
    assert matched == ()


def test_patch_race_only_added_lines():
    from chainforge.triage import patch_signals_race

    # a REMOVED lock is not an added synchronization guard -> no signal
    removed = "--- a/f.c\n+++ b/f.c\n-    mutex_lock(&m);\n     do_work();\n"
    ok, _ = patch_signals_race(removed)
    assert not ok


# --- new ARVO-arm source patch-signals ---
def test_patch_array_index_signal():
    from chainforge.triage import patch_signals_array_index
    diff = "--- a/f.c\n+++ b/f.c\n+    if (idx >= ARRAY_SIZE(tbl))\n+        return -EINVAL;\n"
    assert patch_signals_array_index(diff)[0]
    assert not patch_signals_array_index("+    x = compute(y);\n")[0]


def test_patch_type_check_signal():
    from chainforge.triage import patch_signals_type_check
    diff = "+    if (obj->type != EXPECTED_TYPE)\n+        return NULL;\n"
    assert patch_signals_type_check(diff)[0]
    assert not patch_signals_type_check("+    total += n;\n")[0]


def test_patch_return_check_signal():
    from chainforge.triage import patch_signals_return_check
    diff = "+    p = lookup(key);\n+    if (p == NULL)\n+        return -ENOENT;\n"
    assert patch_signals_return_check(diff)[0]
    diff2 = "+    if (IS_ERR(handle))\n+        goto out;\n"
    assert patch_signals_return_check(diff2)[0]
    assert not patch_signals_return_check("+    y = y + 1;\n")[0]
