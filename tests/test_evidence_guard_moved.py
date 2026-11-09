"""PR-4 amendment (2026-10-29): a re-indented or re-braced line is not a line the fix adds."""

from chainforge.evidence import _added, guard_classes, input_validation_child

MOVED_NULL = """@@ -1,4 +1,4 @@
-    if (buf == NULL)
-        return;
+        if (buf == NULL) {
+            return;
+        }
"""

MOVED_PLUS_BOUND = (
    MOVED_NULL
    + """+        if (20 * key_id > blob->len)
+            goto err;
"""
)


def test_reindented_lines_are_not_added():
    assert _added(MOVED_NULL).strip() == "}"
    assert guard_classes(MOVED_NULL) == []


def test_a_new_check_beside_a_moved_one_decides():
    assert guard_classes(MOVED_PLUS_BOUND)[0] == 20
    assert input_validation_child(MOVED_PLUS_BOUND) == 1284


def test_a_changed_line_still_counts():
    hunk = "@@ -1 +1 @@\n-    if (p == NULL)\n+    if (p == NULL || n > max)\n"
    assert 476 in guard_classes(hunk)
