"""Patch evidence must be able to carry the claim its tier makes, not merely exist.

Each case here shipped in the release before the check existed: a `git://` reference counted
as a materialised patch, a `Makefile.am` diff backed a use-after-free guard claim, a diff cut
mid-hunk at 200,000 bytes was applied as if complete, and nine causal proofs rested on a fuzz
harness clamp that silenced the crash without fixing anything.
"""

from chainforge.evidence import (
    causal_proof_defect,
    clip_patch,
    guard_evidence_defect,
    is_non_guard_path,
    patch_is_content,
)

REAL = "diff --git a/src/x.c b/src/x.c\n@@ -1,2 +1,3 @@\n+    if (n > max) return -1;\n"


def test_patch_is_content_rejects_pointers():
    assert patch_is_content(REAL)
    assert not patch_is_content("https://github.com/o/r/commit/abc")
    assert not patch_is_content("git://thekelleys.org.uk/dnsmasq.git -> " + "a" * 40)
    assert not patch_is_content("fix:" + "b" * 40)
    assert not patch_is_content("diff --git a/x.c b/x.c\n")  # header, no hunk
    assert not patch_is_content("")
    assert not patch_is_content(None)


def test_guard_evidence_defect_accepts_a_real_source_guard():
    assert guard_evidence_defect(REAL) is None


def test_guard_evidence_defect_rejects_non_source_fixes():
    build = "diff --git a/Makefile.am b/Makefile.am\n@@ -1 +1,2 @@\n+EXTRA =\n"
    harness = "diff --git a/fuzz/Fuzz.h b/fuzz/Fuzz.h\n@@ -1 +1,2 @@\n+  size = 8;\n"
    docs = "diff --git a/docs/a.md b/docs/a.md\n@@ -1 +1,2 @@\n+text\n"
    for d in (build, harness, docs):
        assert guard_evidence_defect(d) == "touches no non-test source file"


def test_guard_evidence_defect_rejects_truncated_and_wrong_commit():
    assert guard_evidence_defect(REAL.rstrip("\n") + "x" * 2000) == "truncated mid-line"
    got, want = "a" * 40, "b" * 40
    why = guard_evidence_defect(f"From {got}\n" + REAL, want)
    assert why is not None and why.startswith("sha mismatch")
    # the same diff at the commit the record names is fine
    assert guard_evidence_defect(f"From {got}\n" + REAL, got) is None


def test_clip_patch_never_ends_mid_hunk():
    two = (
        "diff --git a/src/x.c b/src/x.c\n"
        "@@ -1,2 +1,3 @@\n+    guard();\n"
        "@@ -9,2 +9,3 @@\n+    more();\n"
    )
    assert clip_patch(two, len(two)) == two  # under the limit: untouched
    # room for the headers plus the first hunk, but not the second: keep hunk one whole
    clipped = clip_patch(two, len(two) - 10)
    assert clipped.endswith("+    guard();\n")
    assert clipped.count("@@ -") == 1
    assert patch_is_content(clipped)  # what survives is still a valid patch
    # too small for even one hunk: nothing valid to store, and it must not look like a patch
    assert clip_patch(two, 40) == ""


def test_causal_proof_defect_flags_a_harness_guard():
    harness = {"causal_proof": {"file": "src/bin/fuzz/template_fuzzer.cc", "added_lines": 1}}
    source = {"causal_proof": {"file": "libvips/foreign/jpeg2vips.c", "added_lines": 3}}
    assert causal_proof_defect(harness) == "guard hunk is in a fuzz harness or test file"
    assert causal_proof_defect(source) is None
    assert causal_proof_defect({}) is None  # no proof to judge
    assert causal_proof_defect(None) is None


def test_non_guard_path_covers_every_harness_layout_seen_in_the_release():
    for harness in (
        "harnesses/base.c",  # oniguruma: three proofs passed both checks on this
        "src/fuzzer/mode_padding.cpp",  # botan
        "unit_test/fuzzing/test_responder/chunk_send_ack.c",  # libspdm
        "fuzz/fuzz_config_read.c",
        "src/bin/fuzz/template_fuzzer.cc",  # lwan
        "tests/fuzz_regex.cc",
        "png_read_fuzzer.cc",
    ):
        assert is_non_guard_path(harness), harness
    for source in ("src/codec/SkSwizzler.cpp", "regparse.c", "lib/attest/latest.c"):
        assert not is_non_guard_path(source), source


def test_clip_patch_drops_a_file_header_left_without_hunks():
    two_files = (
        "diff --git a/a.c b/a.c\n--- a/a.c\n+++ b/a.c\n@@ -1 +1 @@\n-x\n+y\n"
        "diff --git a/b.c b/b.c\n--- a/b.c\n+++ b/b.c\n@@ -1 +1 @@\n-" + "z" * 500 + "\n+w\n"
    )
    clipped = clip_patch(two_files, 200)
    assert clipped.endswith("+y\n")
    assert "b/b.c" not in clipped


def _hunk(*added: str) -> str:
    return "@@ -1,2 +1,4 @@\n ctx;\n" + "".join(f"+{a}\n" for a in added)


def test_guard_class_reads_what_the_added_lines_check():
    from chainforge.cwe import is_admissible_edge as adm
    from chainforge.evidence import source_for_guard as src

    overflow = _hunk("if (n > SIZE_MAX / sz) return -1;")
    nullchk = _hunk("if (p == NULL) return;")
    bounds = _hunk("if (len > sizeof(buf)) goto err;")
    index = _hunk("if (idx >= table->count) return -1;")
    refcnt = _hunk("kref_get(&obj->ref);")
    clear = "@@ -1 +1,2 @@\n free(ctx->buf);\n+ctx->buf = NULL;\n"
    init = _hunk("memset(&hdr, 0, sizeof(hdr));")
    assert src(overflow, 787, adm) == 190
    assert src(nullchk, 787, adm) == 476
    assert src(nullchk, 125, adm) is None  # 476->125 is not admissible: no CWE credited
    assert src(bounds, 125, adm) == 20
    assert src(index, 119, adm) == 129
    assert src(index, 787, adm) == 20  # an index check toward 787 is input validation
    assert src(refcnt, 787, adm) == 416
    assert src(clear, 125, adm) == 416
    assert src(init, 457, adm) == 456


def test_guard_class_ignores_comments_and_unrelated_changes():
    from chainforge.cwe import is_admissible_edge as adm
    from chainforge.evidence import source_for_guard as src

    assert src(_hunk("// avoid integer overflow here", "x = compute(y);"), 787, adm) is None
    assert src(_hunk("n = get_bits(gb, 4);"), 787, adm) is None  # not a lifetime fix
    assert src(_hunk("ctx->buf = NULL;"), 787, adm) is None  # cleared, but nothing freed


def test_input_validation_covers_the_forms_pr4_names():
    from chainforge.cwe import is_admissible_edge as adm
    from chainforge.evidence import source_for_guard as src

    for guard in (
        "for (i = 0; i + 4 <= n; i += 4) {",  # a loop bound
        "VerifyOrExit(len <= sizeof(out), err = -1);",  # a check macro
        "    (hdr_len >= min_len) &&",  # a continued condition
        "continue;",  # skip a bad element
        "return -1;",  # early error exit
        "n = MIN(n, avail);",  # a clamp
    ):
        assert src(_hunk(guard), 787, adm) == 20, guard
    # not comparisons: member access, shifts, a template argument
    for not_guard in ("x = p->next;", "v = a << 3 | b >> 2;", "k = static_cast<uint32_t>(m);"):
        assert src(_hunk(not_guard), 787, adm) is None, not_guard


def test_guard_site_is_the_vulnerable_line_the_guard_goes_before():
    from chainforge.evidence import guard_site

    hunk = (
        "@@ -120,6 +120,8 @@ static int read_hdr(ctx_t *c, size_t n)\n"
        "     uint8_t b[16];\n"
        "     size_t k = n;\n"
        "+    if (k > sizeof(b))\n"
        "+        return -1;\n"
        "     memcpy(b, c->p, k);\n"
    )
    site = guard_site(hunk, "src/hdr.c")
    assert site["line"] == 122  # lines 120-121 are context; the guard goes before line 122
    assert site["function"] == "read_hdr"
    assert site["file"] == "src/hdr.c"


def test_bare_function_sees_through_an_anonymous_namespace():
    from chainforge.evidence import bare_function

    assert bare_function("(anonymous namespace)::LoadTGA(QDataStream&, int)") == "LoadTGA"
    assert bare_function("ot::Cli::Interpreter::ProcessService(int,") == "ProcessService"


def test_guard_site_names_no_function_when_git_reports_a_statement():
    from chainforge.evidence import guard_site

    hunk = "@@ -826,3 +826,4 @@ if (c > 127)\n   x = 1;\n+  if (y) return;\n   z = 2;\n"
    assert guard_site(hunk, "src/pcre2_study.c")["function"] is None


def test_chain_kind_counts_a_use_after_free_tail_once():
    from chainforge.evidence import chain_kind

    assert chain_kind([416, 787]) == "stage-decomposition"
    assert chain_kind([416, 125]) == "stage-decomposition"
    assert chain_kind([362, 416, 787]) == "multi-weakness"  # a race enabling a UAF
    assert chain_kind([20, 125]) == "multi-weakness"
    assert chain_kind([456, 457]) == "multi-weakness"  # PR-5: considered, kept as a chain
    assert chain_kind([20, 190, 787]) == "multi-weakness"
    # One rule for all of them: a pair whose two CWEs classify the same faulting operation is
    # one defect; a pair whose first CWE is an earlier, different operation is two weaknesses.
    assert chain_kind([843, 119]) == "stage-decomposition"  # the typed access IS the OOB access
    assert chain_kind([252, 476]) == "multi-weakness"  # unchecked return, then the dereference
    assert chain_kind([129, 119]) == "multi-weakness"  # missing index check, then the access


def test_cwe_basis_separates_the_tested_site_from_the_rule_that_named_it():
    from chainforge.evidence import cwe_basis

    proven = {"role": "source", "evidence": {"causal_proof": {"rule": "PR-4"}}}
    msan = {"role": "source", "evidence": {"patch_hunk_ref": "MSan origin block: created here"}}
    sink = {"role": "sink", "evidence": {"sanitizer_report_ref": "vul.txt"}}
    rule = {"role": "source", "evidence": {"patch_hunk_ref": "CWE-20 source NOT attested"}}
    assert cwe_basis(proven, "arvo") == "guard-class"
    assert cwe_basis(msan, "arvo-msan") == "msan-origin"
    assert cwe_basis(sink, "arvo") == "sanitizer-class"
    assert cwe_basis(rule, "arvo") == "catalogue-default"


def test_locality_compares_normalised_paths_and_bare_functions():
    from chainforge.evidence import locality

    def rec(a, b):
        return {"chain": [{"evidence": {"location": a}}, {"evidence": {"location": b}}]}

    skia_sink = {
        "file": "out/Fuzz/../../src/codec/SkSwizzler.cpp",
        "line": 237,
        "function": "swizzle_index_to_n32(void*, unsigned char const*, int)",
    }
    skia_src = {"file": "src/codec/SkSwizzler.cpp", "line": 230, "function": "swizzle_index_to_n32"}
    assert locality(rec(skia_src, skia_sink)) == "in-function"
    other = {**skia_src, "function": "SkSwizzler::swizzle"}
    assert locality(rec(other, skia_sink)) == "cross-function"
    assert (
        locality(rec({**skia_src, "function": None}, skia_sink)) == "same-file"
    )  # unknown != different
    assert locality(rec({"file": "src/a.c", "line": 1}, skia_sink)) == "cross-file"
    assert locality(rec({}, skia_sink)) is None


def test_site_kind_free_site_spellings():
    from chainforge.evidence import site_kind

    for stage in ("freed (ARVO archived report)", "free (ASan 'freed by' stack)"):
        link = {
            "cwe_id": 416,
            "role": "source",
            "evidence": {"location": {"file": "a.c", "line": 1, "stage": stage}},
        }
        assert site_kind(link) == "origin-site"
    kasan_alloc = {
        "cwe_id": 20,
        "role": "source",
        "evidence": {"location": {"file": "mm/slab.h", "line": 1, "stage": "allocated"}},
    }
    assert site_kind(kasan_alloc) == "annotated-site"


def test_harness_site_with_vendored_exception():
    from chainforge.evidence import harness_site

    assert harness_site("tests/fuzz/custom_memory_manager.c")
    assert harness_site("FuzzerTracePC.cpp")
    assert harness_site("oss-fuzz/projects/wolf-ssl-ssh/fuzzers/include/fuzzers/shared.h")
    assert not harness_site(
        "oss-fuzz/projects/wolf-ssl-ssh/fuzzers/wolfssl/wolfssl/wolfcrypt/src/tfm.c"
    )
    assert not harness_site("/src/krb5/src/tests/fuzzing/./../../kdc/replay.c")
    assert not harness_site("lib/parser.c")


def test_null_check_of_a_call_result_is_cwe_252_only_toward_a_null_dereference():
    from chainforge.cwe import is_admissible_edge
    from chainforge.evidence import source_for_guard

    called = (
        "@@ -1,3 +1,5 @@ f\n p = lookup(t, k);\n+if (p == NULL)\n+    return -1;\n use(p->f);\n"
    )
    param = "@@ -1,2 +1,4 @@ f\n+if (!p)\n+    return -1;\n use(p->f);\n"
    assert source_for_guard(called, 476, is_admissible_edge) == 252
    assert source_for_guard(param, 476, is_admissible_edge) is None
    # Unchanged toward any other sink: a NULL check credits nothing there.
    assert source_for_guard(called, 125, is_admissible_edge) is None


def test_site_kind_msan_origin_named_by_guard_rule():
    from chainforge.evidence import site_kind

    # An intervention named CWE-456 (guard-class basis) but the site is still MSan's origin.
    link = {
        "cwe_id": 456,
        "role": "source",
        "evidence": {
            "causal_proof": {"hunk": "hunk00.patch"},
            "sanitizer_report_ref": "data/evidence/arvo/1/vul.sanitizer.txt",
            "location": {"file": "a.c", "line": 3, "function": "f", "stage": None},
        },
    }
    assert site_kind(link, "arvo") == "origin-site"


def test_input_validation_child_pr17():
    from chainforge.evidence import input_validation_child as child

    assert child("+  if (offset + n > buf_size) return -1;") == 1285
    assert child("+  if (bufLen < 4) goto fail;") == 1284
    assert child("+  if (!ok) return;") is None
    assert child("+  x = ps->len;") is None  # `->` is not a comparison
    assert child("+  // check the index\n+  foo(x);") is None  # comments do not count


def test_mitre_inherited_edges_pr17():
    from chainforge.mitre_chains import classify_edge

    assert classify_edge(1284, 125).kind == "mitre-inherited"
    assert classify_edge(1285, 787).kind == "mitre-inherited"
    # CWE-416 is-a CWE-825, and CWE-825 CanPrecede CWE-125 in CWE 4.20.
    assert classify_edge(416, 125).kind == "mitre-inherited"
    assert classify_edge(20, 125).kind == "mitre-transitive"
    assert classify_edge(129, 119).kind == "mitre-direct"
