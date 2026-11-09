from chainforge.mining.arvo import ArvoMetaClient, cwe_from_crash_type, parse_case

# Trimmed real record shape (archive_data/meta/10012.json).
SAMPLE = {
    "localId": 10012,
    "project": "curl",
    "fix": "https://github.com/curl/curl/commit/86b1e94ae72bc0e49745ed33d4b923ac8e6b8366",
    "verify": "0",
    "fuzzer": "libfuzzer",
    "sanitizer": "ubsan",
    "crash_type": "Null-dereference READ",
    "report": {"comments": []},
}


def test_parse_case_fields():
    c = parse_case(SAMPLE)
    assert c.local_id == 10012
    assert c.project == "curl"
    assert c.sanitizer == "ubsan"
    assert c.crash_type == "Null-dereference READ"
    assert c.fuzzer == "libfuzzer"
    assert c.fix_commit_url.endswith("86b1e94ae72bc0e49745ed33d4b923ac8e6b8366")


def test_image_refs():
    c = parse_case(SAMPLE)
    assert c.vul_image == "n132/arvo:10012-vul"
    assert c.fix_image == "n132/arvo:10012-fix"


def test_cwe_from_crash_type_specific_beats_generic():
    # heap-buffer-overflow WRITE -> 787 (not the generic buffer-overflow branch)
    assert cwe_from_crash_type("Heap-buffer-overflow WRITE") == (787,)
    assert cwe_from_crash_type("Heap-buffer-overflow READ") == (125,)
    assert cwe_from_crash_type("Use-after-free READ") == (416,)
    assert cwe_from_crash_type("Null-dereference READ") == (476,)
    assert cwe_from_crash_type("Integer-overflow") == (190,)
    assert cwe_from_crash_type("") == ()
    assert cwe_from_crash_type(None) == ()


def test_cwe_hints_prefers_crash_type():
    # 10012 is ubsan + "Null-dereference READ": crash_type (476) must win over sanitizer (190)
    assert parse_case(SAMPLE).cwe_hints == (476,)


def test_cwe_hints_falls_back_to_sanitizer():
    # No/unknown crash_type -> use the sanitizer tag.
    case = parse_case({**SAMPLE, "crash_type": "", "sanitizer": "asan"})
    assert case.cwe_hints == (125, 787, 416)
    case = parse_case({**SAMPLE, "crash_type": "Timeout", "sanitizer": "msan"})
    assert case.cwe_hints == ()


def test_get_case_client(httpx_mock):
    httpx_mock.add_response(
        url="https://raw.githubusercontent.com/n132/ARVO-Meta/main/archive_data/meta/10012.json",
        json=SAMPLE,
    )
    with ArvoMetaClient() as client:
        c = client.get_case(10012)
    assert c.project == "curl"
    assert c.vul_image == "n132/arvo:10012-vul"


def test_raw_diff_url_github():
    from chainforge.mining.arvo import raw_diff_url
    assert raw_diff_url("https://github.com/curl/curl/commit/abc123") == (
        "https://github.com/curl/curl/commit/abc123.diff"
    )


def test_raw_diff_url_googlesource():
    from chainforge.mining.arvo import diff_needs_base64, raw_diff_url
    u = raw_diff_url("https://skia.googlesource.com/skia.git/+/abc123%5E%21/")
    assert u.endswith("?format=TEXT")
    assert diff_needs_base64(u)


def test_raw_diff_url_kernel():
    from chainforge.mining.arvo import raw_diff_url
    u = raw_diff_url("https://git.kernel.org/pub/scm/linux/kernel/commit/?id=deadbeef")
    assert "/patch/" in u


def test_raw_diff_url_unknown_host():
    from chainforge.mining.arvo import raw_diff_url
    assert raw_diff_url("https://foss.heptapod.net/x/y") is None
    assert raw_diff_url("") is None
