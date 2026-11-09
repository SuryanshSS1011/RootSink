from chainforge.mining.debian import parse_cve_list

_C1 = "8685930f5e2e448563ef31d8871553308b954785"
_C2 = "a237fa62341bf882c7edc4e5e8cc492cec851d0b"
_URL = "https://github.com/proftpd/proftpd/commit/"

# Mirrors the real data/CVE/list grammar observed from the live tracker.
SAMPLE = "\n".join(
    [
        "CVE-2026-53994 (ProFTPD mod_sftp contains a heap-based buffer overflow reachable ...)",
        "\t- proftpd-dfsg 1.3.9b~dfsg-1",
        "\tNOTE: https://github.com/proftpd/proftpd/issues/2115",
        f"\tNOTE: Fixed by: {_URL}{_C1} (v1.3.9b)",
        f"\tNOTE: Fixed by: {_URL}{_C2} (v1.3.9b)",
        "CVE-2026-0001 (kernel thing ...)",
        "\t- linux 7.0.12-1",
        "\t[trixie] - linux 6.12.94-1",
        "\t[bookworm] - linux <not-affected> (Vulnerable code not present)",
        "CVE-2026-16229 (A flaw has been found ...)",
        "\tNOT-FOR-US: itsourcecode System",
    ]
)


def _parse():
    return list(parse_cve_list(SAMPLE.splitlines()))


def test_parses_all_cves():
    entries = _parse()
    assert [e.cve for e in entries] == ["CVE-2026-53994", "CVE-2026-0001", "CVE-2026-16229"]


def test_description_captured():
    e = _parse()[0]
    assert e.description.startswith("ProFTPD mod_sftp contains")


def test_fixed_version_and_release():
    e = _parse()[1]  # CVE-2026-0001
    unstable = [p for p in e.packages if p.release is None]
    assert len(unstable) == 1
    assert unstable[0].package == "linux"
    assert unstable[0].version == "7.0.12-1"
    assert unstable[0].fixed

    trixie = [p for p in e.packages if p.release == "trixie"][0]
    assert trixie.version == "6.12.94-1"
    assert trixie.fixed


def test_not_affected_is_not_fixed():
    e = _parse()[1]
    bookworm = [p for p in e.packages if p.release == "bookworm"][0]
    assert bookworm.version == "<not-affected>"
    assert not bookworm.fixed
    assert bookworm.is_status_placeholder


def test_fixed_by_commits_harvested():
    e = _parse()[0]  # proftpd
    assert e.fix_commits == [_C1, _C2]


def test_not_for_us_entry_has_no_packages():
    e = _parse()[2]
    assert e.packages == []
    assert e.fix_commits == []


def test_source_packages_property():
    e = _parse()[1]
    assert e.source_packages == {"linux"}
