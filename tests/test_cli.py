import json

from chainforge.cli import main

_DEBIAN_LIST = "\n".join(
    [
        "CVE-2026-0001 (kernel thing ...)",
        "\t- linux 7.0.12-1",
        "\t[trixie] - linux 6.12.94-1",
        "\t[bookworm] - linux <not-affected> (Vulnerable code not present)",
        "CVE-2026-9999 (not for us ...)",
        "\tNOT-FOR-US: something",
    ]
)


def test_redhat_subcommand(capsys):
    rc = main(["redhat", "CVE-2023-0002", "CWE-20->(CWE-125|CWE-787)"])
    assert rc == 0
    out = capsys.readouterr().out.strip().splitlines()
    chains = {json.loads(line)["chain_string"] for line in out}
    assert chains == {"CWE-20->CWE-125", "CWE-20->CWE-787"}


def test_redhat_no_admissible_chain(capsys):
    rc = main(["redhat", "CVE-2023-0003", "CWE-805->CWE-125"])
    assert rc == 0
    captured = capsys.readouterr()
    assert captured.out.strip() == ""
    assert "no admissible chain" in captured.err


def test_debian_subcommand(tmp_path, capsys):
    list_file = tmp_path / "list"
    list_file.write_text(_DEBIAN_LIST, encoding="utf-8")
    rc = main(["debian", str(list_file)])
    assert rc == 0
    out = capsys.readouterr().out.strip().splitlines()
    # only the CVE with a fixed version is emitted; NOT-FOR-US entry is skipped
    assert len(out) == 1
    rec = json.loads(out[0])
    assert rec["cve"] == "CVE-2026-0001"
    versions = {f["version"] for f in rec["fixed"]}
    assert versions == {"7.0.12-1", "6.12.94-1"}  # not the <not-affected> line
