from chainforge.mining.syzbot import (
    SyzbotClient,
    parse_bug_page,
    parse_fixed_listing,
)

FIXED_LISTING_HTML = """
<table>
  <tr>
    <td><a href="/bug?extid=6d3e28b33490b3085412">KASAN: slab-out-of-bounds in foo</a></td>
    <td><a href="/bug?extid=aaaa1111bbbb2222cccc">WARNING in bar</a></td>
  </tr>
  <tr>
    <td><a href="/bug?extid=6d3e28b33490b3085412">duplicate link same extid</a></td>
  </tr>
</table>
"""

BUG_PAGE_HTML = """
<div>
  <a href="/text?tag=ReproC&x=1316587a980000">C repro</a>
  <a href="/text?tag=ReproSyz&x=1653cfba980000">syz repro</a>
  <a href="/text?tag=KernelConfig&x=c79815c08cc14227">.config</a>
  <a href="/text?tag=CrashReport&x=dead0000beef1111">report</a>
  <a href="https://git.kernel.org/linus/?id=267b801fda10b70eca4001a819fcac07f023df6b">fix</a>
  <a href="/text?tag=SomethingElse&x=999">ignored</a>
</div>
"""


def test_parse_fixed_listing_dedupes():
    rows = parse_fixed_listing(FIXED_LISTING_HTML)
    extids = [r.extid for r in rows]
    assert extids == ["6d3e28b33490b3085412", "aaaa1111bbbb2222cccc"]
    assert rows[0].title == "KASAN: slab-out-of-bounds in foo"
    assert rows[0].url.endswith("/bug?extid=6d3e28b33490b3085412")


def test_parse_bug_page_artifacts():
    art = parse_bug_page("6d3e28b33490b3085412", BUG_PAGE_HTML)
    assert art.has_c_reproducer
    assert art.has_syz_reproducer
    assert "KernelConfig" in art.texts
    assert "CrashReport" in art.texts
    assert "SomethingElse" not in art.texts  # not a known artifact tag
    assert art.texts["ReproC"].endswith("/text?tag=ReproC&x=1316587a980000")


def test_parse_bug_page_no_repro():
    art = parse_bug_page("x", "<div>no artifacts here</div>")
    assert not art.has_c_reproducer
    assert not art.has_syz_reproducer
    assert art.texts == {}


def test_fixed_bugs_client(httpx_mock):
    httpx_mock.add_response(
        url="https://syzkaller.appspot.com/upstream/fixed",
        text=FIXED_LISTING_HTML,
    )
    with SyzbotClient() as client:
        rows = client.fixed_bugs()
    assert len(rows) == 2


def test_bug_artifacts_client(httpx_mock):
    httpx_mock.add_response(
        url="https://syzkaller.appspot.com/bug?extid=6d3e28b33490b3085412",
        text=BUG_PAGE_HTML,
    )
    with SyzbotClient() as client:
        art = client.bug_artifacts("6d3e28b33490b3085412")
    assert art.has_c_reproducer


def test_bug_json(httpx_mock):
    httpx_mock.add_response(
        url="https://syzkaller.appspot.com/bug?extid=abc&json=1",
        json={
            "title": "KASAN: slab-out-of-bounds Write in foo",
            "id": "deadbeef",
            "fix-commits": [
                {"title": "fix foo", "repo": "git://...torvalds...", "branch": "master"}
            ],
            "crashes": [{"c-reproducer": "/text?tag=ReproC&x=1", "crash-report-link": "/text?x=2"}],
        },
    )
    with SyzbotClient() as client:
        d = client.bug_json("abc")
    assert d["fix-commits"][0]["title"] == "fix foo"
    assert d["crashes"][0]["c-reproducer"].startswith("/text")
