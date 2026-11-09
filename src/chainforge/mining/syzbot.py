"""syzbot dashboard scraper (plan section 2).

syzbot is the top chain-with-reproducer source: kernel bugs ship a C and/or syz
reproducer, the kernel config, the fixing commit, and the cause (introducing) commit.
A single reproducer exercises a call sequence a sanitizer trace can decompose into
ordered chain links (plan section 3c), and kernel bugs are frequently multi-CWE and
cross-scope (plan section 2). ARVO's port hit ~78% reproduction on reachable reports.

syzbot has no JSON API, so this scrapes the HTML dashboard. Artifacts are downloaded
from the `/text?tag=...&x=...` endpoints:

    ReproC        C reproducer            KernelConfig  kernel .config
    ReproSyz      syz-language reproducer CrashReport   crash report
    CrashLog      console log             ReproLog      reproducer log

Individual bug pages live at /bug?extid=<id>; the fixed-bug listing is at
/<namespace>/fixed (e.g. /upstream/fixed). Parsing uses stdlib html.parser to avoid a
heavyweight HTML dependency; it targets the stable link/commit patterns, not full layout.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from html.parser import HTMLParser
from urllib.parse import parse_qs, urljoin, urlparse

import httpx

SYZBOT_BASE = "https://syzkaller.appspot.com"

# The artifact tags exposed via /text?tag=...
ARTIFACT_TAGS = frozenset(
    {"ReproC", "ReproSyz", "KernelConfig", "CrashReport", "CrashLog", "ReproLog"}
)

_EXTID_RE = re.compile(r"extid=([0-9a-f]+)")
_COMMIT_RE = re.compile(r"\b[0-9a-f]{12,40}\b")


@dataclass
class BugArtifacts:
    """Downloadable artifact refs for one syzbot bug, keyed by tag -> full URL."""

    extid: str
    texts: dict[str, str] = field(default_factory=dict)  # tag -> /text?... URL

    @property
    def has_c_reproducer(self) -> bool:
        return "ReproC" in self.texts

    @property
    def has_syz_reproducer(self) -> bool:
        return "ReproSyz" in self.texts


@dataclass
class FixedBugRef:
    """A row from the fixed-bugs listing."""

    extid: str
    title: str
    url: str


class _FixedListParser(HTMLParser):
    """Collect (extid, title, url) for every bug link in a fixed-bugs listing."""

    def __init__(self) -> None:
        super().__init__()
        self.rows: list[FixedBugRef] = []
        self._href: str | None = None
        self._extid: str | None = None
        self._depth = 0

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag != "a":
            return
        href = dict(attrs).get("href") or ""
        m = _EXTID_RE.search(href)
        if m:
            self._href = href
            self._extid = m.group(1)
            self._depth = 1

    def handle_data(self, data: str) -> None:
        if self._extid is not None and self._href is not None:
            text = data.strip()
            if text:
                self.rows.append(
                    FixedBugRef(
                        extid=self._extid,
                        title=text,
                        url=urljoin(SYZBOT_BASE, self._href),
                    )
                )
                self._href = None
                self._extid = None


class _BugPageParser(HTMLParser):
    """Collect /text?tag=...&x=... artifact links and candidate commit hashes."""

    def __init__(self) -> None:
        super().__init__()
        self.texts: dict[str, str] = {}
        self.commit_hashes: set[str] = set()

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag != "a":
            return
        href = dict(attrs).get("href") or ""
        parsed = urlparse(href)
        if parsed.path.endswith("/text") or parsed.path == "/text":
            q = parse_qs(parsed.query)
            tags = q.get("tag", [])
            if tags and tags[0] in ARTIFACT_TAGS:
                # keep the first occurrence per tag (most recent listed first)
                self.texts.setdefault(tags[0], urljoin(SYZBOT_BASE, href))
        # kernel.org git links carry commit hashes in ?id=<hash>
        if "git.kernel.org" in href or "id=" in parsed.query:
            q = parse_qs(parsed.query)
            for val in q.get("id", []):
                if _COMMIT_RE.fullmatch(val):
                    self.commit_hashes.add(val)


def parse_fixed_listing(html: str) -> list[FixedBugRef]:
    """Parse a fixed-bugs listing page into bug refs (deduplicated by extid)."""
    p = _FixedListParser()
    p.feed(html)
    seen: set[str] = set()
    out: list[FixedBugRef] = []
    for row in p.rows:
        if row.extid not in seen:
            seen.add(row.extid)
            out.append(row)
    return out


def parse_bug_page(extid: str, html: str) -> BugArtifacts:
    """Parse a bug detail page into its downloadable artifact refs."""
    p = _BugPageParser()
    p.feed(html)
    return BugArtifacts(extid=extid, texts=dict(p.texts))


class SyzbotClient:
    """Thin syzbot dashboard client. Use as a context manager to reuse the connection."""

    def __init__(
        self, base_url: str = SYZBOT_BASE, timeout: float = 30.0, min_interval: float = 0.5
    ) -> None:
        self._client = httpx.Client(
            base_url=base_url,
            timeout=timeout,
            headers={"User-Agent": "chainforge-miner/0.0 (research)"},
            follow_redirects=True,
        )
        # syzbot rate-limits bursts (429). Space requests and back off on 429.
        self._min_interval = min_interval
        self._last_request = 0.0

    def _throttle(self) -> None:
        import time

        wait = self._min_interval - (time.monotonic() - self._last_request)
        if wait > 0:
            time.sleep(wait)
        self._last_request = time.monotonic()

    def _get(self, path: str, *, params: dict | None = None, max_retries: int = 5):
        """GET with inter-request spacing and exponential backoff on HTTP 429."""
        import time

        for attempt in range(max_retries):
            self._throttle()
            resp = self._client.get(path, params=params)
            if resp.status_code == 429:
                # honor Retry-After if present, else exponential backoff.
                retry_after = resp.headers.get("retry-after")
                delay = float(retry_after) if retry_after else min(2**attempt, 30)
                time.sleep(delay)
                continue
            resp.raise_for_status()
            return resp
        resp.raise_for_status()
        return resp

    def __enter__(self) -> SyzbotClient:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def close(self) -> None:
        self._client.close()

    def fixed_bugs(self, namespace: str = "upstream") -> list[FixedBugRef]:
        """List fixed bugs for a namespace (default 'upstream' = mainline kernel)."""
        return parse_fixed_listing(self._get(f"/{namespace}/fixed").text)

    def bug_artifacts(self, extid: str) -> BugArtifacts:
        """Fetch a bug page and extract its artifact download refs."""
        return parse_bug_page(extid, self._get("/bug", params={"extid": extid}).text)

    def bug_json(self, extid: str) -> dict:
        """Fetch a bug's STRUCTURED record via the ?json=1 endpoint.

        Cleaner than scraping HTML: gives title, id, status, fix-commits [{title, repo,
        branch}], and crashes [{c-reproducer, crash-report-link, kernel-source-git,
        kernel-source-commit, ...}]. The fix-commit HASH is NOT included — resolve it from
        the title within the named repo (see infra/roar tooling).
        """
        return self._get("/bug", params={"extid": extid, "json": "1"}).json()

    def download_text(self, url: str) -> str:
        """Download a /text?tag=... artifact (reproducer, config, log) as text."""
        return self._get(url).text
