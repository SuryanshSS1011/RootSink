"""ARVO metadata harvester (plan sections 2, 4).

ARVO (n132/ARVO) reproduces OSS-Fuzz C/C++ vulnerabilities, each packaged as a pair of
Docker images ``n132/arvo:<localId>-vul`` and ``n132/arvo:<localId>-fix`` with an
in-container ``arvo`` command that replays the PoC and emits the sanitizer report, and
``arvo compile`` that rebuilds. Per-case metadata lives in the ARVO-Meta repo at
``archive_data/meta/<localId>.json``.

ARVO is CHAINFORGE's turnkey reproduction substrate: each record is a single
sink-centric memory bug, which we re-label as a chain link using its sanitizer trace
(plan section 2). This module reads ARVO-Meta records; actual reproduction (pulling the
images as Apptainer SIFs and running them) happens on ROAR via infra/roar/arvo_repro.sh.

Fields consumed (observed from real records, e.g. archive_data/meta/10012.json):
    localId       OSS-Fuzz issue id (int)      sanitizer   asan|ubsan|msan
    project       upstream project name        crash_type  e.g. "Null-dereference READ"
    fix           fix commit URL               fuzzer      libfuzzer|afl|...
"""

from __future__ import annotations

from dataclasses import dataclass, field

import httpx

ARVO_META_RAW = "https://raw.githubusercontent.com/n132/ARVO-Meta/main/archive_data/meta"
ARVO_IMAGE = "n132/arvo"

# Map ARVO sanitizer tags to the CWE families they most directly witness (plan section 3c).
# Advisory only: the actual chain link is confirmed from the sanitizer trace, not this map.
SANITIZER_CWE_HINT: dict[str, tuple[int, ...]] = {
    "asan": (125, 787, 416),  # OOB read/write, use-after-free
    "ubsan": (190,),  # integer overflow / undefined behavior
    "msan": (),  # uninitialized reads (not in the 8-CWE catalog)
}

# The OSS-Fuzz/ClusterFuzz `crash_type` string is a far sharper CWE signal than the
# sanitizer tag (e.g. it distinguishes an OOB READ from an OOB WRITE from a null deref).
# Substrings are matched case-insensitively against crash_type; still advisory, the
# authoritative link comes from the sanitizer trace on the PoV.
_CRASH_TYPE_CWE: tuple[tuple[str, tuple[int, ...]], ...] = (
    ("null-dereference", (476,)),
    ("use-after-free", (416,)),
    ("heap-buffer-overflow read", (125,)),
    ("heap-buffer-overflow write", (787,)),
    ("stack-buffer-overflow read", (125,)),
    ("stack-buffer-overflow write", (787,)),
    ("global-buffer-overflow read", (125,)),
    ("global-buffer-overflow write", (787,)),
    ("buffer-overflow read", (125,)),
    ("buffer-overflow write", (787,)),
    ("out-of-bounds read", (125,)),
    ("out-of-bounds write", (787,)),
    ("integer-overflow", (190,)),
    ("unsigned-integer-overflow", (190,)),
    # New ARVO-reproducible arms (sink CWEs; source inferred by dataflow/patch downstream):
    ("index-out-of-bounds", (119,)),  # -> 129->119 (improper array index)
    ("bad-cast", (119,)),  # -> 843->119 (type confusion)
    ("heap-double-free", (415,)),  # -> 362->415 (race -> double free)
    ("double-free", (415,)),
    ("segv on unknown address", (476,)),  # null-deref-class -> 252->476
    ("segv on unknown", (476,)),
)


def cwe_from_crash_type(crash_type: str | None) -> tuple[int, ...]:
    """Map an ARVO/OSS-Fuzz crash_type string to candidate CWEs (advisory).

    Longer, more specific patterns are tried first so 'heap-buffer-overflow READ' wins
    over the generic 'buffer-overflow READ'. Returns () if nothing matches.
    """
    if not crash_type:
        return ()
    text = crash_type.lower()
    for needle, cwes in _CRASH_TYPE_CWE:
        if needle in text:
            return cwes
    return ()


@dataclass
class ArvoCase:
    """The subset of an ARVO-Meta record CHAINFORGE consumes."""

    local_id: int
    project: str | None = None
    sanitizer: str | None = None
    crash_type: str | None = None
    fuzzer: str | None = None
    fix_commit_url: str | None = None
    raw: dict = field(default_factory=dict)

    @property
    def vul_image(self) -> str:
        """Docker image ref for the vulnerable revision."""
        return f"{ARVO_IMAGE}:{self.local_id}-vul"

    @property
    def fix_image(self) -> str:
        """Docker image ref for the patched revision."""
        return f"{ARVO_IMAGE}:{self.local_id}-fix"

    @property
    def cwe_hints(self) -> tuple[int, ...]:
        """Candidate sink CWEs for this case (advisory, not authoritative).

        Prefers the specific crash_type signal; falls back to the coarse sanitizer tag.
        """
        from_crash = cwe_from_crash_type(self.crash_type)
        if from_crash:
            return from_crash
        return SANITIZER_CWE_HINT.get((self.sanitizer or "").lower(), ())


def raw_diff_url(patch_url: str) -> str | None:
    """Convert an ARVO `patch_url` (a commit page) into a raw-diff URL, per host.

    ARVO's patch_url points to the real upstream commit across heterogeneous hosts. This
    maps each to its raw-diff form so the fix diff can be fetched and triaged (e.g. for an
    added integer-overflow guard). Returns None for hosts we don't have a rule for. The
    caller base64-decodes googlesource responses (`?format=TEXT`).
    """
    if not patch_url:
        return None
    u = patch_url.rstrip("/")
    if "github.com" in u and "/commit/" in u:
        return u + ".diff"
    if "gitlab.com" in u and "/commit/" in u:
        return u + ".diff"
    if "googlesource.com" in u:
        return u + "?format=TEXT"  # base64-encoded diff
    if "git.kernel.org" in u:
        # /commit/?id=<hash> -> /patch/?id=<hash>
        return u.replace("/commit/", "/patch/")
    return None


def diff_needs_base64(diff_url: str) -> bool:
    """True if the raw-diff response is base64-encoded (googlesource ?format=TEXT)."""
    return "googlesource.com" in diff_url and "format=TEXT" in diff_url


def parse_case(record: dict) -> ArvoCase:
    """Parse a raw ARVO-Meta JSON record into an ArvoCase."""
    return ArvoCase(
        local_id=int(record["localId"]),
        project=record.get("project"),
        sanitizer=record.get("sanitizer"),
        crash_type=record.get("crash_type"),
        fuzzer=record.get("fuzzer"),
        fix_commit_url=record.get("fix"),
        raw=record,
    )


class ArvoMetaClient:
    """Fetches ARVO-Meta case records. Use as a context manager to reuse the connection."""

    def __init__(self, base_url: str = ARVO_META_RAW, timeout: float = 30.0) -> None:
        self._base = base_url.rstrip("/")
        self._client = httpx.Client(timeout=timeout, follow_redirects=True)

    def __enter__(self) -> ArvoMetaClient:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def close(self) -> None:
        self._client.close()

    def get_case(self, local_id: int) -> ArvoCase:
        """Fetch and parse one ARVO case by its OSS-Fuzz localId."""
        resp = self._client.get(f"{self._base}/{local_id}.json")
        resp.raise_for_status()
        return parse_case(resp.json())
