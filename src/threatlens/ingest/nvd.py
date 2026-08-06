"""NVD client and CVE record parsing.

Owns: rate limiting, fetching by CVE id, and turning raw NVD JSON into Node
objects. Must not: call an LLM, import anything from retrieval/ or agent/.

NVD allows 5 requests per 30 seconds without a key, 50 with one. Exceeding
the limit produces 403 storms that look like outages — the bucket is not
optional.
"""

from __future__ import annotations

import time
from collections.abc import Callable

from threatlens.models import Node

NVD_ENDPOINT = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_DETAIL = "https://nvd.nist.gov/vuln/detail/"


# ---------------------------------------------------------------------------
# Rate limiter
# ---------------------------------------------------------------------------


class TokenBucket:
    """Leaky-bucket rate limiter with injectable clock for testing.

    The NVD API returns 403 when the limit is exceeded and does not tell you
    how long to wait. A token bucket avoids hitting it in the first place.

    Args:
        rate:        number of tokens (requests) per window
        per_seconds: length of the window in seconds
        clock:       injectable monotonic clock — tests pass a fake
        sleep:       injectable sleep — tests record instead of blocking
    """

    def __init__(
        self,
        rate: int,
        per_seconds: float,
        clock: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        self.rate = rate
        self.per_seconds = per_seconds
        self._clock = clock
        self._sleep = sleep
        self._tokens = float(rate)
        self._last = clock()

    def acquire(self) -> None:
        """Block until a token is available, then consume one."""
        self._refill()
        if self._tokens < 1.0:
            deficit = 1.0 - self._tokens
            wait = deficit * (self.per_seconds / self.rate)
            self._sleep(wait)
            self._refill()
        self._tokens -= 1.0

    def _refill(self) -> None:
        now = self._clock()
        elapsed = now - self._last
        self._last = now
        self._tokens = min(
            float(self.rate),
            self._tokens + elapsed * (self.rate / self.per_seconds),
        )


# ---------------------------------------------------------------------------
# CVE record parsing
# ---------------------------------------------------------------------------


def _english_description(raw: dict) -> str | None:
    """Extract the English-language description, ignoring translations."""
    for d in raw.get("descriptions", []):
        if d.get("lang") == "en":
            return d.get("value")
    return None


def _cvss(raw: dict) -> tuple[float | None, str | None, str | None]:
    """Extract CVSS score with a strict fallback chain: v3.1 → v4.0 → None.

    Returns (score, version, vector_string). A missing score is None —
    never 0.0. A fabricated 0.0 reads as "no risk" in an answer someone
    may act on.
    """
    metrics = raw.get("metrics", {})
    for key, version in (("cvssMetricV31", "3.1"), ("cvssMetricV40", "4.0")):
        entries = metrics.get(key) or []
        if entries:
            data = entries[0].get("cvssData", {})
            score = data.get("baseScore")
            return (
                float(score) if score is not None else None,
                version,
                data.get("vectorString"),
            )
    return None, None, None


def parse_cve_record(raw: dict) -> Node | None:
    """Turn a single NVD CVE JSON object into a Node, or None if unusable.

    Expects the inner ``cve`` dict from the NVD 2.0 API response — the one
    that has ``id``, ``descriptions``, ``metrics``, etc.
    """
    cve_id = raw.get("id")
    if not cve_id:
        return None

    score, version, vector = _cvss(raw)

    return Node(
        id=Node.make_id("cve", cve_id),
        kind="cve",
        external_id=cve_id,
        name=cve_id,
        source_url=f"{NVD_DETAIL}{cve_id}",
        description=_english_description(raw),
        attrs={
            "cvss_score": score,
            "cvss_version": version,
            "cvss_vector": vector,
            "published": raw.get("published"),
            "last_modified": raw.get("lastModified"),
            "references": [r.get("url") for r in raw.get("references", []) if r.get("url")],
        },
    )
