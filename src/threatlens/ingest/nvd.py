"""NVD client and CVE record parsing.

Owns: rate limiting, fetching by CVE id, and turning raw NVD JSON into Node
objects. Must not: call an LLM, import anything from retrieval/ or agent/.

NVD allows 5 requests per 30 seconds without a key, 50 with one. Exceeding
the limit produces 403 storms that look like outages — the bucket is not
optional.
"""

from threatlens.ingest.fetch import TokenBucket as TokenBucket
from threatlens.models import Node

NVD_ENDPOINT = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_DETAIL = "https://nvd.nist.gov/vuln/detail/"


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

    Expects the inner ``cve`` dict from the NVD 2.0 API response or top-level wrapper.
    """
    if "cve" in raw and isinstance(raw["cve"], dict):
        raw = raw["cve"]
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
            "references": [
                r.get("url")
                for r in raw.get("references", [])
                if isinstance(r, dict) and r.get("url")
            ],
        },
    )
