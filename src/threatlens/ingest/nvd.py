"""NVD client and CVE record parsing.

Owns: rate limiting, fetching by CVE id, and turning raw NVD JSON into Node
objects. Must not: call an LLM, import anything from retrieval/ or agent/.

NVD allows 5 requests per 30 seconds without a key, 50 with one. Exceeding
the limit produces 403 storms that look like outages — the bucket is not
optional.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import TYPE_CHECKING

from threatlens.ingest.fetch import TokenBucket as TokenBucket
from threatlens.models import Node

if TYPE_CHECKING:
    from sqlalchemy.engine import Connection

log = logging.getLogger(__name__)

NVD_ENDPOINT = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_DETAIL = "https://nvd.nist.gov/vuln/detail/"


# ---------------------------------------------------------------------------
# CVE record parsing
# ---------------------------------------------------------------------------


# Names used in a node's `malformed_fields`. Fixed, so a reader can tell exactly which
# upstream field arrived corrupt.
MALFORMED_FIELD_NAMES = frozenset(
    {
        "descriptions",
        "metrics",
        "cvss_score",
        "cvss_vector",
        "references",
        "published",
        "last_modified",
    }
)


def _dict_field(raw: dict, key: str, malformed: list[str], name: str = "") -> dict:
    """`raw[key]` if it is a dict, else an empty dict.

    Absent and null are honest missing data and pass silently. A value that is present but
    the wrong type is corruption: it is dropped — a bad field must never end an ingest run —
    and its name is recorded in `malformed`, so the loss stays visible and countable rather
    than looking exactly like absence. The list and string readers below follow the same rule.
    """
    value = raw.get(key)
    if isinstance(value, dict):
        return value
    if value is not None:
        malformed.append(name or key)
    return {}


def _list_field(raw: dict, key: str, malformed: list[str], name: str = "") -> list:
    """`raw[key]` if it is a list, else an empty list. See `_dict_field`."""
    value = raw.get(key)
    if isinstance(value, list):
        return value
    if value is not None:
        malformed.append(name or key)
    return []


def _str_field(raw: dict, key: str, malformed: list[str], name: str = "") -> str | None:
    """`raw[key]` if it is a non-empty string, else None. See `_dict_field`.

    An empty string is treated as absent, not malformed: it carries no value either way.
    """
    value = raw.get(key)
    if isinstance(value, str):
        return value or None
    if value is not None:
        malformed.append(name or key)
    return None


def _english_description(raw: dict, malformed: list[str]) -> str | None:
    """Extract the English-language description, ignoring translations."""
    for d in _list_field(raw, "descriptions", malformed):
        if not isinstance(d, dict):
            malformed.append("descriptions")
            continue
        if d.get("lang") == "en":
            return _str_field(d, "value", malformed, name="descriptions")
    return None


def _score(value: object) -> float | None:
    """A CVSS base score as a float in 0–10, or None.

    Anything else — a bool, an unparseable string, a number outside the scale — is not a
    score, and inventing one would be worse than having none.
    """
    if isinstance(value, bool) or not isinstance(value, (int, float, str)):
        return None
    try:
        score = float(value)
    except ValueError:
        return None
    return score if 0.0 <= score <= 10.0 else None


def _cvss(raw: dict, malformed: list[str]) -> tuple[float | None, str | None, str | None]:
    """Extract CVSS score with a strict fallback chain: v3.1 → v4.0 → None.

    Returns (score, version, vector_string). A missing score is None —
    never 0.0. A fabricated 0.0 reads as "no risk" in an answer someone
    may act on.
    """
    metrics = _dict_field(raw, "metrics", malformed)
    for key, version in (("cvssMetricV31", "3.1"), ("cvssMetricV40", "4.0")):
        entries = _list_field(metrics, key, malformed, name="metrics")
        if not entries:
            continue
        if not isinstance(entries[0], dict):
            malformed.append("metrics")
            continue
        data = _dict_field(entries[0], "cvssData", malformed, name="metrics")
        base = data.get("baseScore")
        score = _score(base)
        if base is not None and score is None:
            malformed.append("cvss_score")
        return score, version, _str_field(data, "vectorString", malformed, name="cvss_vector")
    return None, None, None


def _references(raw: dict, malformed: list[str]) -> list[str]:
    urls: list[str] = []
    for r in _list_field(raw, "references", malformed):
        url = r.get("url") if isinstance(r, dict) else None
        if isinstance(url, str) and url:
            urls.append(url)
        else:
            malformed.append("references")
    return urls


def parse_cve_record(raw: dict) -> Node | None:
    """Turn a single NVD CVE JSON object into a Node, or None if unusable.

    Expects the inner ``cve`` dict from the NVD 2.0 API response or top-level wrapper.

    Tolerant of malformed fields, but never silently: a field that is present with the wrong
    type is dropped, named in the node's `malformed_fields`, and logged with the CVE id, so
    corrupt upstream data stays distinguishable from data that is genuinely absent. The id
    must be a non-empty string — a record whose id is `true` or `1` returns None rather than
    becoming a node called `cve:True`.
    """
    raw = raw if isinstance(raw, dict) else {}
    if isinstance(raw.get("cve"), dict):
        raw = raw["cve"]
    cve_id = raw.get("id")
    if not isinstance(cve_id, str) or not cve_id:
        return None

    malformed: list[str] = []
    score, version, vector = _cvss(raw, malformed)
    attrs: dict = {
        "cvss_score": score,
        "cvss_version": version,
        "cvss_vector": vector,
        "published": _str_field(raw, "published", malformed),
        "last_modified": _str_field(raw, "lastModified", malformed, name="last_modified"),
        "references": _references(raw, malformed),
    }
    description = _english_description(raw, malformed)

    if malformed:
        attrs["malformed_fields"] = sorted(set(malformed))
        log.warning(
            "%s: dropped malformed field(s): %s", cve_id, ", ".join(attrs["malformed_fields"])
        )

    return Node(
        id=Node.make_id("cve", cve_id),
        kind="cve",
        external_id=cve_id,
        name=cve_id,
        source_url=f"{NVD_DETAIL}{cve_id}",
        description=description,
        attrs=attrs,
    )


# ---------------------------------------------------------------------------
# KEV catalog
# ---------------------------------------------------------------------------


def load_kev_ids(kev_path: Path) -> set[str]:
    """Read a CISA KEV catalog JSON file and return the set of CVE IDs.

    The catalog format is ``{"vulnerabilities": [{"cveID": "CVE-..."}, ...]}``.
    Returns an empty set if the file does not exist — callers decide whether
    that is acceptable.
    """
    if not kev_path.exists():
        return set()
    raw = json.loads(kev_path.read_text(encoding="utf-8"))
    return {
        v.get("cveID", "").strip().upper() for v in raw.get("vulnerabilities", []) if v.get("cveID")
    }


# ---------------------------------------------------------------------------
# Ingestion
# ---------------------------------------------------------------------------


def ingest_cves(
    nvd_path: Path,
    sha256: str,
    conn: Connection,
    kev_ids: set[str] | None = None,
) -> tuple[int, int]:
    """Parse the NVD snapshot and upsert CVE nodes into the graph.

    Reads ``nvd-scoped.json`` (format: ``{"vulnerabilities": [...]}``) produced
    by ``threatlens fetch nvd``.  Each record is parsed with `parse_cve_record`,
    and CVEs appearing in the CISA KEV catalog get ``attrs["kev"] = True`` —
    a genuine triage signal worth surfacing in answers.

    Returns (node_count, kev_count).
    """
    from threatlens.graph.store import record_ingest_run, upsert_nodes

    raw = json.loads(nvd_path.read_text(encoding="utf-8"))
    vulnerabilities = raw.get("vulnerabilities", [])

    nodes: list[Node] = []
    kev_count = 0
    skipped = 0

    for entry in vulnerabilities:
        node = parse_cve_record(entry)
        if node is None:
            skipped += 1
            continue

        # Stamp KEV membership. The dataclass is frozen but the attrs dict is
        # mutable — mutating it here before the upsert is safe and avoids
        # rebuilding the entire node just to add one flag.
        if kev_ids and node.external_id in kev_ids:
            node.attrs["kev"] = True
            kev_count += 1

        nodes.append(node)

    n_nodes = upsert_nodes(conn, nodes)
    record_ingest_run(conn, "nvd", raw.get("version", "2.0"), sha256, n_nodes, 0)

    if skipped:
        log.info("skipped %d unusable CVE records", skipped)
    damaged = sum(1 for n in nodes if n.attrs.get("malformed_fields"))
    if damaged:
        # The run-level number that makes upstream corruption visible at a glance. Each
        # record's own warning, above, names the CVE and the fields it lost.
        log.warning(
            "%d of %d CVE records were ingested with malformed fields dropped", damaged, len(nodes)
        )

    return n_nodes, kev_count
