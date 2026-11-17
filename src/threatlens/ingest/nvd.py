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


def _as_dict(value: object) -> dict:
    """`value` if it is a dict, else an empty one.

    NVD records are large, nested, and have changed shape before. A field holding null, a
    string, or a list where a dict belongs must cost that field, not the whole ingest run.
    """
    return value if isinstance(value, dict) else {}


def _as_list(value: object) -> list:
    """`value` if it is a list, else an empty one. See `_as_dict`."""
    return value if isinstance(value, list) else []


def _as_str(value: object) -> str | None:
    """`value` if it is a non-empty string, else None."""
    return value if isinstance(value, str) and value else None


def _english_description(raw: dict) -> str | None:
    """Extract the English-language description, ignoring translations."""
    for d in _as_list(raw.get("descriptions")):
        d = _as_dict(d)
        if d.get("lang") == "en":
            return _as_str(d.get("value"))
    return None


def _score(value: object) -> float | None:
    """A CVSS base score as a float in 0–10, or None.

    Anything else — a bool, an unparseable string, a number outside the scale — is not a
    score, and inventing one would be worse than having none.
    """
    if isinstance(value, bool):
        return None
    try:
        score = float(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return None
    return score if 0.0 <= score <= 10.0 else None


def _cvss(raw: dict) -> tuple[float | None, str | None, str | None]:
    """Extract CVSS score with a strict fallback chain: v3.1 → v4.0 → None.

    Returns (score, version, vector_string). A missing score is None —
    never 0.0. A fabricated 0.0 reads as "no risk" in an answer someone
    may act on.
    """
    metrics = _as_dict(raw.get("metrics"))
    for key, version in (("cvssMetricV31", "3.1"), ("cvssMetricV40", "4.0")):
        entries = _as_list(metrics.get(key))
        if entries:
            data = _as_dict(_as_dict(entries[0]).get("cvssData"))
            return _score(data.get("baseScore")), version, _as_str(data.get("vectorString"))
    return None, None, None


def parse_cve_record(raw: dict) -> Node | None:
    """Turn a single NVD CVE JSON object into a Node, or None if unusable.

    Expects the inner ``cve`` dict from the NVD 2.0 API response or top-level wrapper.

    Tolerant of malformed fields: a wrong-typed field is dropped, never raised on, so one
    bad record cannot end an ingest run. The id must be a non-empty string — a record whose
    id is `true` or `1` returns None rather than becoming a node called `cve:True`.
    """
    raw = _as_dict(raw)
    if isinstance(raw.get("cve"), dict):
        raw = raw["cve"]
    cve_id = _as_str(raw.get("id"))
    if cve_id is None:
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
            "published": _as_str(raw.get("published")),
            "last_modified": _as_str(raw.get("lastModified")),
            "references": [
                url
                for r in _as_list(raw.get("references"))
                if (url := _as_str(_as_dict(r).get("url")))
            ],
        },
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

    return n_nodes, kev_count
