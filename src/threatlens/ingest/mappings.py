"""CVE → ATT&CK mappings parser.

This file turns the Mappings Explorer CSV into ENABLES edges — the bridge
between the CVE world and the ATT&CK world. The same dataset is also the
labelled ground truth for evaluation: 20% is held out and frozen before any
retrieval code exists.

Primary impact carries full weight (1.0); secondary impact is a weaker
signal (0.5). A row with no CVE ID is logged and counted as skipped,
not silently swallowed — the distinction between "ignored" and "lost"
matters for data quality.

Must not: import from retrieval/, agent/, or llm/.
"""

from __future__ import annotations

import csv
import logging
from pathlib import Path
from typing import TYPE_CHECKING

from threatlens.models import Edge, Node

if TYPE_CHECKING:
    from sqlalchemy.engine import Connection

log = logging.getLogger(__name__)

SOURCE = "mappings-explorer"


def parse_mappings_csv(path: Path) -> tuple[list[Edge], int]:
    """Parse a CVE→ATT&CK mappings CSV into ENABLES edges.

    Returns:
        (edges, skipped_count) — skipped rows are counted so the caller can
        decide if the count is acceptable. The parser emits edges even for
        techniques that may not exist in the graph; the *loader* drops
        unresolvable ones later, because the parser has no access to the
        graph and should not need it.
    """
    edges: list[Edge] = []
    skipped = 0

    with open(path, newline="", encoding="utf-8") as fh:
        for row in csv.DictReader(fh):
            cve_id = (row.get("CVE ID") or "").strip()
            if not cve_id:
                skipped += 1
                log.warning("mappings row with no CVE ID: %r", row)
                continue

            src = Node.make_id("cve", cve_id)

            for column, weight in (("Primary Impact", 1.0), ("Secondary Impact", 0.5)):
                technique = (row.get(column) or "").strip()
                if not technique:
                    continue

                edges.append(
                    Edge(
                        src=src,
                        dst=Node.make_id("technique", technique),
                        kind="ENABLES",
                        source=SOURCE,
                        weight=weight,
                        attrs={"impact": column.split()[0].lower()},
                    )
                )

    return edges, skipped


# ---------------------------------------------------------------------------
# Edge filtering
# ---------------------------------------------------------------------------


def partition_edges(
    edges: list[Edge],
    existing_node_ids: set[str],
) -> tuple[list[Edge], list[Edge], list[Edge]]:
    """Split edges by whether their endpoints exist in the graph.

    Returns (resolvable, dropped_technique, dropped_source):
      - resolvable: both src and dst exist — safe to upsert
      - dropped_technique: dst (technique) is absent — the mapping points at a
        revoked technique or one from the Mobile/ICS domain
      - dropped_source: src (CVE) is absent — the CVE was not in the scoped
        NVD pull, or was not fetched
    """
    resolvable: list[Edge] = []
    dropped_technique: list[Edge] = []
    dropped_source: list[Edge] = []

    for edge in edges:
        if edge.dst not in existing_node_ids:
            dropped_technique.append(edge)
        elif edge.src not in existing_node_ids:
            dropped_source.append(edge)
        else:
            resolvable.append(edge)

    return resolvable, dropped_technique, dropped_source


# ---------------------------------------------------------------------------
# Ingestion
# ---------------------------------------------------------------------------


def ingest_mappings(
    mappings_path: Path,
    sha256: str,
    conn: Connection,
) -> tuple[int, int]:
    """Parse mappings CSV, filter against existing nodes, upsert ENABLES edges.

    The drop count is the one number that matters: if it is large, the ATT&CK
    snapshot and the mappings snapshot are out of step, and the graph is quietly
    missing a chunk of its bridge.

    Returns (edge_count, dropped_count).
    """
    from threatlens.graph.store import get_node, record_ingest_run, upsert_edges

    edges, skipped_rows = parse_mappings_csv(mappings_path)

    if skipped_rows:
        log.info("skipped %d CSV rows with no CVE ID", skipped_rows)

    # Collect all referenced node IDs and check which exist in the graph.
    # Uses get_node() per unique ID — ~200–300 unique techniques + CVEs
    # at ~1ms each is well under a second.
    unique_ids = {e.dst for e in edges} | {e.src for e in edges}
    existing_ids: set[str] = set()
    for node_id in unique_ids:
        if get_node(conn, node_id) is not None:
            existing_ids.add(node_id)

    resolvable, dropped_technique, dropped_source = partition_edges(edges, existing_ids)

    # Report dropped technique edges — this is the critical diagnostic
    if dropped_technique:
        absent = sorted({e.dst for e in dropped_technique})
        for tech_id in absent:
            count = sum(1 for e in dropped_technique if e.dst == tech_id)
            log.warning("dropped %d edges to absent technique %s", count, tech_id)

    if dropped_source:
        absent_cves = sorted({e.src for e in dropped_source})
        log.warning(
            "dropped %d edges from %d absent CVE nodes — run 'threatlens ingest cves' first",
            len(dropped_source),
            len(absent_cves),
        )

    total_dropped = len(dropped_technique) + len(dropped_source)
    n_edges = upsert_edges(conn, resolvable)
    record_ingest_run(conn, SOURCE, "1.0", sha256, 0, n_edges)

    return n_edges, total_dropped
