"""CVE → ATT&CK mappings parser.

This file turns the Mappings Explorer CSV into ENABLES edges — the bridge
between the CVE world and the ATT&CK world. The same dataset is also the
labelled ground truth for evaluation: 20% is held out and frozen before any
retrieval code exists.

Primary impact carries full weight (1.0); secondary impact is a weaker
signal (0.5). A row with no CVE ID, or a technique token that is not an
ATT&CK id, is logged and counted as skipped, not silently swallowed — the
distinction between "ignored" and "lost" matters for data quality.

Only the two impact columns become edges. The upstream file also carries
`Exploitation Technique` and `Uncategorized` columns; those are deliberately
not read, because the design weights a CVE's link to a technique by impact.

Must not: import from retrieval/, agent/, or llm/.
"""

from __future__ import annotations

import csv
import logging
import re
from pathlib import Path
from typing import TYPE_CHECKING

from threatlens.models import Edge, Node

if TYPE_CHECKING:
    from sqlalchemy.engine import Connection

log = logging.getLogger(__name__)

SOURCE = "mappings-explorer"

REQUIRED_COLUMNS = ("CVE ID", "Primary Impact", "Secondary Impact")
IMPACT_WEIGHTS = (("Primary Impact", 1.0), ("Secondary Impact", 0.5))

# The only shape a technique id may take. Anything else in a technique cell is a malformed
# token: counted as lost, never turned into a node id that matches nothing.
_TECHNIQUE_ID = re.compile(r"^T\d{4}(?:\.\d{3})?$")
_CELL_SEPARATORS = re.compile(r"[;,]")


def read_mappings_rows(
    path: Path, required: tuple[str, ...] = REQUIRED_COLUMNS
) -> list[dict[str, str]]:
    """Read the mappings CSV into one dict per row, tolerating a byte-order mark.

    The upstream file begins with a UTF-8 BOM. Read as plain `utf-8`, the BOM becomes part of
    the first header, every lookup of `"CVE ID"` misses, and the whole file is skipped without
    an error. `utf-8-sig` strips the BOM when present and is a no-op when it is not.

    Shared by the parser and by `fetch.collect_scoped_cve_ids`, so both readers of this file
    handle its format the same way.

    `required` names the columns this caller reads; it defaults to everything the parser
    needs. A reader that only wants CVE ids asks for less, rather than rejecting a file over
    columns it never looks at.

    Raises ValueError when a required column is missing. A renamed upstream column would
    otherwise skip every row and report success, which is how the BOM went unnoticed.
    """
    with open(path, newline="", encoding="utf-8-sig") as fh:
        reader = csv.DictReader(fh)
        found = reader.fieldnames or []
        missing = [c for c in required if c not in found]
        if missing:
            raise ValueError(
                f"{path.name} is missing required column(s) {missing}; found {list(found)}"
            )
        return list(reader)


def _technique_ids(cell: str) -> tuple[list[str], int]:
    """Split one cell into ATT&CK technique ids.

    Upstream packs several techniques into one cell (`T1499; T1098`) — 86 cells in the
    real file. Treating the cell as a single id produced `technique:T1499; T1098`, which
    matches no node and was later dropped as an absent technique.

    Returns (valid ids in cell order, count of tokens that are not technique ids).
    """
    valid: list[str] = []
    invalid = 0
    for token in _CELL_SEPARATORS.split(cell):
        token = token.strip().upper()
        if not token:
            continue
        if _TECHNIQUE_ID.match(token):
            valid.append(token)
        else:
            invalid += 1
    return valid, invalid


def parse_mappings_csv(path: Path) -> tuple[list[Edge], int]:
    """Parse a CVE→ATT&CK mappings CSV into ENABLES edges.

    Emits one edge per (CVE, technique) pair, at its strongest weight. A technique listed
    under both impacts, or on two rows for the same CVE, would otherwise reach the database
    twice, and the upsert keeps whichever arrives last — so a secondary listing could
    quietly lower a primary edge to 0.5. Edges come back in file order, so output is
    deterministic.

    Edges are emitted even for techniques that may not exist in the graph; the loader drops
    unresolvable ones later, because the parser has no access to the graph and should not
    need it.

    Returns:
        (edges, skipped_count) — skipped counts rows with no CVE ID plus technique tokens
        that are not valid ATT&CK ids.

    Raises:
        ValueError: a required column is missing, or the file has rows but yields no usable
            mapping at all — never a legitimate result for this dataset, and the exact
            symptom of the byte-order-mark bug.
    """
    rows = read_mappings_rows(path)
    strongest: dict[tuple[str, str], Edge] = {}
    skipped = 0

    for row in rows:
        cve_id = (row.get("CVE ID") or "").strip()
        if not cve_id:
            skipped += 1
            log.warning("mappings row with no CVE ID: %r", row)
            continue

        src = Node.make_id("cve", cve_id)

        for column, weight in IMPACT_WEIGHTS:
            cell = row.get(column) or ""
            techniques, invalid = _technique_ids(cell)
            if invalid:
                skipped += invalid
                log.warning(
                    "%d malformed technique token(s) for %s in %s: %r",
                    invalid,
                    cve_id,
                    column,
                    cell,
                )

            for technique in techniques:
                key = (src, Node.make_id("technique", technique))
                current = strongest.get(key)
                if current is None or weight > current.weight:
                    strongest[key] = Edge(
                        src=src,
                        dst=key[1],
                        kind="ENABLES",
                        source=SOURCE,
                        weight=weight,
                        attrs={"impact": column.split()[0].lower()},
                    )

    edges = list(strongest.values())
    if rows and not edges:
        raise ValueError(
            f"{path.name} has {len(rows)} row(s) but no usable mappings — check the file's "
            "encoding and column names before trusting an empty graph"
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
