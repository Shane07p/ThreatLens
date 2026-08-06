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

from threatlens.models import Edge, Node

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
