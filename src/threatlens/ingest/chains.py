"""Derive CHAINS_TO edges from actor co-occurrence.

Every other edge in the graph is something MITRE published. This one is inferred, and it
is the only edge here that could be wrong in a way no upstream source would catch — so
the definition is kept deliberately narrow, and the evidence behind each edge is stored
on it:

    Techniques A and B are chained when at least MIN_SHARED_ACTORS distinct threat actors
    are documented using both, and A's tactic comes before B's in the kill chain.

**This is co-occurrence, not observed sequence.** Nobody recorded an attacker doing A and
then B. Two techniques used by the same groups, in kill-chain order, is weaker evidence
than "these steps follow one another", and describing it as attack-path data would be
overclaiming. Say so wherever these edges are surfaced.

The threshold is the whole content of the edge. Lower it and the graph fills with
plausible-looking noise that no metric downstream can separate from signal; raise it and
rare-but-real progressions disappear.
"""

from __future__ import annotations

import logging

from sqlalchemy.engine import Connection

from threatlens.graph.store import record_ingest_run, replace_chain_edges

log = logging.getLogger(__name__)

SOURCE = "derived: actor co-occurrence"

# The shared-actor count at which an edge reaches weight 1.0. Deliberately a constant
# rather than the maximum observed in the run: normalizing by the observed maximum would
# score the single strongest pair 1.0 no matter how thin the evidence behind it, and
# would move every weight in the graph whenever one new pair appeared.
SATURATION_SHARED_ACTORS = 10


def derive_chains(
    conn: Connection,
    min_shared_actors: int | None = None,
    saturation: int = SATURATION_SHARED_ACTORS,
) -> int:
    """Rebuild CHAINS_TO from the actor and tactic edges already in the graph.

    Reads `USES` and `BELONGS_TO`, writes `CHAINS_TO`. Needs no snapshot on disk — it is
    derived from what ingestion already loaded, so it must run after `ingest attack`.

    `min_shared_actors` defaults to the configured value. Re-running replaces the derived
    edges wholesale, so a chain whose evidence has weakened disappears rather than
    lingering.

    Returns the number of edges written.
    """
    if min_shared_actors is None:
        from threatlens.config import get_settings

        min_shared_actors = get_settings().min_shared_actors

    n_edges = replace_chain_edges(conn, min_shared_actors, saturation, SOURCE)
    record_ingest_run(conn, "chains", f"min_shared={min_shared_actors}", "derived", 0, n_edges)

    log.info("derived %d CHAINS_TO edges at min_shared_actors=%d", n_edges, min_shared_actors)
    return n_edges
