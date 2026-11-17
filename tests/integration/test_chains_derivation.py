"""Deriving CHAINS_TO from actor co-occurrence.

The fuzziest edge in the graph, and the one most likely to be challenged. It is not
observed sequence data — nobody recorded an attacker doing A then B. It says only that
enough documented actors use both techniques, and that one tactic precedes the other in
the kill chain.

That makes the threshold and the direction the whole content of the edge. Both are
asserted here; if either is wrong the graph fills with plausible-looking noise that no
downstream metric can distinguish from signal.
"""

from __future__ import annotations

import os

import pytest
from sqlalchemy import text

from threatlens.graph.store import get_engine, init_schema, upsert_edges, upsert_nodes
from threatlens.ingest.chains import derive_chains
from threatlens.models import Edge, Node

pytestmark = [
    pytest.mark.db,
    pytest.mark.skipif(not os.getenv("THREATLENS_TEST_DSN"), reason="no THREATLENS_TEST_DSN"),
]


@pytest.fixture(scope="module")
def engine():
    eng = get_engine(os.environ["THREATLENS_TEST_DSN"])
    init_schema(eng)
    return eng


@pytest.fixture
def conn(engine):
    with engine.begin() as c:
        c.execute(text("TRUNCATE nodes CASCADE"))
        yield c


def tactic(ext_id: str, order: int | None) -> Node:
    return Node(
        id=f"tactic:{ext_id}",
        kind="tactic",
        external_id=ext_id,
        name=ext_id,
        source_url="u",
        attrs={"shortname": ext_id.lower(), "order": order},
    )


def technique(ext_id: str) -> Node:
    return Node(
        id=f"technique:{ext_id}",
        kind="technique",
        external_id=ext_id,
        name=f"Technique {ext_id}",
        source_url="u",
    )


def actor(ext_id: str) -> Node:
    return Node(
        id=f"actor:{ext_id}",
        kind="actor",
        external_id=ext_id,
        name=f"Actor {ext_id}",
        source_url="u",
    )


def belongs(tech: str, tac: str) -> Edge:
    return Edge(src=f"technique:{tech}", dst=f"tactic:{tac}", kind="BELONGS_TO", source="t")


def uses(act: str, tech: str) -> Edge:
    return Edge(src=f"actor:{act}", dst=f"technique:{tech}", kind="USES", source="t")


def scenario(conn, *, actors: int, early: str = "T1", late: str = "T2") -> None:
    """`actors` distinct actors use both techniques. `early` sits in an earlier tactic."""
    upsert_nodes(
        conn,
        [tactic("TA1", 0), tactic("TA2", 5), technique(early), technique(late)]
        + [actor(f"G{i}") for i in range(actors)],
    )
    upsert_edges(
        conn,
        [belongs(early, "TA1"), belongs(late, "TA2")]
        + [uses(f"G{i}", t) for i in range(actors) for t in (early, late)],
    )


def chains(conn) -> list[tuple[str, str]]:
    rows = conn.execute(
        text("SELECT src, dst FROM edges WHERE kind = 'CHAINS_TO' ORDER BY src, dst")
    )
    return [(r.src, r.dst) for r in rows]


# --- the threshold ---------------------------------------------------------------------


def test_enough_shared_actors_creates_a_chain(conn):
    scenario(conn, actors=3)
    derive_chains(conn, min_shared_actors=3)
    assert chains(conn) == [("technique:T1", "technique:T2")]


def test_one_actor_below_the_threshold_creates_nothing(conn):
    """Two techniques sharing two actors is a coincidence, not a pattern. The threshold is
    the only thing keeping the graph out of noise."""
    scenario(conn, actors=2)
    derive_chains(conn, min_shared_actors=3)
    assert chains(conn) == []


def test_the_threshold_is_inclusive(conn):
    """Exactly at the threshold counts. Off-by-one here silently halves the edge set."""
    scenario(conn, actors=3)
    derive_chains(conn, min_shared_actors=3)
    assert len(chains(conn)) == 1


# --- direction -------------------------------------------------------------------------


def test_direction_runs_from_earlier_tactic_to_later(conn):
    scenario(conn, actors=4)
    derive_chains(conn, min_shared_actors=3)
    assert chains(conn) == [("technique:T1", "technique:T2")]


def test_the_reverse_edge_is_not_created(conn):
    """A chain is an ordering claim. Emitting both directions would make it say nothing."""
    scenario(conn, actors=4)
    derive_chains(conn, min_shared_actors=3)
    assert ("technique:T2", "technique:T1") not in chains(conn)


def test_two_techniques_in_the_same_tactic_do_not_chain(conn):
    """Same phase means no ordering between them, however many actors they share."""
    upsert_nodes(
        conn,
        [tactic("TA1", 0), technique("T1"), technique("T2")] + [actor(f"G{i}") for i in range(5)],
    )
    upsert_edges(
        conn,
        [belongs("T1", "TA1"), belongs("T2", "TA1")]
        + [uses(f"G{i}", t) for i in range(5) for t in ("T1", "T2")],
    )
    derive_chains(conn, min_shared_actors=3)
    assert chains(conn) == []


def test_a_technique_takes_its_earliest_tactic(conn):
    """A technique in several tactics is placed at the earliest one, so a chain out of it
    is not suppressed by a later placement it also happens to have."""
    upsert_nodes(
        conn,
        [tactic("TA1", 0), tactic("TA2", 5), tactic("TA3", 9), technique("T1"), technique("T2")]
        + [actor(f"G{i}") for i in range(3)],
    )
    upsert_edges(
        conn,
        [belongs("T1", "TA1"), belongs("T1", "TA3"), belongs("T2", "TA2")]
        + [uses(f"G{i}", t) for i in range(3) for t in ("T1", "T2")],
    )
    derive_chains(conn, min_shared_actors=3)
    assert chains(conn) == [("technique:T1", "technique:T2")]


# --- degenerate shapes -------------------------------------------------------------------


def test_a_technique_never_chains_to_itself(conn):
    upsert_nodes(conn, [tactic("TA1", 0), technique("T1")] + [actor(f"G{i}") for i in range(5)])
    upsert_edges(conn, [belongs("T1", "TA1")] + [uses(f"G{i}", "T1") for i in range(5)])
    derive_chains(conn, min_shared_actors=3)
    assert chains(conn) == []


def test_an_unplaced_tactic_yields_no_chain(conn):
    """A tactic missing from the matrix has no position, so no ordering can be claimed.
    Treating a null order as zero would make every unplaced technique chain to everything."""
    upsert_nodes(
        conn,
        [tactic("TA1", 0), tactic("TAX", None), technique("T1"), technique("T2")]
        + [actor(f"G{i}") for i in range(4)],
    )
    upsert_edges(
        conn,
        [belongs("T1", "TA1"), belongs("T2", "TAX")]
        + [uses(f"G{i}", t) for i in range(4) for t in ("T1", "T2")],
    )
    derive_chains(conn, min_shared_actors=3)
    assert chains(conn) == []


def test_a_technique_with_no_tactic_yields_no_chain(conn):
    upsert_nodes(
        conn,
        [tactic("TA1", 0), technique("T1"), technique("T2")] + [actor(f"G{i}") for i in range(4)],
    )
    upsert_edges(
        conn,
        [belongs("T1", "TA1")] + [uses(f"G{i}", t) for i in range(4) for t in ("T1", "T2")],
    )
    derive_chains(conn, min_shared_actors=3)
    assert chains(conn) == []


def test_an_empty_graph_derives_nothing(conn):
    assert derive_chains(conn, min_shared_actors=3) == 0


def test_one_actor_using_both_techniques_counts_once(conn):
    """The shared count is a count of actors, and the row count equals it by construction.

    `edges` is keyed on (src, dst, kind), so an actor physically cannot have two USES rows
    against one technique — which is why the SQL counts rows rather than distinct actors.
    An earlier version used COUNT(DISTINCT actor_id); mutating it to COUNT(*) changed
    nothing and no test noticed, because the primary key had already made the two
    identical. The defensive version was unreachable code that read like a guard.
    """
    upsert_nodes(
        conn,
        [tactic("TA1", 0), tactic("TA2", 5), technique("T1"), technique("T2"), actor("G0")],
    )
    upsert_edges(
        conn,
        [belongs("T1", "TA1"), belongs("T2", "TA2"), uses("G0", "T1"), uses("G0", "T2")],
    )

    derive_chains(conn, min_shared_actors=2)
    assert chains(conn) == [], "one actor must not satisfy a two-actor threshold"

    derive_chains(conn, min_shared_actors=1)
    attrs = conn.execute(text("SELECT attrs FROM edges WHERE kind='CHAINS_TO'")).scalar_one()
    assert attrs["shared_actors"] == 1


# --- weight and provenance ----------------------------------------------------------------


def test_weight_rises_with_the_number_of_shared_actors(conn):
    """Ranking reads this weight. More corroboration must cost less to traverse."""
    scenario(conn, actors=3)
    derive_chains(conn, min_shared_actors=3)
    weak = conn.execute(text("SELECT weight FROM edges WHERE kind='CHAINS_TO'")).scalar_one()

    conn.execute(text("TRUNCATE nodes CASCADE"))
    scenario(conn, actors=9)
    derive_chains(conn, min_shared_actors=3)
    strong = conn.execute(text("SELECT weight FROM edges WHERE kind='CHAINS_TO'")).scalar_one()

    assert strong > weak


def test_weight_stays_within_zero_and_one(conn):
    scenario(conn, actors=7)
    derive_chains(conn, min_shared_actors=3)
    w = conn.execute(text("SELECT weight FROM edges WHERE kind='CHAINS_TO'")).scalar_one()
    assert 0.0 < w <= 1.0


def test_the_shared_actor_count_is_recorded_on_the_edge(conn):
    """The number behind the edge has to be inspectable, or the heuristic cannot be
    defended when somebody asks why two techniques are linked."""
    scenario(conn, actors=5)
    derive_chains(conn, min_shared_actors=3)
    attrs = conn.execute(text("SELECT attrs FROM edges WHERE kind='CHAINS_TO'")).scalar_one()
    assert attrs["shared_actors"] == 5


def test_the_edge_says_it_was_derived(conn):
    """Distinguishable from an edge that came out of MITRE's own data."""
    scenario(conn, actors=3)
    derive_chains(conn, min_shared_actors=3)
    src = conn.execute(text("SELECT source FROM edges WHERE kind='CHAINS_TO'")).scalar_one()
    assert "derived" in src


# --- reruns --------------------------------------------------------------------------------


def test_deriving_twice_changes_nothing(conn):
    scenario(conn, actors=4)
    first = derive_chains(conn, min_shared_actors=3)
    second = derive_chains(conn, min_shared_actors=3)
    assert first == second
    assert len(chains(conn)) == 1


def test_rerunning_after_the_evidence_weakens_removes_the_edge(conn):
    """A stale chain is worse than a missing one: it keeps asserting a link the current
    data no longer supports, and nothing in the graph says it is out of date."""
    scenario(conn, actors=4)
    derive_chains(conn, min_shared_actors=3)
    assert len(chains(conn)) == 1

    conn.execute(text("DELETE FROM edges WHERE kind = 'USES' AND src IN ('actor:G2','actor:G3')"))
    derive_chains(conn, min_shared_actors=3)
    assert chains(conn) == []


def test_derivation_leaves_other_edge_kinds_alone(conn):
    """Only derived edges are ours to delete. Removing a BELONGS_TO here would destroy
    ingested data on a routine re-derivation."""
    scenario(conn, actors=3)
    before = conn.execute(text("SELECT count(*) FROM edges WHERE kind <> 'CHAINS_TO'")).scalar_one()
    derive_chains(conn, min_shared_actors=3)
    after = conn.execute(text("SELECT count(*) FROM edges WHERE kind <> 'CHAINS_TO'")).scalar_one()
    assert before == after
