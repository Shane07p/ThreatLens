"""Store integration tests. Real Postgres, real SQL, real pgvector.

Skipped without THREATLENS_TEST_DSN so a contributor with no local database can still
run the suite. CI always sets it, so these always run there.

The property that matters most here is idempotency: ingestion re-runs, and a write path
that duplicates instead of updating silently doubles the graph.
"""

from __future__ import annotations

import os

import pytest
from sqlalchemy import text

from threatlens.graph.store import (
    edge_counts,
    get_engine,
    get_node,
    init_schema,
    neighbors,
    node_counts,
    record_ingest_run,
    upsert_edges,
    upsert_nodes,
)
from threatlens.models import Edge, Node

pytestmark = [
    pytest.mark.db,
    pytest.mark.skipif(not os.getenv("THREATLENS_TEST_DSN"), reason="no THREATLENS_TEST_DSN"),
]

NODES = [
    Node(
        id="technique:T1190",
        kind="technique",
        external_id="T1190",
        name="Exploit Public-Facing Application",
        source_url="https://attack.mitre.org/techniques/T1190",
        description="Adversaries may attempt to exploit a weakness.",
        stix_id="attack-pattern--3f886f2a",
        attrs={"is_subtechnique": False},
    ),
    Node(
        id="tactic:TA0001",
        kind="tactic",
        external_id="TA0001",
        name="Initial Access",
        source_url="https://attack.mitre.org/tactics/TA0001",
    ),
    Node(
        id="mitigation:M1030",
        kind="mitigation",
        external_id="M1030",
        name="Network Segmentation",
        source_url="https://attack.mitre.org/mitigations/M1030",
    ),
]

EDGES = [
    Edge(src="technique:T1190", dst="tactic:TA0001", kind="BELONGS_TO", source="test"),
    Edge(
        src="technique:T1190",
        dst="mitigation:M1030",
        kind="MITIGATED_BY",
        source="test",
        weight=0.5,
    ),
]


@pytest.fixture(scope="module")
def engine():
    eng = get_engine(os.environ["THREATLENS_TEST_DSN"])
    init_schema(eng)
    return eng


@pytest.fixture
def conn(engine):
    """A clean, seeded connection per test. Truncate rather than drop — faster, and it
    proves the schema survives repeated use."""
    with engine.begin() as c:
        c.execute(text("TRUNCATE nodes CASCADE"))
        c.execute(text("TRUNCATE ingest_runs"))
        upsert_nodes(c, NODES)
        upsert_edges(c, EDGES)
        yield c


# --- schema --------------------------------------------------------------------------


def test_init_schema_is_idempotent(engine):
    """Applied on every `db init`; a second run must not error."""
    init_schema(engine)
    init_schema(engine)
    with engine.connect() as c:
        assert c.execute(text("SELECT count(*) FROM nodes")).scalar_one() >= 0


def test_pgvector_extension_is_enabled(engine):
    with engine.connect() as c:
        n = c.execute(text("SELECT count(*) FROM pg_extension WHERE extname = 'vector'"))
        assert n.scalar_one() == 1


def test_embedding_column_is_384_dimensions(engine):
    """The embedding model emits 384 dimensions. A mismatch here is invisible until
    the first vector search returns nothing."""
    with engine.connect() as c:
        typ = c.execute(
            text("""
                SELECT format_type(a.atttypid, a.atttypmod)
                FROM pg_attribute a
                WHERE a.attrelid = 'nodes'::regclass AND a.attname = 'embedding'
            """)
        ).scalar_one()
    assert "384" in typ


# --- idempotency ---------------------------------------------------------------------


def test_upsert_nodes_is_idempotent(conn):
    upsert_nodes(conn, NODES)
    upsert_nodes(conn, NODES)
    assert conn.execute(text("SELECT count(*) FROM nodes")).scalar_one() == 3


def test_upsert_edges_is_idempotent(conn):
    upsert_edges(conn, EDGES)
    upsert_edges(conn, EDGES)
    assert conn.execute(text("SELECT count(*) FROM edges")).scalar_one() == 2


def test_upsert_updates_changed_fields(conn):
    """Re-ingesting after an ATT&CK release must refresh names, not duplicate rows."""
    renamed = [
        Node(
            id="technique:T1190",
            kind="technique",
            external_id="T1190",
            name="RENAMED",
            source_url="https://attack.mitre.org/techniques/T1190",
            description="new description",
        )
    ]
    upsert_nodes(conn, renamed)
    row = conn.execute(
        text("SELECT name, description FROM nodes WHERE id = :i"), {"i": "technique:T1190"}
    ).one()
    assert row.name == "RENAMED"
    assert row.description == "new description"


def test_upsert_of_empty_iterable_is_a_noop(conn):
    assert upsert_nodes(conn, []) == 0
    assert upsert_edges(conn, []) == 0


# --- constraints ---------------------------------------------------------------------


def test_edge_to_a_missing_node_is_rejected(conn):
    """The foreign key is the last line of defence against a dangling edge."""
    from sqlalchemy.exc import IntegrityError

    with pytest.raises(IntegrityError):
        upsert_edges(
            conn, [Edge(src="technique:T1190", dst="technique:GHOST", kind="USES", source="t")]
        )


def test_kind_and_external_id_are_unique_together(conn):
    """Two rows claiming (technique, T1190) would break every id-based join."""
    from sqlalchemy.exc import IntegrityError

    with pytest.raises(IntegrityError):
        conn.execute(
            text("""
                INSERT INTO nodes (id, kind, external_id, name, source_url)
                VALUES ('technique:duplicate', 'technique', 'T1190', 'dupe', 'u')
            """)
        )


def test_deleting_a_node_cascades_to_its_edges(conn):
    conn.execute(text("DELETE FROM nodes WHERE id = :i"), {"i": "mitigation:M1030"})
    remaining = conn.execute(
        text("SELECT count(*) FROM edges WHERE dst = :i"), {"i": "mitigation:M1030"}
    ).scalar_one()
    assert remaining == 0


# --- round-tripping ------------------------------------------------------------------


def test_get_node_round_trips_every_field(conn):
    node = get_node(conn, "technique:T1190")
    original = NODES[0]
    assert node == original


def test_get_node_missing_returns_none(conn):
    assert get_node(conn, "technique:T9999") is None


def test_jsonb_attrs_survive_the_round_trip(conn):
    upsert_nodes(
        conn,
        [
            Node(
                id="technique:T0001",
                kind="technique",
                external_id="T0001",
                name="attrs test",
                source_url="u",
                attrs={"nested": {"a": [1, 2, 3]}, "flag": True, "none": None},
            )
        ],
    )
    node = get_node(conn, "technique:T0001")
    assert node.attrs == {"nested": {"a": [1, 2, 3]}, "flag": True, "none": None}


def test_unicode_survives_the_round_trip(conn):
    upsert_nodes(
        conn,
        [
            Node(
                id="technique:T0002",
                kind="technique",
                external_id="T0002",
                name="Tëchnïque — 攻撃 🔒",
                source_url="u",
            )
        ],
    )
    assert get_node(conn, "technique:T0002").name == "Tëchnïque — 攻撃 🔒"


@pytest.mark.security
def test_sql_shaped_text_is_stored_verbatim(conn):
    """Proves the parameterized queries actually parameterize."""
    hostile = "'; DROP TABLE nodes; --"
    upsert_nodes(
        conn,
        [
            Node(
                id="technique:T0003",
                kind="technique",
                external_id="T0003",
                name=hostile,
                source_url="u",
            )
        ],
    )
    assert get_node(conn, "technique:T0003").name == hostile
    assert conn.execute(text("SELECT count(*) FROM nodes")).scalar_one() > 0


# --- reads ---------------------------------------------------------------------------


def test_node_counts_by_kind(conn):
    assert node_counts(conn) == {"technique": 1, "tactic": 1, "mitigation": 1}


def test_edge_counts_by_kind(conn):
    assert edge_counts(conn) == {"BELONGS_TO": 1, "MITIGATED_BY": 1}


def test_neighbors_filters_by_kind(conn):
    result = neighbors(conn, "technique:T1190", ["BELONGS_TO"])
    assert len(result) == 1
    edge, node = result[0]
    assert edge.kind == "BELONGS_TO"
    assert node.id == "tactic:TA0001"


def test_neighbors_accepts_multiple_kinds(conn):
    result = neighbors(conn, "technique:T1190", ["BELONGS_TO", "MITIGATED_BY"])
    assert {n.id for _, n in result} == {"tactic:TA0001", "mitigation:M1030"}


def test_neighbors_preserves_weight(conn):
    edge, _ = neighbors(conn, "technique:T1190", ["MITIGATED_BY"])[0]
    assert edge.weight == pytest.approx(0.5)


def test_neighbors_orders_by_weight_descending(conn):
    """Truncating a large neighbour set must keep the strongest edges."""
    result = neighbors(conn, "technique:T1190", ["BELONGS_TO", "MITIGATED_BY"])
    weights = [e.weight for e, _ in result]
    assert weights == sorted(weights, reverse=True)


def test_neighbors_of_an_unknown_node_is_empty(conn):
    assert neighbors(conn, "technique:GHOST", ["BELONGS_TO"]) == []


def test_neighbors_with_no_kinds_is_empty(conn):
    assert neighbors(conn, "technique:T1190", []) == []


# --- provenance ----------------------------------------------------------------------


def test_record_ingest_run_returns_its_id(conn):
    run_id = record_ingest_run(conn, "attack-stix", "19.1", "abc123", 3, 2)
    row = conn.execute(
        text("SELECT source, version, sha256, node_count FROM ingest_runs WHERE id = :i"),
        {"i": run_id},
    ).one()
    assert (row.source, row.version, row.sha256, row.node_count) == (
        "attack-stix",
        "19.1",
        "abc123",
        3,
    )


def test_ingest_runs_accumulate(conn):
    """History, not a single row — you need to see which snapshot built which graph."""
    record_ingest_run(conn, "attack-stix", "19.0", "aaa", 1, 1)
    record_ingest_run(conn, "attack-stix", "19.1", "bbb", 2, 2)
    assert conn.execute(text("SELECT count(*) FROM ingest_runs")).scalar_one() == 2
