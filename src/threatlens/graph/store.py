"""The only module in the project that contains SQL.

Every write path is an upsert on the primary key, so re-running an ingestion updates
rather than duplicates.
"""

from __future__ import annotations

import json
from collections.abc import Iterable
from importlib import resources

from sqlalchemy import create_engine, make_url, text
from sqlalchemy.engine import Connection, Engine, Row
from sqlalchemy.exc import ArgumentError

from threatlens.models import Edge, Node

_NODE_UPSERT = text("""
    INSERT INTO nodes (id, kind, external_id, stix_id, name, description, attrs, source_url)
    VALUES (:id, :kind, :external_id, :stix_id, :name, :description,
            CAST(:attrs AS jsonb), :source_url)
    ON CONFLICT (id) DO UPDATE SET
        name        = EXCLUDED.name,
        description = EXCLUDED.description,
        attrs       = EXCLUDED.attrs,
        source_url  = EXCLUDED.source_url,
        stix_id     = EXCLUDED.stix_id
""")

_EDGE_UPSERT = text("""
    INSERT INTO edges (src, dst, kind, weight, source, attrs)
    VALUES (:src, :dst, :kind, :weight, :source, CAST(:attrs AS jsonb))
    ON CONFLICT (src, dst, kind) DO UPDATE SET
        weight = EXCLUDED.weight,
        source = EXCLUDED.source,
        attrs  = EXCLUDED.attrs
""")


def normalize_dsn(url: str) -> str:
    """Force the psycopg (v3) driver.

    SQLAlchemy maps a bare `postgresql://` to psycopg2, which this project does not
    install — the failure is an unhelpful `No module named 'psycopg2'` at connect time.
    CI and most tooling emit the bare form, so normalize rather than requiring everyone
    to remember the `+psycopg` suffix.
    """
    if url.startswith("postgresql://"):
        return url.replace("postgresql://", "postgresql+psycopg://", 1)
    if url.startswith("postgres://"):  # the legacy Heroku-style prefix
        return url.replace("postgres://", "postgresql+psycopg://", 1)
    return url


def redact_dsn(url: str) -> str:
    """The DSN with its password hidden, for anything printed or logged.

    What a command prints ends up in shell history, CI logs, and pasted bug reports.
    Host, port, user, and database stay visible — they are what someone debugging a
    connection needs. A DSN with no password is returned unchanged.

    A URL that cannot be parsed is hidden entirely rather than printed as-is: if the
    password cannot be located, no part of the string can be shown safely. SQLAlchemy
    signals a malformed URL with ArgumentError, but a non-numeric port surfaces as a
    ValueError from int() — catching only the first let that shape crash the caller.
    """
    try:
        parsed = make_url(url)
    except (ArgumentError, ValueError):
        return "****"
    return parsed.render_as_string(hide_password=True) if parsed.password else url


def ping(engine: Engine) -> bool:
    """Is the database reachable? Used by the CLI health check.

    Lives here rather than in the CLI because this file is the only place SQL is
    allowed — a health check is still a query, and scattering them is how a schema
    change ends up with more than one home.
    """
    try:
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
        return True
    except Exception:
        return False


def get_engine(url: str | None = None) -> Engine:
    """Build an Engine. Tests pass a URL explicitly; production reads config."""
    if url is None:
        from threatlens.config import get_settings

        url = get_settings().database_url
    return create_engine(normalize_dsn(url), future=True)


def _split_statements(sql: str) -> list[str]:
    return [s.strip() for s in sql.split(";") if s.strip()]


def init_schema(engine: Engine) -> None:
    """Apply schema.sql. Idempotent — every statement is IF NOT EXISTS."""
    sql = resources.files("threatlens.graph").joinpath("schema.sql").read_text(encoding="utf-8")
    with engine.begin() as conn:
        for statement in _split_statements(sql):
            conn.execute(text(statement))


def upsert_nodes(conn: Connection, nodes: Iterable[Node]) -> int:
    rows = [
        {
            "id": n.id,
            "kind": n.kind,
            "external_id": n.external_id,
            "stix_id": n.stix_id,
            "name": n.name,
            "description": n.description,
            "attrs": json.dumps(n.attrs, sort_keys=True),
            "source_url": n.source_url,
        }
        for n in nodes
    ]
    if not rows:
        return 0
    conn.execute(_NODE_UPSERT, rows)
    return len(rows)


def upsert_edges(conn: Connection, edges: Iterable[Edge]) -> int:
    rows = [
        {
            "src": e.src,
            "dst": e.dst,
            "kind": e.kind,
            "weight": e.weight,
            "source": e.source,
            "attrs": json.dumps(e.attrs, sort_keys=True),
        }
        for e in edges
    ]
    if not rows:
        return 0
    conn.execute(_EDGE_UPSERT, rows)
    return len(rows)


def record_ingest_run(
    conn: Connection,
    source: str,
    version: str,
    sha256: str,
    n_nodes: int,
    n_edges: int,
) -> int:
    return conn.execute(
        text("""
            INSERT INTO ingest_runs (source, version, sha256, node_count, edge_count)
            VALUES (:source, :version, :sha256, :n_nodes, :n_edges)
            RETURNING id
        """),
        {
            "source": source,
            "version": version,
            "sha256": sha256,
            "n_nodes": n_nodes,
            "n_edges": n_edges,
        },
    ).scalar_one()


def node_counts(conn: Connection) -> dict[str, int]:
    rows = conn.execute(text("SELECT kind, count(*) AS n FROM nodes GROUP BY kind"))
    return {r.kind: r.n for r in rows}


def edge_counts(conn: Connection) -> dict[str, int]:
    rows = conn.execute(text("SELECT kind, count(*) AS n FROM edges GROUP BY kind"))
    return {r.kind: r.n for r in rows}


def _row_to_node(row: Row) -> Node:
    return Node(
        id=row.id,
        kind=row.kind,
        external_id=row.external_id,
        name=row.name,
        source_url=row.source_url,
        description=row.description,
        stix_id=row.stix_id,
        attrs=row.attrs or {},
    )


def get_node(conn: Connection, node_id: str) -> Node | None:
    row = conn.execute(
        text("""
            SELECT id, kind, external_id, stix_id, name, description, attrs, source_url
            FROM nodes WHERE id = :id
        """),
        {"id": node_id},
    ).one_or_none()
    return _row_to_node(row) if row else None


def neighbors(conn: Connection, node_id: str, kinds: list[str]) -> list[tuple[Edge, Node]]:
    rows = conn.execute(
        text("""
            SELECT e.src, e.dst, e.kind AS edge_kind, e.weight, e.source,
                   e.attrs AS edge_attrs,
                   n.id, n.kind, n.external_id, n.stix_id, n.name, n.description,
                   n.attrs, n.source_url
            FROM edges e
            JOIN nodes n ON n.id = e.dst
            WHERE e.src = :id AND e.kind = ANY(:kinds)
            ORDER BY e.weight DESC, n.id
        """),
        {"id": node_id, "kinds": kinds},
    )
    out: list[tuple[Edge, Node]] = []
    for r in rows:
        edge = Edge(
            src=r.src,
            dst=r.dst,
            kind=r.edge_kind,
            source=r.source,
            weight=r.weight,
            attrs=r.edge_attrs or {},
        )
        out.append((edge, _row_to_node(r)))
    return out


# ── node_chunks operations ───────────────────────────────────────────────────

_DELETE_NODE_CHUNKS = text("DELETE FROM node_chunks WHERE node_id = :node_id")

_INSERT_CHUNK = text("""
    INSERT INTO node_chunks (node_id, chunk_ix, text, embedding)
    VALUES (:node_id, :chunk_ix, :text, CAST(:embedding AS vector))
    ON CONFLICT (node_id, chunk_ix) DO UPDATE SET
        text      = EXCLUDED.text,
        embedding = EXCLUDED.embedding
""")

_COUNT_NODE_CHUNKS = text("SELECT count(*) FROM node_chunks")

_NODES_WITH_DESCRIPTIONS = text("""
    SELECT id, kind, external_id, stix_id, name, description, attrs, source_url
    FROM nodes
    WHERE description IS NOT NULL AND description != ''
    ORDER BY id
""")


def delete_node_chunks(conn: Connection, node_id: str) -> int:
    """Remove all chunks for a node. Returns the number of rows deleted."""
    result = conn.execute(_DELETE_NODE_CHUNKS, {"node_id": node_id})
    return result.rowcount


def upsert_node_chunks(
    conn: Connection,
    chunks: Iterable[dict],
) -> int:
    """Insert or update node chunks. Each dict must have node_id, chunk_ix, text, embedding."""
    rows = list(chunks)
    if not rows:
        return 0
    conn.execute(_INSERT_CHUNK, rows)
    return len(rows)


def count_node_chunks(conn: Connection) -> int:
    """Total number of rows in node_chunks."""
    return conn.execute(_COUNT_NODE_CHUNKS).scalar_one()


def nodes_with_descriptions(conn: Connection) -> list[Node]:
    """All nodes that have a non-empty description (candidates for embedding)."""
    rows = conn.execute(_NODES_WITH_DESCRIPTIONS)
    return [_row_to_node(r) for r in rows]


# ── derived edges ────────────────────────────────────────────────────────────

_DELETE_DERIVED_CHAINS = text("DELETE FROM edges WHERE kind = 'CHAINS_TO'")

_DERIVE_CHAINS = text("""
    WITH tech_phase AS (
        SELECT e.src AS technique_id, MIN((t.attrs->>'order')::int) AS phase_ix
        FROM edges e
        JOIN nodes t ON t.id = e.dst AND t.kind = 'tactic'
        WHERE e.kind = 'BELONGS_TO' AND t.attrs->>'order' IS NOT NULL
        GROUP BY e.src
    ),
    -- No DISTINCT here, and none needed: edges is keyed on (src, dst, kind), so an
    -- actor cannot appear twice against the same technique. A defensive COUNT(DISTINCT)
    -- would be unreachable code that reads like it is guarding something.
    actor_tech AS (
        SELECT src AS actor_id, dst AS technique_id
        FROM edges WHERE kind = 'USES'
    ),
    pairs AS (
        SELECT a.technique_id AS src_id,
               b.technique_id AS dst_id,
               count(*) AS shared
        FROM actor_tech a
        JOIN actor_tech b
          ON b.actor_id = a.actor_id AND b.technique_id <> a.technique_id
        JOIN tech_phase pa ON pa.technique_id = a.technique_id
        JOIN tech_phase pb ON pb.technique_id = b.technique_id
        WHERE pa.phase_ix < pb.phase_ix
        GROUP BY a.technique_id, b.technique_id
        HAVING count(*) >= :min_shared
    )
    INSERT INTO edges (src, dst, kind, weight, source, attrs)
    SELECT src_id, dst_id, 'CHAINS_TO',
           LEAST(shared::float8 / :saturation, 1.0)::real,
           :source,
           jsonb_build_object('shared_actors', shared)
    FROM pairs
""")


def replace_chain_edges(
    conn: Connection,
    min_shared: int,
    saturation: int,
    source: str,
) -> int:
    """Rebuild every CHAINS_TO edge from current actor co-occurrence.

    Deletes the existing derived edges before re-deriving. A chain left behind after its
    evidence weakened keeps asserting a link the data no longer supports, and nothing in
    the graph marks it stale — so a rebuild has to be a replacement, not a merge. Only
    CHAINS_TO is touched; every ingested edge kind is left alone.

    `min_shared` is the number of distinct actors that must use both techniques.
    `saturation` is the count at which weight reaches 1.0; it cannot be the observed
    maximum, because then a run producing a single pair would score it 1.0 on the
    strength of one actor.

    A technique in several tactics is placed at its earliest, so a chain out of it is not
    suppressed by a later placement it also holds. A tactic with no position in the matrix
    yields no chain at all rather than being treated as first.

    Returns the number of edges written.
    """
    conn.execute(_DELETE_DERIVED_CHAINS)
    result = conn.execute(
        _DERIVE_CHAINS,
        {"min_shared": min_shared, "saturation": saturation, "source": source},
    )
    return result.rowcount
