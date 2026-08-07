"""The only module in the project that contains SQL.

Every write path is an upsert on the primary key, so re-running an ingestion updates
rather than duplicates.
"""

from __future__ import annotations

import json
from collections.abc import Iterable
from importlib import resources

from sqlalchemy import create_engine, text
from sqlalchemy.engine import Connection, Engine

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


def _row_to_node(row) -> Node:
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
