# Phase 1 + Independent Phase 2 Parsers — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the MITRE ATT&CK Enterprise matrix into a queryable Postgres graph, and unit-test the Phase 2 parsers (NVD, CVE→ATT&CK mappings, eval metrics) that need no graph.

**Architecture:** Contract-first. Task 0 freezes the shared `Node`/`Edge`/`Graph` dataclasses, the SQL schema, and a working node/edge upsert. Four tracks then proceed in parallel against that frozen interface — foundation (config + read helpers), STIX parser, CLI + fetch, and the Phase 2 pure parsers. Ingestion is offline and one-shot; nothing here calls an LLM.

**Tech Stack:** Python 3.12, uv, PostgreSQL 16 + pgvector, SQLAlchemy Core (not the ORM), psycopg 3, `stix2`, `httpx`, `tenacity`, Typer, pytest, ruff.

## Global Constraints

- **`uv add`, never `pip install`.** Dependencies must land in `pyproject.toml` and `uv.lock`.
- **Node ids are `f"{kind}:{external_id}"`.** Deterministic — this is what makes ingestion idempotent.
- **No `os.environ` outside `config.py`.**
- **No SQL outside `graph/`.**
- **No f-string SQL.** Parameterized queries only, including in ingestion scripts.
- **A missing CVSS score is `None`, never `0.0`.** A fabricated 0.0 severity will surface in an answer.
- **`Graph.skipped` is reported, never hidden.** Revoked/deprecated/dangling counts get printed.
- **Every ingest write path is an upsert on the primary key.** Re-running must not duplicate.
- **Unit tests take no network, no database, no model weights.** `tests/conftest.py` already blocks sockets for anything not marked `db` or `eval`.
- **Line length 100.** `uv run ruff check . && uv run ruff format .` before every commit.
- **Commits carry no Claude/Anthropic attribution.** Conventional Commits, phase-scoped.
- **CI must be green before merge:** `uv run ruff check . && uv run ruff format --check . && uv run pytest -m "not eval"`.

## Environment Blocker — resolve before Task 0

Docker 29.4.1 is installed but its daemon is not running, and something is already listening on `localhost:5432`. Identify it:

```bash
docker info                                    # start Docker Desktop if this fails
python -c "import socket;s=socket.socket();print(s.connect_ex(('localhost',5432)))"
```

If a native Postgres owns 5432, either install pgvector into it or remap the container in `docker-compose.yml` to `5433:5432` and update `DATABASE_URL`. A native Postgres without the `vector` extension fails at `CREATE EXTENSION` and every integration test dies.

## File Structure

| File | Responsibility | Task |
|---|---|---|
| `src/threatlens/models.py` | `Node`, `Edge`, `Graph` dataclasses. No behavior beyond id construction. | 0 |
| `src/threatlens/graph/schema.sql` | DDL: `nodes`, `node_chunks`, `edges`, `ingest_runs`, indexes | 0 |
| `src/threatlens/graph/store.py` | Engine, schema application, upserts, read helpers. The only module with SQL. | 0, A1, A2 |
| `src/threatlens/config.py` | Frozen `Settings` from env. The only module reading `os.environ`. | A1 |
| `src/threatlens/ingest/attack.py` | STIX bundle → `Graph`. Pure: no DB, no network. | B1–B4 |
| `src/threatlens/ingest/fetch.py` | Download + sha256 + `data/manifest.json` | C1 |
| `src/threatlens/cli.py` | Typer app. Wiring only — no logic. | C2, C3 |
| `src/threatlens/ingest/nvd.py` | NVD client, rate limiter, CVE record → `Node` | D1, D2 |
| `src/threatlens/ingest/mappings.py` | CVE→ATT&CK mappings → `list[Edge]` | D3 |
| `src/threatlens/eval/metrics.py` | `recall_at_k`, `mrr`, `path_correct`. Pure functions. | D4 |

Split by responsibility. `store.py` owns all SQL so a schema change has one home; `attack.py` stays pure so its 20-odd parsing rules are testable without a database.

## Track Assignment

| Track | Tasks | Depends on | Branch |
|---|---|---|---|
| **0 — Contract** | Task 0 | — | `contract` → merge to `main` first |
| **A — Foundation** | A1, A2 | Task 0 | `track-a-foundation` |
| **B — STIX parser** | B1, B2, B3, B4 | Task 0 | `track-b-stix-parser` |
| **C — CLI + fetch** | C1, C2, C3 | Task 0; C3 needs A + B merged | `track-c-cli` |
| **D — Phase 2 parsers** | D1, D2, D3, D4 | **nothing** | `track-d-parsers` |

Merge order: `contract` → A → B → C. D merges whenever it's ready.

---

# Task 0: The Contract

**Owner:** one person. Everyone else waits. Budget ~90 minutes.

**Files:**
- Create: `src/threatlens/models.py`
- Create: `src/threatlens/graph/__init__.py`
- Create: `src/threatlens/graph/schema.sql`
- Create: `src/threatlens/graph/store.py`
- Create: `src/threatlens/ingest/__init__.py`
- Create: `src/threatlens/eval/__init__.py`
- Create: `tests/unit/test_models.py`
- Create: `tests/integration/__init__.py`
- Create: `tests/integration/test_upsert_idempotent.py`
- Modify: `pyproject.toml` (dependencies)

**Interfaces:**
- Consumes: nothing
- Produces: `Node`, `Edge`, `Graph` from `threatlens.models`; from `threatlens.graph.store`: `get_engine(url: str | None = None) -> Engine`, `init_schema(engine: Engine) -> None`, `upsert_nodes(conn, nodes: Iterable[Node]) -> int`, `upsert_edges(conn, edges: Iterable[Edge]) -> int`. Stubs raising `NotImplementedError`: `record_ingest_run`, `node_counts`, `edge_counts`, `get_node`, `neighbors`.

- [ ] **Step 1: Add dependencies**

```bash
uv add "psycopg[binary]" sqlalchemy typer python-dotenv
```

- [ ] **Step 2: Write the failing test for id construction**

Create `tests/unit/test_models.py`:

```python
from dataclasses import FrozenInstanceError

import pytest

from threatlens.models import Edge, Graph, Node


def test_node_id_is_kind_colon_external_id():
    assert Node.make_id("technique", "T1190") == "technique:T1190"
    assert Node.make_id("cve", "CVE-2021-44228") == "cve:CVE-2021-44228"


def test_node_is_frozen():
    n = Node(
        id="technique:T1190",
        kind="technique",
        external_id="T1190",
        name="Exploit Public-Facing Application",
        source_url="https://attack.mitre.org/techniques/T1190",
    )
    with pytest.raises(FrozenInstanceError):
        n.name = "changed"


def test_graph_counts_are_derived():
    n = Node(
        id="technique:T1190",
        kind="technique",
        external_id="T1190",
        name="X",
        source_url="u",
    )
    e = Edge(src="technique:T1190", dst="tactic:TA0001", kind="BELONGS_TO", source="test")
    g = Graph(nodes=[n], edges=[e], version="19.1", skipped=3)
    assert len(g.nodes) == 1
    assert len(g.edges) == 1
    assert g.skipped == 3
```

- [ ] **Step 3: Run the test to verify it fails**

Run: `uv run pytest tests/unit/test_models.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'threatlens.models'`

- [ ] **Step 4: Write models.py**

Create `src/threatlens/models.py`:

```python
"""Shared types. Every track depends on these — changing them is a conversation."""

from __future__ import annotations

from dataclasses import dataclass, field

NODE_KINDS = frozenset(
    {"technique", "tactic", "mitigation", "actor", "software", "cve", "detection"}
)

EDGE_KINDS = frozenset(
    {
        "ENABLES",
        "BELONGS_TO",
        "MITIGATED_BY",
        "USES",
        "USES_SOFTWARE",
        "SUBTECHNIQUE_OF",
        "CHAINS_TO",
        "DETECTED_BY",
    }
)


@dataclass(frozen=True)
class Node:
    id: str
    kind: str
    external_id: str
    name: str
    source_url: str
    description: str | None = None
    stix_id: str | None = None
    attrs: dict = field(default_factory=dict)

    @staticmethod
    def make_id(kind: str, external_id: str) -> str:
        """Deterministic id. This is what makes re-ingestion an upsert, not a duplicate."""
        return f"{kind}:{external_id}"


@dataclass(frozen=True)
class Edge:
    src: str
    dst: str
    kind: str
    source: str
    weight: float = 1.0
    attrs: dict = field(default_factory=dict)


@dataclass(frozen=True)
class Graph:
    nodes: list[Node]
    edges: list[Edge]
    version: str
    skipped: int = 0
```

- [ ] **Step 5: Run the test to verify it passes**

Run: `uv run pytest tests/unit/test_models.py -v`
Expected: 3 passed

- [ ] **Step 6: Write the schema**

Create `src/threatlens/graph/__init__.py` (empty file), then `src/threatlens/graph/schema.sql`:

```sql
CREATE EXTENSION IF NOT EXISTS vector;

CREATE TABLE IF NOT EXISTS nodes (
    id           text PRIMARY KEY,
    kind         text NOT NULL,
    external_id  text NOT NULL,
    stix_id      text,
    name         text NOT NULL,
    description  text,
    attrs        jsonb NOT NULL DEFAULT '{}'::jsonb,
    source_url   text NOT NULL,
    embedding    vector(384)
);
CREATE UNIQUE INDEX IF NOT EXISTS nodes_kind_extid ON nodes (kind, external_id);
CREATE INDEX IF NOT EXISTS nodes_stix_id ON nodes (stix_id) WHERE stix_id IS NOT NULL;

CREATE TABLE IF NOT EXISTS node_chunks (
    node_id    text NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
    chunk_ix   int  NOT NULL,
    text       text NOT NULL,
    embedding  vector(384) NOT NULL,
    PRIMARY KEY (node_id, chunk_ix)
);

CREATE TABLE IF NOT EXISTS edges (
    src     text NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
    dst     text NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
    kind    text NOT NULL,
    weight  real NOT NULL DEFAULT 1.0,
    source  text NOT NULL,
    attrs   jsonb NOT NULL DEFAULT '{}'::jsonb,
    PRIMARY KEY (src, dst, kind)
);
CREATE INDEX IF NOT EXISTS edges_src_kind ON edges (src, kind);
CREATE INDEX IF NOT EXISTS edges_dst_kind ON edges (dst, kind);

CREATE TABLE IF NOT EXISTS ingest_runs (
    id          serial PRIMARY KEY,
    source      text NOT NULL,
    version     text NOT NULL,
    sha256      text NOT NULL,
    node_count  int NOT NULL,
    edge_count  int NOT NULL,
    ran_at      timestamptz NOT NULL DEFAULT now()
);
```

HNSW indexes on the embedding columns are deliberately omitted — they land in Phase 3 when there is data to index.

- [ ] **Step 7: Write the failing integration test for upsert idempotency**

Create `tests/integration/__init__.py` (empty), then `tests/integration/test_upsert_idempotent.py`:

```python
import os

import pytest
from sqlalchemy import text

from threatlens.graph.store import get_engine, init_schema, upsert_edges, upsert_nodes
from threatlens.models import Edge, Node

pytestmark = [
    pytest.mark.db,
    pytest.mark.skipif(
        not os.getenv("THREATLENS_TEST_DSN"), reason="no THREATLENS_TEST_DSN"
    ),
]

NODES = [
    Node(
        id="technique:T1190",
        kind="technique",
        external_id="T1190",
        name="Exploit Public-Facing Application",
        source_url="https://attack.mitre.org/techniques/T1190",
        description="Adversaries may attempt to exploit...",
        stix_id="attack-pattern--3f886f2a",
        attrs={"is_subtechnique": False},
    ),
    Node(
        id="tactic:TA0001",
        kind="tactic",
        external_id="TA0001",
        name="Initial Access",
        source_url="https://attack.mitre.org/tactics/TA0001",
        attrs={"shortname": "initial-access"},
    ),
]

EDGES = [
    Edge(
        src="technique:T1190",
        dst="tactic:TA0001",
        kind="BELONGS_TO",
        source="attack-stix test",
    )
]


@pytest.fixture(scope="module")
def engine():
    eng = get_engine(os.environ["THREATLENS_TEST_DSN"])
    init_schema(eng)
    return eng


def test_upsert_is_idempotent(engine):
    with engine.begin() as conn:
        conn.execute(text("TRUNCATE nodes CASCADE"))
        upsert_nodes(conn, NODES)
        upsert_edges(conn, EDGES)
        first_nodes = conn.execute(text("SELECT count(*) FROM nodes")).scalar_one()
        first_edges = conn.execute(text("SELECT count(*) FROM edges")).scalar_one()

        upsert_nodes(conn, NODES)
        upsert_edges(conn, EDGES)
        second_nodes = conn.execute(text("SELECT count(*) FROM nodes")).scalar_one()
        second_edges = conn.execute(text("SELECT count(*) FROM edges")).scalar_one()

    assert (first_nodes, first_edges) == (2, 1)
    assert (second_nodes, second_edges) == (2, 1)


def test_upsert_updates_changed_fields(engine):
    with engine.begin() as conn:
        conn.execute(text("TRUNCATE nodes CASCADE"))
        upsert_nodes(conn, NODES)
        renamed = [
            Node(
                id="technique:T1190",
                kind="technique",
                external_id="T1190",
                name="RENAMED",
                source_url="https://attack.mitre.org/techniques/T1190",
            )
        ]
        upsert_nodes(conn, renamed)
        name = conn.execute(
            text("SELECT name FROM nodes WHERE id = :i"), {"i": "technique:T1190"}
        ).scalar_one()

    assert name == "RENAMED"


def test_init_schema_is_idempotent(engine):
    init_schema(engine)
    with engine.connect() as conn:
        n = conn.execute(text("SELECT count(*) FROM nodes")).scalar_one()
    assert n >= 0
```

- [ ] **Step 8: Run the test to verify it fails**

```bash
docker compose up -d db
export THREATLENS_TEST_DSN="postgresql+psycopg://threatlens:threatlens@localhost:5432/threatlens_test"
uv run pytest tests/integration/test_upsert_idempotent.py -v
```

Expected: FAIL with `ModuleNotFoundError: No module named 'threatlens.graph.store'`

- [ ] **Step 9: Write store.py**

Create `src/threatlens/graph/store.py`:

```python
"""The only module in the project that contains SQL."""

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


def get_engine(url: str | None = None) -> Engine:
    """Build an Engine. Pass a URL explicitly in tests; production reads config."""
    if url is None:
        from threatlens.config import get_settings

        url = get_settings().database_url
    return create_engine(url, future=True)


def init_schema(engine: Engine) -> None:
    """Apply schema.sql. Idempotent — every statement is IF NOT EXISTS."""
    sql = resources.files("threatlens.graph").joinpath("schema.sql").read_text()
    with engine.begin() as conn:
        for statement in _split_statements(sql):
            conn.execute(text(statement))


def _split_statements(sql: str) -> list[str]:
    return [s.strip() for s in sql.split(";") if s.strip()]


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
    raise NotImplementedError("Track A")


def node_counts(conn: Connection) -> dict[str, int]:
    raise NotImplementedError("Track A")


def edge_counts(conn: Connection) -> dict[str, int]:
    raise NotImplementedError("Track A")


def get_node(conn: Connection, node_id: str) -> Node | None:
    raise NotImplementedError("Track A")


def neighbors(conn: Connection, node_id: str, kinds: list[str]) -> list[tuple[Edge, Node]]:
    raise NotImplementedError("Track A")
```

- [ ] **Step 10: Make schema.sql ship inside the package**

Modify `pyproject.toml`, appending to the existing `[tool.hatch.build.targets.wheel]` section:

```toml
[tool.hatch.build.targets.wheel]
packages = ["src/threatlens"]

[tool.hatch.build.targets.wheel.force-include]
"src/threatlens/graph/schema.sql" = "threatlens/graph/schema.sql"
```

- [ ] **Step 11: Create the remaining package directories**

```bash
touch src/threatlens/ingest/__init__.py src/threatlens/eval/__init__.py
```

- [ ] **Step 12: Run the integration test to verify it passes**

Run: `uv run pytest tests/integration/test_upsert_idempotent.py -v`
Expected: 3 passed

- [ ] **Step 13: Run the whole suite and lint**

```bash
uv run ruff check . && uv run ruff format . && uv run pytest -m "not eval"
```
Expected: all pass

- [ ] **Step 14: Commit and merge to main**

```bash
git add -A
git commit -m "feat(contract): freeze Node/Edge/Graph, schema, and upserts

Shared types and the store API that all four tracks build against. The two
upserts ship working rather than stubbed so the parser track can validate
against a real database from its first integration test. Read helpers raise
NotImplementedError until Track A fills them in."
git push origin contract
```

Open a PR, get CI green, merge to `main`. **Tell the other three it has landed.**

---

# Track A — Foundation

## Task A1: Settings

**Files:**
- Create: `src/threatlens/config.py`
- Create: `tests/unit/test_config.py`

**Interfaces:**
- Consumes: nothing
- Produces: `get_settings() -> Settings` from `threatlens.config`; `Settings` has `database_url: str`, `nvd_api_key: str | None`, `provider: str`, `model: str`, `max_depth: int`, `node_budget: int`, `min_shared_actors: int`, `rrf_k: int`, `rerank_candidates: int`, `evidence_top_n: int`, `max_agent_steps: int`.

- [ ] **Step 1: Write the failing test**

Create `tests/unit/test_config.py`:

```python
import pytest

from threatlens.config import Settings, get_settings


def test_settings_reads_database_url(monkeypatch):
    monkeypatch.setenv("DATABASE_URL", "postgresql+psycopg://u:p@host:5432/db")
    get_settings.cache_clear()
    assert get_settings().database_url == "postgresql+psycopg://u:p@host:5432/db"


def test_settings_defaults(monkeypatch):
    monkeypatch.setenv("DATABASE_URL", "postgresql+psycopg://u:p@host:5432/db")
    monkeypatch.delenv("THREATLENS_PROVIDER", raising=False)
    get_settings.cache_clear()
    s = get_settings()
    assert s.provider == "anthropic"
    assert s.max_depth == 3
    assert s.node_budget == 200
    assert s.min_shared_actors == 3
    assert s.rrf_k == 60


def test_settings_is_frozen(monkeypatch):
    monkeypatch.setenv("DATABASE_URL", "postgresql+psycopg://u:p@host:5432/db")
    get_settings.cache_clear()
    s = get_settings()
    with pytest.raises(Exception):
        s.max_depth = 99


def test_missing_database_url_raises(monkeypatch):
    monkeypatch.delenv("DATABASE_URL", raising=False)
    get_settings.cache_clear()
    with pytest.raises(RuntimeError, match="DATABASE_URL"):
        get_settings()


def test_settings_is_cached(monkeypatch):
    monkeypatch.setenv("DATABASE_URL", "postgresql+psycopg://u:p@host:5432/db")
    get_settings.cache_clear()
    assert get_settings() is get_settings()
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `uv run pytest tests/unit/test_config.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'threatlens.config'`

- [ ] **Step 3: Write config.py**

Create `src/threatlens/config.py`:

```python
"""The only module that reads os.environ. Everything else takes Settings."""

from __future__ import annotations

import os
from dataclasses import dataclass
from functools import lru_cache

from dotenv import load_dotenv


@dataclass(frozen=True)
class Settings:
    database_url: str
    nvd_api_key: str | None = None
    provider: str = "anthropic"
    model: str = "claude-opus-5"
    # retrieval knobs — recorded in eval run metadata so a number is reproducible
    max_depth: int = 3
    node_budget: int = 200
    min_shared_actors: int = 3
    rrf_k: int = 60
    rerank_candidates: int = 50
    evidence_top_n: int = 12
    max_agent_steps: int = 8


def _int_env(name: str, default: int) -> int:
    raw = os.getenv(name)
    return int(raw) if raw else default


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    load_dotenv()
    database_url = os.getenv("DATABASE_URL")
    if not database_url:
        raise RuntimeError("DATABASE_URL is not set. Copy .env.example to .env.")
    return Settings(
        database_url=database_url,
        nvd_api_key=os.getenv("NVD_API_KEY") or None,
        provider=os.getenv("THREATLENS_PROVIDER", "anthropic"),
        model=os.getenv("THREATLENS_MODEL", "claude-opus-5"),
        max_depth=_int_env("THREATLENS_MAX_DEPTH", 3),
        node_budget=_int_env("THREATLENS_NODE_BUDGET", 200),
        min_shared_actors=_int_env("THREATLENS_MIN_SHARED_ACTORS", 3),
        rrf_k=_int_env("THREATLENS_RRF_K", 60),
        rerank_candidates=_int_env("THREATLENS_RERANK_CANDIDATES", 50),
        evidence_top_n=_int_env("THREATLENS_EVIDENCE_TOP_N", 12),
        max_agent_steps=_int_env("THREATLENS_MAX_AGENT_STEPS", 8),
    )
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `uv run pytest tests/unit/test_config.py -v`
Expected: 5 passed

- [ ] **Step 5: Commit**

```bash
git add src/threatlens/config.py tests/unit/test_config.py
git commit -m "feat(config): frozen Settings loaded once from env"
```

## Task A2: Store read helpers

**Files:**
- Modify: `src/threatlens/graph/store.py` (replace the five `NotImplementedError` bodies)
- Create: `tests/integration/test_store_reads.py`

**Interfaces:**
- Consumes: `Node`, `Edge` from `threatlens.models`; `get_engine`, `init_schema`, `upsert_nodes`, `upsert_edges` from Task 0
- Produces: `record_ingest_run(conn, source, version, sha256, n_nodes, n_edges) -> int`, `node_counts(conn) -> dict[str, int]`, `edge_counts(conn) -> dict[str, int]`, `get_node(conn, node_id) -> Node | None`, `neighbors(conn, node_id, kinds) -> list[tuple[Edge, Node]]`

- [ ] **Step 1: Write the failing test**

Create `tests/integration/test_store_reads.py`:

```python
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
    pytest.mark.skipif(
        not os.getenv("THREATLENS_TEST_DSN"), reason="no THREATLENS_TEST_DSN"
    ),
]

NODES = [
    Node(
        id="technique:T1190",
        kind="technique",
        external_id="T1190",
        name="Exploit Public-Facing Application",
        source_url="https://attack.mitre.org/techniques/T1190",
        description="desc",
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
    Edge(src="technique:T1190", dst="tactic:TA0001", kind="BELONGS_TO", source="t"),
    Edge(
        src="technique:T1190",
        dst="mitigation:M1030",
        kind="MITIGATED_BY",
        source="t",
        weight=0.5,
    ),
]


@pytest.fixture
def conn():
    eng = get_engine(os.environ["THREATLENS_TEST_DSN"])
    init_schema(eng)
    with eng.begin() as c:
        c.execute(text("TRUNCATE nodes CASCADE"))
        c.execute(text("TRUNCATE ingest_runs"))
        upsert_nodes(c, NODES)
        upsert_edges(c, EDGES)
        yield c


def test_node_counts_by_kind(conn):
    assert node_counts(conn) == {"technique": 1, "tactic": 1, "mitigation": 1}


def test_edge_counts_by_kind(conn):
    assert edge_counts(conn) == {"BELONGS_TO": 1, "MITIGATED_BY": 1}


def test_get_node_roundtrips(conn):
    n = get_node(conn, "technique:T1190")
    assert n is not None
    assert n.name == "Exploit Public-Facing Application"
    assert n.kind == "technique"
    assert n.description == "desc"


def test_get_node_missing_returns_none(conn):
    assert get_node(conn, "technique:T9999") is None


def test_neighbors_filters_by_kind(conn):
    result = neighbors(conn, "technique:T1190", ["BELONGS_TO"])
    assert len(result) == 1
    edge, node = result[0]
    assert edge.kind == "BELONGS_TO"
    assert node.id == "tactic:TA0001"


def test_neighbors_preserves_weight(conn):
    result = neighbors(conn, "technique:T1190", ["MITIGATED_BY"])
    edge, _ = result[0]
    assert edge.weight == pytest.approx(0.5)


def test_record_ingest_run_returns_id(conn):
    run_id = record_ingest_run(conn, "attack-stix", "19.1", "abc123", 3, 2)
    assert isinstance(run_id, int)
    row = conn.execute(
        text("SELECT source, version, sha256 FROM ingest_runs WHERE id = :i"),
        {"i": run_id},
    ).one()
    assert row.source == "attack-stix"
    assert row.version == "19.1"
    assert row.sha256 == "abc123"
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `uv run pytest tests/integration/test_store_reads.py -v`
Expected: FAIL with `NotImplementedError: Track A`

- [ ] **Step 3: Implement the five functions**

In `src/threatlens/graph/store.py`, replace the five stub bodies:

```python
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
            SELECT e.src, e.dst, e.kind AS edge_kind, e.weight, e.source, e.attrs AS edge_attrs,
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
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `uv run pytest tests/integration/test_store_reads.py -v`
Expected: 7 passed

- [ ] **Step 5: Lint and commit**

```bash
uv run ruff check . && uv run ruff format .
git add src/threatlens/graph/store.py tests/integration/test_store_reads.py
git commit -m "feat(graph): store read helpers and ingest run recording"
```

- [ ] **Step 6: Open the PR**

```bash
git push origin track-a-foundation
```

Merge to `main` once CI is green. **Track A merges first** — B and C need it.

---

# Track B — STIX Parser

## Task B1: Fixture bundle and ATT&CK id extraction

**Files:**
- Create: `tests/fixtures/mini-attack-bundle.json`
- Create: `src/threatlens/ingest/attack.py`
- Create: `tests/unit/test_stix_parse.py`

**Interfaces:**
- Consumes: `Node`, `Edge`, `Graph` from `threatlens.models`
- Produces: `parse_bundle(path: Path) -> Graph` from `threatlens.ingest.attack`

- [ ] **Step 1: Add the stix2 dependency**

```bash
uv add stix2
```

- [ ] **Step 2: Build the fixture bundle**

Create `tests/fixtures/mini-attack-bundle.json`:

```json
{
  "type": "bundle",
  "id": "bundle--test-0001",
  "objects": [
    {
      "type": "x-mitre-collection",
      "id": "x-mitre-collection--test",
      "name": "Enterprise ATT&CK",
      "x_mitre_version": "19.1"
    },
    {
      "type": "x-mitre-tactic",
      "id": "x-mitre-tactic--ta0001",
      "name": "Initial Access",
      "description": "The adversary is trying to get into your network.",
      "x_mitre_shortname": "initial-access",
      "external_references": [
        {"source_name": "mitre-attack", "external_id": "TA0001",
         "url": "https://attack.mitre.org/tactics/TA0001"}
      ]
    },
    {
      "type": "x-mitre-tactic",
      "id": "x-mitre-tactic--ta0002",
      "name": "Execution",
      "description": "The adversary is trying to run malicious code.",
      "x_mitre_shortname": "execution",
      "external_references": [
        {"source_name": "mitre-attack", "external_id": "TA0002",
         "url": "https://attack.mitre.org/tactics/TA0002"}
      ]
    },
    {
      "type": "attack-pattern",
      "id": "attack-pattern--t1190",
      "name": "Exploit Public-Facing Application",
      "description": "Adversaries may attempt to exploit a weakness.",
      "x_mitre_is_subtechnique": false,
      "kill_chain_phases": [
        {"kill_chain_name": "mitre-attack", "phase_name": "initial-access"}
      ],
      "external_references": [
        {"source_name": "mitre-attack", "external_id": "T1190",
         "url": "https://attack.mitre.org/techniques/T1190"}
      ]
    },
    {
      "type": "attack-pattern",
      "id": "attack-pattern--t1059",
      "name": "Command and Scripting Interpreter",
      "description": "Adversaries may abuse command interpreters.",
      "x_mitre_is_subtechnique": false,
      "kill_chain_phases": [
        {"kill_chain_name": "mitre-attack", "phase_name": "execution"},
        {"kill_chain_name": "mitre-attack", "phase_name": "initial-access"}
      ],
      "external_references": [
        {"source_name": "mitre-attack", "external_id": "T1059",
         "url": "https://attack.mitre.org/techniques/T1059"}
      ]
    },
    {
      "type": "attack-pattern",
      "id": "attack-pattern--t1059-001",
      "name": "PowerShell",
      "description": "Adversaries may abuse PowerShell commands.",
      "x_mitre_is_subtechnique": true,
      "kill_chain_phases": [
        {"kill_chain_name": "mitre-attack", "phase_name": "execution"}
      ],
      "external_references": [
        {"source_name": "mitre-attack", "external_id": "T1059.001",
         "url": "https://attack.mitre.org/techniques/T1059/001"}
      ]
    },
    {
      "type": "attack-pattern",
      "id": "attack-pattern--revoked",
      "name": "Revoked Technique",
      "revoked": true,
      "kill_chain_phases": [
        {"kill_chain_name": "mitre-attack", "phase_name": "execution"}
      ],
      "external_references": [
        {"source_name": "mitre-attack", "external_id": "T9998",
         "url": "https://attack.mitre.org/techniques/T9998"}
      ]
    },
    {
      "type": "attack-pattern",
      "id": "attack-pattern--deprecated",
      "name": "Deprecated Technique",
      "x_mitre_deprecated": true,
      "kill_chain_phases": [
        {"kill_chain_name": "mitre-attack", "phase_name": "execution"}
      ],
      "external_references": [
        {"source_name": "mitre-attack", "external_id": "T9999",
         "url": "https://attack.mitre.org/techniques/T9999"}
      ]
    },
    {
      "type": "course-of-action",
      "id": "course-of-action--m1030",
      "name": "Network Segmentation",
      "description": "Architect sections of the network.",
      "external_references": [
        {"source_name": "mitre-attack", "external_id": "M1030",
         "url": "https://attack.mitre.org/mitigations/M1030"}
      ]
    },
    {
      "type": "intrusion-set",
      "id": "intrusion-set--g0016",
      "name": "APT29",
      "description": "APT29 is a threat group.",
      "external_references": [
        {"source_name": "mitre-attack", "external_id": "G0016",
         "url": "https://attack.mitre.org/groups/G0016"}
      ]
    },
    {
      "type": "malware",
      "id": "malware--s0154",
      "name": "Cobalt Strike",
      "description": "Cobalt Strike is a commercial tool.",
      "external_references": [
        {"source_name": "mitre-attack", "external_id": "S0154",
         "url": "https://attack.mitre.org/software/S0154"}
      ]
    },
    {
      "type": "relationship",
      "id": "relationship--r1",
      "relationship_type": "mitigates",
      "source_ref": "course-of-action--m1030",
      "target_ref": "attack-pattern--t1190"
    },
    {
      "type": "relationship",
      "id": "relationship--r2",
      "relationship_type": "uses",
      "source_ref": "intrusion-set--g0016",
      "target_ref": "attack-pattern--t1190"
    },
    {
      "type": "relationship",
      "id": "relationship--r3",
      "relationship_type": "uses",
      "source_ref": "intrusion-set--g0016",
      "target_ref": "malware--s0154"
    },
    {
      "type": "relationship",
      "id": "relationship--r4",
      "relationship_type": "subtechnique-of",
      "source_ref": "attack-pattern--t1059-001",
      "target_ref": "attack-pattern--t1059"
    },
    {
      "type": "relationship",
      "id": "relationship--r5",
      "relationship_type": "uses",
      "source_ref": "intrusion-set--g0016",
      "target_ref": "attack-pattern--revoked"
    }
  ]
}
```

Expected output: 9 nodes (2 tactics, 3 techniques, 1 mitigation, 1 actor, 1 software — note `T9998` and `T9999` are excluded), and 4 kept relationships plus 4 `BELONGS_TO` edges. `relationship--r5` points at a revoked object and must be dropped.

- [ ] **Step 3: Write the failing tests**

Create `tests/unit/test_stix_parse.py`:

```python
from pathlib import Path

import pytest

from threatlens.ingest.attack import parse_bundle

FIXTURE = Path(__file__).parent.parent / "fixtures" / "mini-attack-bundle.json"


@pytest.fixture(scope="module")
def graph():
    return parse_bundle(FIXTURE)


def _ids(graph) -> set[str]:
    return {n.id for n in graph.nodes}


def test_attack_id_comes_from_external_references(graph):
    assert "technique:T1190" in _ids(graph)


def test_source_url_comes_from_external_references(graph):
    node = next(n for n in graph.nodes if n.id == "technique:T1190")
    assert node.source_url == "https://attack.mitre.org/techniques/T1190"


def test_revoked_objects_are_skipped(graph):
    assert "technique:T9998" not in _ids(graph)


def test_deprecated_objects_are_skipped(graph):
    assert "technique:T9999" not in _ids(graph)


def test_skipped_count_is_reported(graph):
    assert graph.skipped >= 2


def test_belongs_to_comes_from_kill_chain_phases(graph):
    edges = [e for e in graph.edges if e.kind == "BELONGS_TO"]
    pairs = {(e.src, e.dst) for e in edges}
    assert ("technique:T1190", "tactic:TA0001") in pairs


def test_technique_in_two_tactics_yields_two_edges(graph):
    edges = [
        e for e in graph.edges if e.kind == "BELONGS_TO" and e.src == "technique:T1059"
    ]
    assert {e.dst for e in edges} == {"tactic:TA0001", "tactic:TA0002"}


def test_every_technique_has_a_tactic(graph):
    techniques = {n.id for n in graph.nodes if n.kind == "technique"}
    with_tactic = {e.src for e in graph.edges if e.kind == "BELONGS_TO"}
    assert techniques == with_tactic


def test_subtechnique_keeps_dotted_id(graph):
    assert "technique:T1059.001" in _ids(graph)


def test_subtechnique_of_edge_direction(graph):
    edges = [e for e in graph.edges if e.kind == "SUBTECHNIQUE_OF"]
    assert ("technique:T1059.001", "technique:T1059") in {(e.src, e.dst) for e in edges}


def test_mitigates_is_reversed_to_mitigated_by(graph):
    edges = [e for e in graph.edges if e.kind == "MITIGATED_BY"]
    assert ("technique:T1190", "mitigation:M1030") in {(e.src, e.dst) for e in edges}


def test_actor_uses_technique(graph):
    edges = [e for e in graph.edges if e.kind == "USES"]
    assert ("actor:G0016", "technique:T1190") in {(e.src, e.dst) for e in edges}


def test_actor_uses_software_is_a_distinct_kind(graph):
    edges = [e for e in graph.edges if e.kind == "USES_SOFTWARE"]
    assert ("actor:G0016", "software:S0154") in {(e.src, e.dst) for e in edges}


def test_edges_pointing_at_skipped_objects_are_dropped(graph):
    assert all("T9998" not in e.dst and "T9998" not in e.src for e in graph.edges)


def test_no_edge_dangles(graph):
    ids = _ids(graph)
    for e in graph.edges:
        assert e.src in ids, f"dangling src {e.src}"
        assert e.dst in ids, f"dangling dst {e.dst}"


def test_collection_version_is_read(graph):
    assert graph.version == "19.1"


def test_node_kind_mapping(graph):
    kinds = {n.id: n.kind for n in graph.nodes}
    assert kinds["technique:T1190"] == "technique"
    assert kinds["tactic:TA0001"] == "tactic"
    assert kinds["mitigation:M1030"] == "mitigation"
    assert kinds["actor:G0016"] == "actor"
    assert kinds["software:S0154"] == "software"
```

- [ ] **Step 4: Run the tests to verify they fail**

Run: `uv run pytest tests/unit/test_stix_parse.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'threatlens.ingest.attack'`

- [ ] **Step 5: Write the parser**

Create `src/threatlens/ingest/attack.py`:

```python
"""ATT&CK STIX 2.1 bundle -> Graph. Pure: no database, no network.

Four corrections to the source guide live here, each covered by a test:
  D7  ATT&CK ids come from external_references, not off the object
  D8  BELONGS_TO comes from kill_chain_phases — there is no relationship for it
  D9  revoked / x_mitre_deprecated objects are skipped, and their edges dropped
  D10 the collection object carries the ATT&CK version
"""

from __future__ import annotations

import json
import logging
from pathlib import Path

from threatlens.models import Edge, Graph, Node

log = logging.getLogger(__name__)

STIX_KIND = {
    "attack-pattern": "technique",
    "x-mitre-tactic": "tactic",
    "course-of-action": "mitigation",
    "intrusion-set": "actor",
    "malware": "software",
    "tool": "software",
}

RELATIONSHIP_EDGES = {
    # (relationship_type, src_kind, dst_kind): (edge_kind, reverse)
    ("mitigates", "mitigation", "technique"): ("MITIGATED_BY", True),
    ("uses", "actor", "technique"): ("USES", False),
    ("uses", "actor", "software"): ("USES_SOFTWARE", False),
    ("subtechnique-of", "technique", "technique"): ("SUBTECHNIQUE_OF", False),
}


def _attack_ref(obj: dict) -> tuple[str, str] | None:
    """Return (external_id, url) from the mitre-attack external reference."""
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == "mitre-attack" and ref.get("external_id"):
            return ref["external_id"], ref.get("url", "")
    return None


def _is_dead(obj: dict) -> bool:
    return bool(obj.get("revoked") or obj.get("x_mitre_deprecated"))


def parse_bundle(path: Path) -> Graph:
    raw = json.loads(Path(path).read_text(encoding="utf-8"))
    objects = raw["objects"]

    version = "unknown"
    for obj in objects:
        if obj.get("type") == "x-mitre-collection":
            version = obj.get("x_mitre_version", "unknown")
            break

    nodes: dict[str, Node] = {}
    by_stix: dict[str, Node] = {}
    tactic_by_shortname: dict[str, Node] = {}
    skipped = 0

    for obj in objects:
        kind = STIX_KIND.get(obj.get("type", ""))
        if kind is None:
            continue
        if _is_dead(obj):
            skipped += 1
            continue
        ref = _attack_ref(obj)
        if ref is None:
            skipped += 1
            log.warning("no mitre-attack reference on %s", obj.get("id"))
            continue
        external_id, url = ref
        node = Node(
            id=Node.make_id(kind, external_id),
            kind=kind,
            external_id=external_id,
            name=obj.get("name", external_id),
            source_url=url,
            description=obj.get("description"),
            stix_id=obj.get("id"),
            attrs={"is_subtechnique": bool(obj.get("x_mitre_is_subtechnique", False))}
            if kind == "technique"
            else {},
        )
        nodes[node.id] = node
        by_stix[obj["id"]] = node
        if kind == "tactic" and obj.get("x_mitre_shortname"):
            tactic_by_shortname[obj["x_mitre_shortname"]] = node

    source = f"attack-stix v{version}"
    edges: list[Edge] = []

    # D8 — technique -> tactic from kill_chain_phases, not from a relationship object
    for obj in objects:
        if obj.get("type") != "attack-pattern" or _is_dead(obj):
            continue
        node = by_stix.get(obj["id"])
        if node is None:
            continue
        for phase in obj.get("kill_chain_phases", []):
            if phase.get("kill_chain_name") != "mitre-attack":
                continue
            tactic = tactic_by_shortname.get(phase.get("phase_name", ""))
            if tactic is None:
                skipped += 1
                log.warning("unknown tactic shortname %s", phase.get("phase_name"))
                continue
            edges.append(
                Edge(src=node.id, dst=tactic.id, kind="BELONGS_TO", source=source)
            )

    for obj in objects:
        if obj.get("type") != "relationship" or _is_dead(obj):
            continue
        src = by_stix.get(obj.get("source_ref", ""))
        dst = by_stix.get(obj.get("target_ref", ""))
        if src is None or dst is None:
            skipped += 1  # D9 — an endpoint was skipped, so the edge goes too
            continue
        mapping = RELATIONSHIP_EDGES.get((obj["relationship_type"], src.kind, dst.kind))
        if mapping is None:
            continue
        edge_kind, reverse = mapping
        a, b = (dst, src) if reverse else (src, dst)
        edges.append(Edge(src=a.id, dst=b.id, kind=edge_kind, source=source))

    return Graph(
        nodes=list(nodes.values()), edges=edges, version=version, skipped=skipped
    )
```

- [ ] **Step 6: Run the tests to verify they pass**

Run: `uv run pytest tests/unit/test_stix_parse.py -v`
Expected: 17 passed

- [ ] **Step 7: Lint and commit**

```bash
uv run ruff check . && uv run ruff format .
git add src/threatlens/ingest/attack.py tests/unit/test_stix_parse.py tests/fixtures/mini-attack-bundle.json
git commit -m "feat(ingest): parse ATT&CK STIX bundle into Node and Edge records"
```

## Task B2: Golden graph snapshot

**Files:**
- Create: `tests/fixtures/expected_graph.json`
- Modify: `tests/unit/test_stix_parse.py` (append)

**Interfaces:**
- Consumes: `parse_bundle` from Task B1
- Produces: nothing new — a regression gate

- [ ] **Step 1: Write the failing golden test**

Append to `tests/unit/test_stix_parse.py`:

```python
import json as _json

EXPECTED = Path(__file__).parent.parent / "fixtures" / "expected_graph.json"


def test_golden_graph_matches(graph):
    """Regression gate. Update expected_graph.json deliberately, never to pass a test."""
    expected = _json.loads(EXPECTED.read_text(encoding="utf-8"))
    actual = {
        "version": graph.version,
        "nodes": sorted(f"{n.id}|{n.kind}|{n.name}" for n in graph.nodes),
        "edges": sorted(f"{e.src}|{e.kind}|{e.dst}" for e in graph.edges),
    }
    assert actual["version"] == expected["version"]
    assert actual["nodes"] == expected["nodes"]
    assert actual["edges"] == expected["edges"]
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `uv run pytest tests/unit/test_stix_parse.py::test_golden_graph_matches -v`
Expected: FAIL with `FileNotFoundError: ...expected_graph.json`

- [ ] **Step 3: Generate the golden file, then read it before trusting it**

```bash
uv run python -c "
import json
from pathlib import Path
from threatlens.ingest.attack import parse_bundle
g = parse_bundle(Path('tests/fixtures/mini-attack-bundle.json'))
out = {
    'version': g.version,
    'nodes': sorted(f'{n.id}|{n.kind}|{n.name}' for n in g.nodes),
    'edges': sorted(f'{e.src}|{e.kind}|{e.dst}' for e in g.edges),
}
Path('tests/fixtures/expected_graph.json').write_text(json.dumps(out, indent=2) + '\n')
print(json.dumps(out, indent=2))
"
```

**Read the printed output before committing it.** Confirm by eye: 9 nodes, no `T9998`/`T9999`, `T1059` has two `BELONGS_TO` edges, `MITIGATED_BY` runs technique→mitigation, and there is no edge touching the revoked technique. A golden file generated from a buggy parser locks the bug in permanently.

- [ ] **Step 4: Run the test to verify it passes**

Run: `uv run pytest tests/unit/test_stix_parse.py -v`
Expected: 18 passed

- [ ] **Step 5: Commit**

```bash
git add tests/fixtures/expected_graph.json tests/unit/test_stix_parse.py
git commit -m "test(ingest): golden graph snapshot for the fixture bundle"
```

## Task B3: Ingest the real bundle into Postgres

**Files:**
- Create: `src/threatlens/ingest/__main__.py`
- Create: `tests/integration/test_ingest_attack.py`

**Interfaces:**
- Consumes: `parse_bundle` (B1); `get_engine`, `init_schema`, `upsert_nodes`, `upsert_edges`, `record_ingest_run`, `node_counts` from `threatlens.graph.store`
- Produces: `ingest_attack(path: Path, sha256: str, conn) -> tuple[int, int]` from `threatlens.ingest.attack`

- [ ] **Step 1: Write the failing test**

Create `tests/integration/test_ingest_attack.py`:

```python
import os
from pathlib import Path

import pytest
from sqlalchemy import text

from threatlens.graph.store import get_engine, init_schema, node_counts
from threatlens.ingest.attack import ingest_attack

pytestmark = [
    pytest.mark.db,
    pytest.mark.skipif(
        not os.getenv("THREATLENS_TEST_DSN"), reason="no THREATLENS_TEST_DSN"
    ),
]

FIXTURE = Path(__file__).parent.parent / "fixtures" / "mini-attack-bundle.json"


@pytest.fixture
def conn():
    eng = get_engine(os.environ["THREATLENS_TEST_DSN"])
    init_schema(eng)
    with eng.begin() as c:
        c.execute(text("TRUNCATE nodes CASCADE"))
        c.execute(text("TRUNCATE ingest_runs"))
        yield c


def test_ingest_loads_nodes_and_edges(conn):
    n_nodes, n_edges = ingest_attack(FIXTURE, "deadbeef", conn)
    assert n_nodes == 9
    assert n_edges > 0
    assert node_counts(conn)["technique"] == 3


def test_ingest_is_idempotent(conn):
    ingest_attack(FIXTURE, "deadbeef", conn)
    first = conn.execute(text("SELECT count(*) FROM nodes")).scalar_one()
    ingest_attack(FIXTURE, "deadbeef", conn)
    second = conn.execute(text("SELECT count(*) FROM nodes")).scalar_one()
    assert first == second


def test_ingest_records_the_run(conn):
    ingest_attack(FIXTURE, "deadbeef", conn)
    row = conn.execute(
        text("SELECT source, version, sha256 FROM ingest_runs ORDER BY id DESC LIMIT 1")
    ).one()
    assert row.version == "19.1"
    assert row.sha256 == "deadbeef"
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `uv run pytest tests/integration/test_ingest_attack.py -v`
Expected: FAIL with `ImportError: cannot import name 'ingest_attack'`

- [ ] **Step 3: Add ingest_attack to attack.py**

Append to `src/threatlens/ingest/attack.py`:

```python
def ingest_attack(path: Path, sha256: str, conn) -> tuple[int, int]:
    """Parse the bundle and write it. Returns (node_count, edge_count).

    Nodes go first — edges have foreign keys pointing at them.
    """
    from threatlens.graph.store import record_ingest_run, upsert_edges, upsert_nodes

    graph = parse_bundle(path)
    n_nodes = upsert_nodes(conn, graph.nodes)
    n_edges = upsert_edges(conn, graph.edges)
    record_ingest_run(conn, "attack-stix", graph.version, sha256, n_nodes, n_edges)
    if graph.skipped:
        log.info("skipped %d objects (revoked, deprecated, or dangling)", graph.skipped)
    return n_nodes, n_edges
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `uv run pytest tests/integration/test_ingest_attack.py -v`
Expected: 3 passed

- [ ] **Step 5: Lint and commit**

```bash
uv run ruff check . && uv run ruff format .
git add src/threatlens/ingest/attack.py tests/integration/test_ingest_attack.py
git commit -m "feat(ingest): write the parsed ATT&CK graph to Postgres"
```

## Task B4: Verify against the real bundle

**Files:** none created — this is a manual verification gate

- [ ] **Step 1: Fetch the real bundle**

```bash
mkdir -p data/raw
curl -o data/raw/enterprise-attack.json \
  https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json
```

- [ ] **Step 2: Parse it and check the counts**

```bash
uv run python -c "
from pathlib import Path
from collections import Counter
from threatlens.ingest.attack import parse_bundle
g = parse_bundle(Path('data/raw/enterprise-attack.json'))
print('version:', g.version, 'skipped:', g.skipped)
print('nodes:', Counter(n.kind for n in g.nodes))
print('edges:', Counter(e.kind for e in g.edges))
techniques = {n.id for n in g.nodes if n.kind == 'technique'}
with_tactic = {e.src for e in g.edges if e.kind == 'BELONGS_TO'}
print('techniques without a tactic:', len(techniques - with_tactic))
ids = {n.id for n in g.nodes}
print('dangling edges:', sum(1 for e in g.edges if e.src not in ids or e.dst not in ids))
"
```

Expected, order of magnitude: ~650 techniques, **exactly 14 tactics**, ~45 mitigations, ~170 actors, ~750 software. `techniques without a tactic: 0` and `dangling edges: 0` are hard requirements — a non-zero value on either means the parser is wrong.

- [ ] **Step 3: Spot-check five entries by hand**

Open https://attack.mitre.org/techniques/T1190 and compare name, description, tactic, and mitigations against:

```bash
uv run python -c "
from pathlib import Path
from threatlens.ingest.attack import parse_bundle
g = parse_bundle(Path('data/raw/enterprise-attack.json'))
n = next(x for x in g.nodes if x.id == 'technique:T1190')
print(n.name); print(n.source_url); print((n.description or '')[:200])
print([e.dst for e in g.edges if e.src == n.id])
"
```

Repeat for `T1059.001` (sub-technique), `M1030` (mitigation), `G0016` (actor), and one technique that appears in two tactics.

- [ ] **Step 4: Record the result in the phase doc**

Update the status line in `.claude/phases/phase-1-attack-ingestion.md` to `verified` and note the ATT&CK version you built against.

```bash
git add .claude/phases/phase-1-attack-ingestion.md
git commit -m "docs(phase-1): record verified ATT&CK version and counts"
git push origin track-b-stix-parser
```

---

# Track C — CLI and Fetch

## Task C1: Snapshot fetching with a manifest

**Files:**
- Create: `src/threatlens/ingest/fetch.py`
- Create: `tests/unit/test_fetch.py`

**Interfaces:**
- Consumes: nothing
- Produces: `sha256_file(path: Path) -> str`, `update_manifest(manifest_path: Path, key: str, entry: dict) -> dict`, `fetch_url(url: str, dest: Path, force: bool = False) -> dict` from `threatlens.ingest.fetch`

- [ ] **Step 1: Add dependencies**

```bash
uv add httpx tenacity
```

- [ ] **Step 2: Write the failing test**

Create `tests/unit/test_fetch.py`:

```python
import hashlib
import json

import pytest

from threatlens.ingest.fetch import sha256_file, update_manifest


def test_sha256_matches_hashlib(tmp_path):
    f = tmp_path / "x.json"
    f.write_bytes(b'{"a": 1}')
    assert sha256_file(f) == hashlib.sha256(b'{"a": 1}').hexdigest()


def test_update_manifest_creates_file(tmp_path):
    m = tmp_path / "manifest.json"
    entry = {"url": "https://example/x.json", "sha256": "abc", "version": "19.1"}
    result = update_manifest(m, "x.json", entry)
    assert result["x.json"]["sha256"] == "abc"
    assert json.loads(m.read_text())["x.json"]["url"] == "https://example/x.json"


def test_update_manifest_preserves_other_entries(tmp_path):
    m = tmp_path / "manifest.json"
    update_manifest(m, "a.json", {"sha256": "1"})
    update_manifest(m, "b.json", {"sha256": "2"})
    data = json.loads(m.read_text())
    assert set(data) == {"a.json", "b.json"}


def test_update_manifest_stamps_fetched_at(tmp_path):
    m = tmp_path / "manifest.json"
    result = update_manifest(m, "a.json", {"sha256": "1"})
    assert "fetched_at" in result["a.json"]


def test_fetch_refuses_to_overwrite_without_force(tmp_path):
    from threatlens.ingest.fetch import fetch_url

    dest = tmp_path / "existing.json"
    dest.write_text("{}")
    with pytest.raises(FileExistsError, match="--force"):
        fetch_url("https://example/x.json", dest, force=False)
```

- [ ] **Step 3: Run the test to verify it fails**

Run: `uv run pytest tests/unit/test_fetch.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'threatlens.ingest.fetch'`

- [ ] **Step 4: Write fetch.py**

Create `src/threatlens/ingest/fetch.py`:

```python
"""Download snapshots and record their provenance.

Query-time code must never call these. Snapshots are fetched once and pinned —
a graph that shifts mid-project invalidates every measured number.
"""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path

import httpx

ATTACK_URL = (
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/"
    "master/enterprise-attack/enterprise-attack.json"
)


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for block in iter(lambda: fh.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def update_manifest(manifest_path: Path, key: str, entry: dict) -> dict:
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    data: dict = {}
    if manifest_path.exists():
        data = json.loads(manifest_path.read_text(encoding="utf-8"))
    data[key] = {**entry, "fetched_at": datetime.now(UTC).isoformat()}
    manifest_path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n")
    return data


def fetch_url(url: str, dest: Path, force: bool = False) -> dict:
    """Download to dest and return the manifest entry.

    Refuses to overwrite an existing snapshot without force — re-fetching mid-project
    silently changes the graph under the eval set.
    """
    if dest.exists() and not force:
        raise FileExistsError(f"{dest} already exists; pass --force to re-download")
    dest.parent.mkdir(parents=True, exist_ok=True)
    with httpx.stream("GET", url, follow_redirects=True, timeout=120.0) as response:
        response.raise_for_status()
        with open(dest, "wb") as fh:
            for chunk in response.iter_bytes():
                fh.write(chunk)
    return {"url": url, "sha256": sha256_file(dest), "bytes": dest.stat().st_size}
```

- [ ] **Step 5: Run the test to verify it passes**

Run: `uv run pytest tests/unit/test_fetch.py -v`
Expected: 5 passed

- [ ] **Step 6: Commit**

```bash
uv run ruff check . && uv run ruff format .
git add src/threatlens/ingest/fetch.py tests/unit/test_fetch.py
git commit -m "feat(ingest): snapshot fetching with sha256 manifest"
```

## Task C2: CLI skeleton

**Files:**
- Create: `src/threatlens/cli.py`
- Create: `tests/unit/test_cli_smoke.py`

**Interfaces:**
- Consumes: `fetch_url`, `update_manifest`, `ATTACK_URL` (C1); `get_engine`, `init_schema` (Task 0)
- Produces: `app` — a `typer.Typer` instance exported as the `threatlens` console script

- [ ] **Step 1: Write the failing test**

Create `tests/unit/test_cli_smoke.py`:

```python
from typer.testing import CliRunner

from threatlens.cli import app

runner = CliRunner()


def test_root_help():
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    assert "threatlens" in result.output.lower()


def test_db_help():
    assert runner.invoke(app, ["db", "--help"]).exit_code == 0


def test_fetch_help():
    assert runner.invoke(app, ["fetch", "--help"]).exit_code == 0


def test_ingest_help():
    assert runner.invoke(app, ["ingest", "--help"]).exit_code == 0


def test_stats_help():
    assert runner.invoke(app, ["stats", "--help"]).exit_code == 0


def test_show_help():
    assert runner.invoke(app, ["show", "--help"]).exit_code == 0
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `uv run pytest tests/unit/test_cli_smoke.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'threatlens.cli'`

- [ ] **Step 3: Write cli.py**

Create `src/threatlens/cli.py`:

```python
"""Typer entrypoint. Wiring only — logic belongs in the modules this calls."""

from __future__ import annotations

import logging
from pathlib import Path

import typer

app = typer.Typer(help="threatlens — a Graph-RAG threat-intelligence agent", no_args_is_help=True)
db_app = typer.Typer(help="Database management", no_args_is_help=True)
fetch_app = typer.Typer(help="Download data snapshots", no_args_is_help=True)
ingest_app = typer.Typer(help="Load snapshots into the graph", no_args_is_help=True)

app.add_typer(db_app, name="db")
app.add_typer(fetch_app, name="fetch")
app.add_typer(ingest_app, name="ingest")

DATA_RAW = Path("data/raw")
MANIFEST = Path("data/manifest.json")


@app.callback()
def main(verbose: bool = typer.Option(False, "--verbose", "-v")) -> None:
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO,
        format="%(levelname)s %(name)s %(message)s",
    )


@db_app.command("init")
def db_init() -> None:
    """Apply the schema to the configured database."""
    from threatlens.graph.store import get_engine, init_schema

    init_schema(get_engine())
    typer.echo("schema applied")


@fetch_app.command("attack")
def fetch_attack(force: bool = typer.Option(False, "--force")) -> None:
    """Download the MITRE ATT&CK Enterprise STIX bundle."""
    from threatlens.ingest.fetch import ATTACK_URL, fetch_url, update_manifest

    dest = DATA_RAW / "enterprise-attack.json"
    try:
        entry = fetch_url(ATTACK_URL, dest, force=force)
    except FileExistsError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=1) from exc
    update_manifest(MANIFEST, dest.name, entry)
    typer.echo(f"{dest}  sha256={entry['sha256'][:12]}...  {entry['bytes']} bytes")


@ingest_app.command("attack")
def ingest_attack_cmd() -> None:
    """Parse the ATT&CK snapshot and load it into the graph."""
    import json

    from threatlens.graph.store import get_engine
    from threatlens.ingest.attack import ingest_attack

    path = DATA_RAW / "enterprise-attack.json"
    if not path.exists():
        typer.echo("snapshot missing — run: threatlens fetch attack", err=True)
        raise typer.Exit(code=1)
    sha = json.loads(MANIFEST.read_text())[path.name]["sha256"] if MANIFEST.exists() else ""
    with get_engine().begin() as conn:
        n_nodes, n_edges = ingest_attack(path, sha, conn)
    typer.echo(f"ingested {n_nodes} nodes, {n_edges} edges")


@app.command("stats")
def stats() -> None:
    """Print node and edge counts by kind."""
    from threatlens.graph.store import edge_counts, get_engine, node_counts

    with get_engine().connect() as conn:
        nodes = node_counts(conn)
        edges = edge_counts(conn)
    typer.echo("nodes:")
    for kind, n in sorted(nodes.items()):
        typer.echo(f"  {kind:<12} {n:>6}")
    typer.echo("edges:")
    for kind, n in sorted(edges.items()):
        typer.echo(f"  {kind:<16} {n:>6}")


@app.command("show")
def show(node_id: str = typer.Argument(..., help="e.g. T1190 or technique:T1190")) -> None:
    """Print one node with its outgoing edges."""
    from threatlens.graph.store import get_engine, get_node, neighbors

    resolved = node_id if ":" in node_id else _guess_id(node_id)
    with get_engine().connect() as conn:
        node = get_node(conn, resolved)
        if node is None:
            typer.echo(f"not found: {resolved}", err=True)
            raise typer.Exit(code=1)
        typer.echo(f"{node.id}  {node.name}")
        typer.echo(node.source_url)
        if node.description:
            typer.echo(f"\n{node.description[:400]}")
        rows = neighbors(
            conn, node.id, ["BELONGS_TO", "MITIGATED_BY", "SUBTECHNIQUE_OF", "CHAINS_TO"]
        )
    if rows:
        typer.echo("\nedges:")
        for edge, target in rows:
            typer.echo(f"  --{edge.kind}--> {target.id}  {target.name}")


def _guess_id(external_id: str) -> str:
    """Resolve a bare external id to a node id.

    Order matters: TA0001 is a tactic, and a bare `T` prefix check would claim it
    as a technique first.
    """
    upper = external_id.upper()
    if upper.startswith("CVE-"):
        return f"cve:{external_id}"
    if upper.startswith("TA"):
        return f"tactic:{external_id}"
    kind = {"T": "technique", "M": "mitigation", "G": "actor", "S": "software"}.get(upper[0])
    return f"{kind or 'technique'}:{external_id}"
```

- [ ] **Step 4: Add the id-resolution test**

Append to `tests/unit/test_cli_smoke.py`:

```python
def test_guess_id_prefixes():
    from threatlens.cli import _guess_id

    assert _guess_id("T1190") == "technique:T1190"
    assert _guess_id("TA0001") == "tactic:TA0001"
    assert _guess_id("M1030") == "mitigation:M1030"
    assert _guess_id("G0016") == "actor:G0016"
    assert _guess_id("S0154") == "software:S0154"
    assert _guess_id("CVE-2021-44228") == "cve:CVE-2021-44228"
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `uv run pytest tests/unit/test_cli_smoke.py -v`
Expected: 7 passed

- [ ] **Step 6: Verify the console script resolves**

Run: `uv run threatlens --help`
Expected: the command list prints, exit code 0

- [ ] **Step 7: Commit**

```bash
uv run ruff check . && uv run ruff format .
git add src/threatlens/cli.py tests/unit/test_cli_smoke.py
git commit -m "feat(cli): db init, fetch, ingest, stats, and show commands"
```

## Task C3: End-to-end CLI check

**Files:** none created — an integration gate. Requires Tracks A and B merged.

- [ ] **Step 1: Run the full path on a clean database**

```bash
docker compose up -d db
uv run threatlens db init
uv run threatlens fetch attack
uv run threatlens ingest attack
uv run threatlens stats
uv run threatlens show T1190
uv run threatlens show TA0001
```

Expected: `stats` prints ~650 techniques and exactly 14 tactics; `show T1190` prints the name, the MITRE URL, and at least one `BELONGS_TO` edge.

- [ ] **Step 2: Confirm re-ingestion changes nothing**

```bash
uv run threatlens ingest attack
uv run threatlens stats
```

Expected: identical counts to Step 1.

- [ ] **Step 3: Confirm fetch refuses to clobber**

```bash
uv run threatlens fetch attack
```

Expected: exit code 1 and a message naming `--force`.

- [ ] **Step 4: Commit and push**

```bash
git push origin track-c-cli
```

---

# Track D — Phase 2 Pure Parsers

Independent of everything above. Start immediately.

## Task D1: Rate limiter

**Files:**
- Create: `src/threatlens/ingest/nvd.py`
- Create: `tests/unit/test_nvd_rate_limit.py`

**Interfaces:**
- Consumes: nothing
- Produces: `TokenBucket(rate: int, per_seconds: float, clock=time.monotonic, sleep=time.sleep)` with method `acquire() -> None`, from `threatlens.ingest.nvd`

- [ ] **Step 1: Write the failing test**

Create `tests/unit/test_nvd_rate_limit.py`:

```python
from threatlens.ingest.nvd import TokenBucket


class FakeClock:
    """Injectable clock. Tests must never call time.sleep for real."""

    def __init__(self) -> None:
        self.now = 0.0
        self.slept: list[float] = []

    def time(self) -> float:
        return self.now

    def sleep(self, seconds: float) -> None:
        self.slept.append(seconds)
        self.now += seconds


def test_allows_burst_up_to_rate():
    c = FakeClock()
    b = TokenBucket(rate=5, per_seconds=30.0, clock=c.time, sleep=c.sleep)
    for _ in range(5):
        b.acquire()
    assert c.slept == []


def test_sleeps_when_budget_exhausted():
    c = FakeClock()
    b = TokenBucket(rate=5, per_seconds=30.0, clock=c.time, sleep=c.sleep)
    for _ in range(6):
        b.acquire()
    assert len(c.slept) == 1
    assert c.slept[0] > 0


def test_refills_over_time():
    c = FakeClock()
    b = TokenBucket(rate=5, per_seconds=30.0, clock=c.time, sleep=c.sleep)
    for _ in range(5):
        b.acquire()
    c.now += 30.0
    b.acquire()
    assert c.slept == []
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `uv run pytest tests/unit/test_nvd_rate_limit.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'threatlens.ingest.nvd'`

- [ ] **Step 3: Write the rate limiter**

Create `src/threatlens/ingest/nvd.py`:

```python
"""NVD client and CVE record parsing.

NVD allows 5 requests per 30 seconds without a key, 50 with one. Exceeding it
produces 403 storms that look like outages.
"""

from __future__ import annotations

import time
from collections.abc import Callable

NVD_ENDPOINT = "https://services.nvd.nist.gov/rest/json/cves/2.0"


class TokenBucket:
    def __init__(
        self,
        rate: int,
        per_seconds: float,
        clock: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        self.rate = rate
        self.per_seconds = per_seconds
        self._clock = clock
        self._sleep = sleep
        self._tokens = float(rate)
        self._last = clock()

    def acquire(self) -> None:
        self._refill()
        if self._tokens < 1.0:
            deficit = 1.0 - self._tokens
            wait = deficit * (self.per_seconds / self.rate)
            self._sleep(wait)
            self._refill()
        self._tokens -= 1.0

    def _refill(self) -> None:
        now = self._clock()
        elapsed = now - self._last
        self._last = now
        self._tokens = min(
            float(self.rate), self._tokens + elapsed * (self.rate / self.per_seconds)
        )
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `uv run pytest tests/unit/test_nvd_rate_limit.py -v`
Expected: 3 passed

- [ ] **Step 5: Commit**

```bash
uv run ruff check . && uv run ruff format .
git add src/threatlens/ingest/nvd.py tests/unit/test_nvd_rate_limit.py
git commit -m "feat(ingest): token-bucket rate limiter for the NVD API"
```

## Task D2: CVE record parsing

**Files:**
- Modify: `src/threatlens/ingest/nvd.py` (append)
- Create: `tests/fixtures/nvd-sample.json`
- Create: `tests/unit/test_nvd_parse.py`

**Interfaces:**
- Consumes: `Node` from `threatlens.models`
- Produces: `parse_cve_record(raw: dict) -> Node | None` from `threatlens.ingest.nvd`

- [ ] **Step 1: Create the fixture**

Create `tests/fixtures/nvd-sample.json`:

```json
{
  "vulnerabilities": [
    {
      "cve": {
        "id": "CVE-2021-44228",
        "published": "2021-12-10T10:15:09.143",
        "lastModified": "2023-11-07T03:39:22.803",
        "descriptions": [
          {"lang": "en", "value": "Apache Log4j2 JNDI features do not protect against attacker controlled LDAP."},
          {"lang": "es", "value": "Las caracteristicas JNDI."}
        ],
        "metrics": {
          "cvssMetricV31": [
            {"cvssData": {"baseScore": 10.0, "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"}}
          ]
        },
        "references": [{"url": "https://logging.apache.org/log4j/2.x/security.html"}]
      }
    },
    {
      "cve": {
        "id": "CVE-2024-0001",
        "published": "2024-01-01T00:00:00.000",
        "lastModified": "2024-01-02T00:00:00.000",
        "descriptions": [{"lang": "en", "value": "Only a v4.0 score is published for this one."}],
        "metrics": {
          "cvssMetricV40": [
            {"cvssData": {"baseScore": 7.5, "vectorString": "CVSS:4.0/AV:N/AC:L"}}
          ]
        },
        "references": []
      }
    },
    {
      "cve": {
        "id": "CVE-2024-0002",
        "published": "2024-02-01T00:00:00.000",
        "lastModified": "2024-02-02T00:00:00.000",
        "descriptions": [{"lang": "en", "value": "Awaiting analysis, no score yet."}],
        "metrics": {},
        "references": []
      }
    }
  ]
}
```

- [ ] **Step 2: Write the failing test**

Create `tests/unit/test_nvd_parse.py`:

```python
import json
from pathlib import Path

import pytest

from threatlens.ingest.nvd import parse_cve_record

FIXTURE = Path(__file__).parent.parent / "fixtures" / "nvd-sample.json"


@pytest.fixture(scope="module")
def records():
    raw = json.loads(FIXTURE.read_text(encoding="utf-8"))
    return {v["cve"]["id"]: parse_cve_record(v["cve"]) for v in raw["vulnerabilities"]}


def test_node_id_and_kind(records):
    n = records["CVE-2021-44228"]
    assert n.id == "cve:CVE-2021-44228"
    assert n.kind == "cve"
    assert n.external_id == "CVE-2021-44228"


def test_prefers_english_description(records):
    assert records["CVE-2021-44228"].description.startswith("Apache Log4j2")


def test_cvss_v31_preferred(records):
    assert records["CVE-2021-44228"].attrs["cvss_score"] == pytest.approx(10.0)
    assert records["CVE-2021-44228"].attrs["cvss_version"] == "3.1"


def test_cvss_v40_accepted_when_v31_absent(records):
    assert records["CVE-2024-0001"].attrs["cvss_score"] == pytest.approx(7.5)
    assert records["CVE-2024-0001"].attrs["cvss_version"] == "4.0"


def test_missing_score_is_none_not_zero(records):
    """A fabricated 0.0 severity would surface in an answer as 'no risk'."""
    assert records["CVE-2024-0002"].attrs["cvss_score"] is None
    assert records["CVE-2024-0002"].attrs["cvss_score"] != 0.0


def test_source_url_is_the_nvd_page(records):
    assert records["CVE-2021-44228"].source_url == (
        "https://nvd.nist.gov/vuln/detail/CVE-2021-44228"
    )


def test_published_date_is_kept(records):
    assert records["CVE-2021-44228"].attrs["published"].startswith("2021-12-10")


def test_record_without_id_returns_none():
    assert parse_cve_record({"descriptions": []}) is None
```

- [ ] **Step 3: Run the test to verify it fails**

Run: `uv run pytest tests/unit/test_nvd_parse.py -v`
Expected: FAIL with `ImportError: cannot import name 'parse_cve_record'`

- [ ] **Step 4: Write the parser**

Append to `src/threatlens/ingest/nvd.py`:

```python
from threatlens.models import Node

NVD_DETAIL = "https://nvd.nist.gov/vuln/detail/"


def _english_description(raw: dict) -> str | None:
    for d in raw.get("descriptions", []):
        if d.get("lang") == "en":
            return d.get("value")
    return None


def _cvss(raw: dict) -> tuple[float | None, str | None, str | None]:
    """Return (score, version, vector). Missing is None — never 0.0."""
    metrics = raw.get("metrics", {})
    for key, version in (("cvssMetricV31", "3.1"), ("cvssMetricV40", "4.0")):
        entries = metrics.get(key) or []
        if entries:
            data = entries[0].get("cvssData", {})
            score = data.get("baseScore")
            return (float(score) if score is not None else None, version, data.get("vectorString"))
    return None, None, None


def parse_cve_record(raw: dict) -> Node | None:
    cve_id = raw.get("id")
    if not cve_id:
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
            "published": raw.get("published"),
            "last_modified": raw.get("lastModified"),
            "references": [r.get("url") for r in raw.get("references", []) if r.get("url")],
        },
    )
```

- [ ] **Step 5: Run the test to verify it passes**

Run: `uv run pytest tests/unit/test_nvd_parse.py -v`
Expected: 8 passed

- [ ] **Step 6: Commit**

```bash
uv run ruff check . && uv run ruff format .
git add src/threatlens/ingest/nvd.py tests/unit/test_nvd_parse.py tests/fixtures/nvd-sample.json
git commit -m "feat(ingest): parse NVD CVE records with a strict CVSS fallback chain"
```

## Task D3: Mappings parser

**Files:**
- Create: `src/threatlens/ingest/mappings.py`
- Create: `tests/fixtures/mini-mappings.csv`
- Create: `tests/unit/test_mappings_parse.py`

**Interfaces:**
- Consumes: `Edge` from `threatlens.models`
- Produces: `parse_mappings_csv(path: Path) -> tuple[list[Edge], int]` from `threatlens.ingest.mappings` — returns edges and a count of unparseable rows

- [ ] **Step 1: Create the fixture**

Create `tests/fixtures/mini-mappings.csv`:

```csv
CVE ID,Primary Impact,Secondary Impact,Exploitation Technique,Uncategorized,Phase
CVE-2021-44228,T1059,T1190,,,Exploitation
CVE-2021-34527,T1210,,,,Exploitation
CVE-2020-1472,T1068,T1078,,,Exploitation
CVE-2019-0708,,T1210,,,Exploitation
,T1190,,,,Exploitation
CVE-2024-9999,T9998,,,,Exploitation
```

Row 5 has no CVE id and must be counted as unparseable. Row 6 maps to a technique that will not exist in the graph — the parser still emits the edge; the loader drops it later.

- [ ] **Step 2: Write the failing test**

Create `tests/unit/test_mappings_parse.py`:

```python
from pathlib import Path

import pytest

from threatlens.ingest.mappings import parse_mappings_csv

FIXTURE = Path(__file__).parent.parent / "fixtures" / "mini-mappings.csv"


@pytest.fixture(scope="module")
def parsed():
    return parse_mappings_csv(FIXTURE)


def test_primary_impact_weight_is_one(parsed):
    edges, _ = parsed
    e = next(e for e in edges if e.src == "cve:CVE-2021-44228" and e.dst == "technique:T1059")
    assert e.weight == pytest.approx(1.0)


def test_secondary_impact_weight_is_half(parsed):
    edges, _ = parsed
    e = next(e for e in edges if e.src == "cve:CVE-2021-44228" and e.dst == "technique:T1190")
    assert e.weight == pytest.approx(0.5)


def test_edge_kind_is_enables(parsed):
    edges, _ = parsed
    assert {e.kind for e in edges} == {"ENABLES"}


def test_rows_without_a_cve_id_are_counted_not_crashed(parsed):
    _, skipped = parsed
    assert skipped == 1


def test_secondary_only_row_still_produces_an_edge(parsed):
    edges, _ = parsed
    e = next(e for e in edges if e.src == "cve:CVE-2019-0708")
    assert e.dst == "technique:T1210"
    assert e.weight == pytest.approx(0.5)


def test_unknown_technique_is_still_emitted(parsed):
    """The loader drops unresolvable edges; the parser does not silently swallow them."""
    edges, _ = parsed
    assert any(e.dst == "technique:T9998" for e in edges)


def test_source_is_recorded(parsed):
    edges, _ = parsed
    assert all(e.source for e in edges)
```

- [ ] **Step 3: Run the test to verify it fails**

Run: `uv run pytest tests/unit/test_mappings_parse.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'threatlens.ingest.mappings'`

- [ ] **Step 4: Write the parser**

Create `src/threatlens/ingest/mappings.py`:

```python
"""CVE -> ATT&CK mappings. This file is both the ENABLES edge set and the eval ground truth.

Primary impact carries full weight; secondary impact is a weaker signal at 0.5.
"""

from __future__ import annotations

import csv
import logging
from pathlib import Path

from threatlens.models import Edge, Node

log = logging.getLogger(__name__)

SOURCE = "mappings-explorer"


def parse_mappings_csv(path: Path) -> tuple[list[Edge], int]:
    """Return (edges, skipped_rows). Skipped rows are counted, never silently dropped."""
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
```

- [ ] **Step 5: Run the test to verify it passes**

Run: `uv run pytest tests/unit/test_mappings_parse.py -v`
Expected: 7 passed

- [ ] **Step 6: Commit**

```bash
uv run ruff check . && uv run ruff format .
git add src/threatlens/ingest/mappings.py tests/unit/test_mappings_parse.py tests/fixtures/mini-mappings.csv
git commit -m "feat(ingest): parse CVE to ATT&CK mappings into weighted ENABLES edges"
```

## Task D4: Eval metrics

**Files:**
- Create: `src/threatlens/eval/metrics.py`
- Create: `tests/unit/test_metrics.py`

**Interfaces:**
- Consumes: nothing
- Produces: `recall_at_k(predicted: list[str], gold: set[str], k: int) -> float`, `mrr(predicted: list[str], gold: set[str]) -> float`, `path_correct(path: list[str], expected_kinds: list[str]) -> bool`, `citation_coverage(claims: list[str], evidence_ids: set[str]) -> float` from `threatlens.eval.metrics`

- [ ] **Step 1: Write the failing test**

Create `tests/unit/test_metrics.py`:

```python
import pytest

from threatlens.eval.metrics import citation_coverage, mrr, path_correct, recall_at_k


@pytest.mark.parametrize(
    "predicted,gold,k,expected",
    [
        (["T1190", "T1059"], {"T1190"}, 1, 1.0),
        (["T1059", "T1190"], {"T1190"}, 1, 0.0),
        (["T1059", "T1190"], {"T1190"}, 2, 1.0),
        (["T1059", "T1078", "T1190"], {"T1190"}, 2, 0.0),
        ([], {"T1190"}, 5, 0.0),
        (["T1190"], set(), 1, 0.0),
    ],
)
def test_recall_at_k(predicted, gold, k, expected):
    assert recall_at_k(predicted, gold, k) == pytest.approx(expected)


def test_recall_counts_any_gold_hit():
    assert recall_at_k(["T1059", "T1078"], {"T1190", "T1078"}, 2) == pytest.approx(1.0)


@pytest.mark.parametrize(
    "predicted,gold,expected",
    [
        (["T1190"], {"T1190"}, 1.0),
        (["T1059", "T1190"], {"T1190"}, 0.5),
        (["T1059", "T1078", "T1190"], {"T1190"}, 1 / 3),
        (["T1059"], {"T1190"}, 0.0),
        ([], {"T1190"}, 0.0),
    ],
)
def test_mrr(predicted, gold, expected):
    assert mrr(predicted, gold) == pytest.approx(expected)


def test_path_correct_matches_kind_sequence():
    path = ["cve:CVE-2021-44228", "technique:T1190", "tactic:TA0001"]
    assert path_correct(path, ["cve", "technique", "tactic"]) is True


def test_path_correct_rejects_wrong_order():
    path = ["technique:T1190", "cve:CVE-2021-44228", "tactic:TA0001"]
    assert path_correct(path, ["cve", "technique", "tactic"]) is False


def test_path_correct_rejects_wrong_length():
    assert path_correct(["cve:X"], ["cve", "technique"]) is False


def test_citation_coverage_all_resolvable():
    claims = ["technique:T1190", "mitigation:M1030"]
    assert citation_coverage(claims, {"technique:T1190", "mitigation:M1030"}) == 1.0


def test_citation_coverage_partial():
    claims = ["technique:T1190", "technique:T9999"]
    assert citation_coverage(claims, {"technique:T1190"}) == pytest.approx(0.5)


def test_citation_coverage_of_no_claims_is_one():
    """Nothing asserted means nothing ungrounded."""
    assert citation_coverage([], {"technique:T1190"}) == 1.0
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `uv run pytest tests/unit/test_metrics.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'threatlens.eval.metrics'`

- [ ] **Step 3: Write the metrics**

Create `src/threatlens/eval/metrics.py`:

```python
"""Retrieval and grounding metrics. Pure functions — no pipeline, no LLM, no I/O.

These are deliberately deterministic: every row of the ablation table except
groundedness must be reproducible without an API call.
"""

from __future__ import annotations


def recall_at_k(predicted: list[str], gold: set[str], k: int) -> float:
    """1.0 if any gold item appears in the top k predictions, else 0.0."""
    if not gold:
        return 0.0
    return 1.0 if set(predicted[:k]) & gold else 0.0


def mrr(predicted: list[str], gold: set[str]) -> float:
    """Reciprocal rank of the first correct prediction. 0.0 if none hit."""
    for index, item in enumerate(predicted, start=1):
        if item in gold:
            return 1.0 / index
    return 0.0


def path_correct(path: list[str], expected_kinds: list[str]) -> bool:
    """Did the traversal walk the expected sequence of node kinds?

    Node recall alone does not demonstrate multi-hop retrieval; the path does.
    """
    if len(path) != len(expected_kinds):
        return False
    return all(node_id.split(":", 1)[0] == kind for node_id, kind in zip(path, expected_kinds))


def citation_coverage(claims: list[str], evidence_ids: set[str]) -> float:
    """Fraction of cited node ids that resolve to the evidence set. Target is 1.0."""
    if not claims:
        return 1.0
    return sum(1 for c in claims if c in evidence_ids) / len(claims)
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `uv run pytest tests/unit/test_metrics.py -v`
Expected: 20 passed

- [ ] **Step 5: Commit and push**

```bash
uv run ruff check . && uv run ruff format .
git add src/threatlens/eval/metrics.py tests/unit/test_metrics.py
git commit -m "feat(eval): recall@k, MRR, path correctness, and citation coverage"
git push origin track-d-parsers
```

---

# Final Integration

- [ ] **Step 1: Confirm all four branches are merged**

```bash
git checkout main && git pull
git log --oneline -12
```

- [ ] **Step 2: Run the full suite against a clean database**

```bash
docker compose down -v && docker compose up -d db
export THREATLENS_TEST_DSN="postgresql+psycopg://threatlens:threatlens@localhost:5432/threatlens_test"
uv run ruff check . && uv run ruff format --check . && uv run pytest -m "not eval" -v
```

Expected: everything passes.

- [ ] **Step 3: Rebuild the graph from scratch and record the numbers**

```bash
uv run threatlens db init
uv run threatlens ingest attack
uv run threatlens stats
```

- [ ] **Step 4: Tick the done-when list**

Update `.claude/phases/phase-1-attack-ingestion.md` and the status row in `.claude/phases/phases.md` to `done`, recording the ATT&CK version and the actual counts.

```bash
git add .claude/
git commit -m "docs(phase-1): mark complete with measured node and edge counts"
```

## Phase Done-When

- [ ] `threatlens db init` creates the schema on an empty Postgres
- [ ] `threatlens fetch attack` writes the bundle and a manifest entry with sha256
- [ ] `threatlens ingest attack` loads the graph; a second run changes no counts
- [ ] Counts in range: ~650 techniques, exactly 14 tactics, ~45 mitigations, ~170 actors, ~750 software
- [ ] Every technique has ≥1 `BELONGS_TO` edge
- [ ] No revoked or deprecated object present; no dangling edges
- [ ] 5–10 manual spot checks against attack.mitre.org agree
- [ ] `ingest_runs` has a row with the ATT&CK version and file sha256
- [ ] Track D parsers pass their suites
- [ ] `uv run pytest -m "not eval"` green
