"""Hostile input through the CLI, against a real database.

The store-level tests already prove a SQL-shaped id is bound as a parameter. These drive
the same input in through the front door — `threatlens show` and `threatlens path`, as a
user would type it — and check only what an outsider can see: the command refuses the id,
and the tables are still there afterwards. If a future change ever routed an id into a
string-built query on the way in, these would catch it where the store tests could not.
"""

from __future__ import annotations

import os

import pytest
from sqlalchemy import text
from typer.testing import CliRunner

from threatlens.cli import app
from threatlens.config import get_settings
from threatlens.graph.store import get_engine, init_schema, upsert_nodes
from threatlens.models import Node

pytestmark = [
    pytest.mark.db,
    pytest.mark.security,
    pytest.mark.skipif(not os.getenv("THREATLENS_TEST_DSN"), reason="no THREATLENS_TEST_DSN"),
]

HOSTILE = [
    "technique:'; DROP TABLE nodes; --",
    "technique:T1190' OR '1'='1",
    'cve:CVE-2021-44228"; DELETE FROM edges; --',
    "T1190; TRUNCATE nodes CASCADE",
]


@pytest.fixture
def cli_on_test_db(monkeypatch: pytest.MonkeyPatch):
    """Point the CLI at the test database, with one real node to prove the table survives."""
    dsn = os.environ["THREATLENS_TEST_DSN"]
    engine = get_engine(dsn)
    init_schema(engine)
    with engine.begin() as conn:
        conn.execute(text("TRUNCATE nodes CASCADE"))
        upsert_nodes(
            conn,
            [
                Node(
                    id="technique:T1190",
                    kind="technique",
                    external_id="T1190",
                    name="Exploit Public-Facing Application",
                    source_url="u",
                )
            ],
        )
    monkeypatch.setenv("DATABASE_URL", dsn)
    get_settings.cache_clear()
    yield engine
    get_settings.cache_clear()


def node_count(engine) -> int:
    with engine.connect() as conn:
        return conn.execute(text("SELECT count(*) FROM nodes")).scalar_one()


@pytest.mark.parametrize("command", ["show", "path"])
@pytest.mark.parametrize("hostile", HOSTILE)
def test_a_sql_shaped_id_is_refused_and_changes_nothing(cli_on_test_db, command, hostile):
    result = CliRunner().invoke(app, [command, hostile])
    assert result.exit_code == 1, result.output
    assert node_count(cli_on_test_db) == 1


def test_the_real_node_is_still_reachable_afterwards(cli_on_test_db):
    """Proves the fixture's node was there to be destroyed, so the count above means
    something — and that the commands still work after hostile input."""
    for hostile in HOSTILE:
        CliRunner().invoke(app, ["show", hostile])
    result = CliRunner().invoke(app, ["show", "T1190"])
    assert result.exit_code == 0
    assert "Exploit Public-Facing Application" in result.output
