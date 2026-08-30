"""Integration tests for the CVE bridge: ingest_cves + ingest_mappings.

Real Postgres, real fixtures, real upserts. Skipped without THREATLENS_TEST_DSN
so a contributor with no local database can still run the suite.

The property that matters most: idempotency. A second run must change no counts.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest
from sqlalchemy import text

from threatlens.graph.store import (
    get_engine,
    get_node,
    init_schema,
    upsert_nodes,
)
from threatlens.ingest.mappings import ingest_mappings
from threatlens.ingest.nvd import ingest_cves
from threatlens.models import Node

pytestmark = [
    pytest.mark.db,
    pytest.mark.skipif(not os.getenv("THREATLENS_TEST_DSN"), reason="no THREATLENS_TEST_DSN"),
]

NVD_FIXTURE = Path(__file__).parent.parent / "fixtures" / "nvd-sample.json"
MAPPINGS_FIXTURE = Path(__file__).parent.parent / "fixtures" / "mini-mappings.csv"

# Techniques that the mini-mappings fixture references
TECHNIQUE_NODES = [
    Node(
        id="technique:T1059",
        kind="technique",
        external_id="T1059",
        name="Command and Scripting Interpreter",
        source_url="https://attack.mitre.org/techniques/T1059",
    ),
    Node(
        id="technique:T1190",
        kind="technique",
        external_id="T1190",
        name="Exploit Public-Facing Application",
        source_url="https://attack.mitre.org/techniques/T1190",
    ),
    Node(
        id="technique:T1210",
        kind="technique",
        external_id="T1210",
        name="Exploitation of Remote Services",
        source_url="https://attack.mitre.org/techniques/T1210",
    ),
    Node(
        id="technique:T1068",
        kind="technique",
        external_id="T1068",
        name="Exploitation for Privilege Escalation",
        source_url="https://attack.mitre.org/techniques/T1068",
    ),
    Node(
        id="technique:T1078",
        kind="technique",
        external_id="T1078",
        name="Valid Accounts",
        source_url="https://attack.mitre.org/techniques/T1078",
    ),
]


@pytest.fixture(scope="module")
def engine():
    eng = get_engine(os.environ["THREATLENS_TEST_DSN"])
    init_schema(eng)
    return eng


@pytest.fixture
def conn(engine):
    """Clean connection per test. Truncate rather than drop — faster."""
    with engine.begin() as c:
        c.execute(text("TRUNCATE nodes CASCADE"))
        c.execute(text("TRUNCATE ingest_runs"))
        yield c


# --- ingest_cves ------------------------------------------------------------------


def test_ingest_cves_creates_nodes(conn):
    n_nodes, _ = ingest_cves(NVD_FIXTURE, "abc123", conn)
    assert n_nodes == 3


def test_ingest_cves_is_idempotent(conn):
    ingest_cves(NVD_FIXTURE, "abc123", conn)
    ingest_cves(NVD_FIXTURE, "abc123", conn)
    count = conn.execute(text("SELECT count(*) FROM nodes WHERE kind = 'cve'")).scalar_one()
    assert count == 3


def test_ingest_cves_kev_flag(conn):
    kev_ids = {"CVE-2021-44228"}
    ingest_cves(NVD_FIXTURE, "abc123", conn, kev_ids=kev_ids)

    flagged = get_node(conn, "cve:CVE-2021-44228")
    assert flagged is not None
    assert flagged.attrs.get("kev") is True

    unflagged = get_node(conn, "cve:CVE-2024-0001")
    assert unflagged is not None
    assert unflagged.attrs.get("kev") is not True


def test_ingest_cves_kev_flag_round_trips(conn):
    """KEV flag survives upsert → read → upsert → read."""
    kev_ids = {"CVE-2021-44228"}
    ingest_cves(NVD_FIXTURE, "abc123", conn, kev_ids=kev_ids)
    ingest_cves(NVD_FIXTURE, "abc456", conn, kev_ids=kev_ids)

    node = get_node(conn, "cve:CVE-2021-44228")
    assert node.attrs["kev"] is True


# --- ingest_mappings --------------------------------------------------------------


def test_ingest_mappings_creates_edges(conn):
    """Seed techniques and CVEs, then ingest mappings."""
    upsert_nodes(conn, TECHNIQUE_NODES)
    ingest_cves(NVD_FIXTURE, "abc", conn)

    n_edges, dropped = ingest_mappings(MAPPINGS_FIXTURE, "def", conn)
    assert n_edges > 0


def test_ingest_mappings_drops_absent_techniques(conn):
    """T9998 is in the fixture but not in TECHNIQUE_NODES — it must be dropped."""
    upsert_nodes(conn, TECHNIQUE_NODES)
    ingest_cves(NVD_FIXTURE, "abc", conn)

    _, dropped = ingest_mappings(MAPPINGS_FIXTURE, "def", conn)
    assert dropped >= 1


def test_ingest_mappings_is_idempotent(conn):
    upsert_nodes(conn, TECHNIQUE_NODES)
    ingest_cves(NVD_FIXTURE, "abc", conn)

    n1, d1 = ingest_mappings(MAPPINGS_FIXTURE, "def", conn)
    n2, d2 = ingest_mappings(MAPPINGS_FIXTURE, "def", conn)

    edge_count = conn.execute(
        text("SELECT count(*) FROM edges WHERE kind = 'ENABLES'")
    ).scalar_one()
    assert edge_count == n1


# --- full pipeline ----------------------------------------------------------------


def test_full_pipeline(conn):
    """ATT&CK techniques → CVE nodes → ENABLES edges. The whole bridge."""
    upsert_nodes(conn, TECHNIQUE_NODES)
    n_nodes, kev_count = ingest_cves(NVD_FIXTURE, "abc", conn, kev_ids={"CVE-2021-44228"})
    n_edges, dropped = ingest_mappings(MAPPINGS_FIXTURE, "def", conn)

    assert n_nodes == 3
    assert kev_count == 1
    assert n_edges > 0

    # Verify a specific edge exists
    row = conn.execute(
        text(
            "SELECT weight FROM edges "
            "WHERE src = 'cve:CVE-2021-44228' AND dst = 'technique:T1059' AND kind = 'ENABLES'"
        )
    ).one_or_none()
    assert row is not None
    assert row.weight == pytest.approx(1.0)


def test_provenance_is_recorded(conn):
    """Both ingest functions must leave an audit trail in ingest_runs."""
    upsert_nodes(conn, TECHNIQUE_NODES)
    ingest_cves(NVD_FIXTURE, "sha-nvd", conn)
    ingest_mappings(MAPPINGS_FIXTURE, "sha-map", conn)

    runs = conn.execute(text("SELECT source, sha256 FROM ingest_runs ORDER BY id")).fetchall()
    sources = {r.source for r in runs}
    assert "nvd" in sources
    assert "mappings-explorer" in sources
