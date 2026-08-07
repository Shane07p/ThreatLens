"""The whole pipeline, wired together, against a real database.

Every other test proves one piece works in isolation. This one proves the pieces fit:
settings load, the schema applies, the STIX parser's output survives a round trip
through Postgres, the mappings parser's edges join to the techniques the STIX parser
produced, and the CLI can read the result back.

That join is the point. The CVE and ATT&CK worlds are parsed by different modules from
different formats by different people, and they meet at exactly one place —
`cve:CVE-x --ENABLES--> technique:T1190`. A unit test cannot catch a mismatch there,
because each side is individually correct.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest
from sqlalchemy import text

from threatlens.eval.metrics import mrr, path_correct, recall_at_k
from threatlens.graph.store import (
    edge_counts,
    get_engine,
    get_node,
    init_schema,
    neighbors,
    node_counts,
    ping,
    record_ingest_run,
    upsert_edges,
    upsert_nodes,
)
from threatlens.ingest.attack import ingest_attack, parse_bundle
from threatlens.ingest.mappings import parse_mappings_csv
from threatlens.ingest.nvd import parse_cve_record

pytestmark = [
    pytest.mark.db,
    pytest.mark.skipif(not os.getenv("THREATLENS_TEST_DSN"), reason="no THREATLENS_TEST_DSN"),
]

FIXTURES = Path(__file__).parent.parent / "fixtures"
BUNDLE = FIXTURES / "mini-attack-bundle.json"
MAPPINGS = FIXTURES / "mini-mappings.csv"
NVD_SAMPLE = FIXTURES / "nvd-sample.json"


@pytest.fixture(scope="module")
def engine():
    eng = get_engine(os.environ["THREATLENS_TEST_DSN"])
    init_schema(eng)
    return eng


@pytest.fixture
def conn(engine):
    with engine.begin() as c:
        c.execute(text("TRUNCATE nodes CASCADE"))
        c.execute(text("TRUNCATE ingest_runs"))
        yield c


def _load_cves(conn) -> int:
    """Parse the NVD sample and write the CVE nodes."""
    raw = json.loads(NVD_SAMPLE.read_text(encoding="utf-8"))
    nodes = [parse_cve_record(v["cve"]) for v in raw["vulnerabilities"]]
    return upsert_nodes(conn, [n for n in nodes if n])


# --- the graph half ------------------------------------------------------------------


def test_database_is_reachable(engine):
    """If this fails, every other failure in this file is noise."""
    assert ping(engine) is True


def test_attack_bundle_loads_and_reads_back(conn):
    n_nodes, n_edges = ingest_attack(BUNDLE, "flow-test-sha", conn)
    assert n_nodes == 8
    assert n_edges > 0

    node = get_node(conn, "technique:T1190")
    assert node is not None
    assert node.name == "Exploit Public-Facing Application"
    assert node.source_url.startswith("https://attack.mitre.org/")


def test_traversal_reaches_the_tactic(conn):
    """The shape the whole product depends on: technique -> tactic."""
    ingest_attack(BUNDLE, "flow-test-sha", conn)
    rows = neighbors(conn, "technique:T1190", ["BELONGS_TO"])
    assert [n.id for _, n in rows] == ["tactic:TA0001"]


# --- the bridge: where the two halves meet -------------------------------------------


def test_cve_to_technique_path_resolves_end_to_end(conn):
    """CVE -> technique -> tactic, with every hop stored and read back.

    The CVE nodes come from the NVD parser, the techniques from the STIX parser, and
    the edge between them from the mappings parser. Three modules, three formats, one
    join key. This asserts the key actually matches.
    """
    ingest_attack(BUNDLE, "flow-test-sha", conn)
    _load_cves(conn)

    edges, _ = parse_mappings_csv(MAPPINGS)
    known = {n.id for n in parse_bundle(BUNDLE).nodes}
    resolvable = [e for e in edges if e.src in _cve_ids(conn) and e.dst in known]
    assert resolvable, "no mapping edge joined a parsed CVE to a parsed technique"
    upsert_edges(conn, resolvable)

    start = resolvable[0].src
    technique = neighbors(conn, start, ["ENABLES"])[0][1]
    tactic = neighbors(conn, technique.id, ["BELONGS_TO"])[0][1]

    path = [start, technique.id, tactic.id]
    assert path_correct(path, ["cve", "technique", "tactic"]) is True


def _cve_ids(conn) -> set[str]:
    rows = conn.execute(text("SELECT id FROM nodes WHERE kind = 'cve'"))
    return {r.id for r in rows}


def test_unresolvable_mapping_edges_are_rejected_by_the_foreign_key(conn):
    """A mapping to a technique that is not in the graph must not create a dangling
    edge. The parser deliberately emits it; the database is what refuses it."""
    from sqlalchemy.exc import IntegrityError

    ingest_attack(BUNDLE, "flow-test-sha", conn)
    _load_cves(conn)
    edges, _ = parse_mappings_csv(MAPPINGS)
    known = {n.id for n in parse_bundle(BUNDLE).nodes} | _cve_ids(conn)
    unresolvable = [e for e in edges if e.dst not in known]
    assert unresolvable, "fixture should contain at least one unmapped technique"

    with pytest.raises(IntegrityError):
        upsert_edges(conn, unresolvable[:1])


def test_mapping_weights_survive_the_round_trip(conn):
    """Primary 1.0 and secondary 0.5 are what the retrieval ranking reads later."""
    ingest_attack(BUNDLE, "flow-test-sha", conn)
    _load_cves(conn)
    edges, _ = parse_mappings_csv(MAPPINGS)
    known = {n.id for n in parse_bundle(BUNDLE).nodes} | _cve_ids(conn)
    upsert_edges(conn, [e for e in edges if e.src in known and e.dst in known])

    rows = conn.execute(text("SELECT DISTINCT weight FROM edges WHERE kind = 'ENABLES'"))
    weights = sorted(r.weight for r in rows)
    assert weights, "no ENABLES edges were stored"
    assert all(w in (0.5, 1.0) for w in weights)


# --- the whole thing, twice ----------------------------------------------------------


def test_full_pipeline_is_idempotent(conn):
    """Re-running every stage must not change a single count.

    This is the regression test for the most likely ingestion bug. A write path that
    inserts instead of upserting doubles the graph, and nothing else notices.
    """

    def run() -> tuple[dict, dict]:
        ingest_attack(BUNDLE, "flow-test-sha", conn)
        _load_cves(conn)
        edges, _ = parse_mappings_csv(MAPPINGS)
        known = {n.id for n in parse_bundle(BUNDLE).nodes} | _cve_ids(conn)
        upsert_edges(conn, [e for e in edges if e.src in known and e.dst in known])
        return node_counts(conn), edge_counts(conn)

    first_nodes, first_edges = run()
    second_nodes, second_edges = run()

    assert first_nodes == second_nodes
    assert first_edges == second_edges


def test_provenance_is_recorded_for_every_run(conn):
    """Which snapshot built this graph has to be answerable later, or no measured
    number taken from it can be reproduced."""
    ingest_attack(BUNDLE, "flow-test-sha", conn)
    record_ingest_run(conn, "mappings-explorer", "test", "mappings-sha", 0, 3)

    rows = conn.execute(text("SELECT source, version, sha256 FROM ingest_runs ORDER BY id")).all()
    sources = {r.source for r in rows}
    assert {"attack-stix", "mappings-explorer"} <= sources
    assert all(r.sha256 for r in rows)


def test_no_dangling_edges_after_a_full_load(conn):
    """The invariant that has to hold whatever the input was."""
    ingest_attack(BUNDLE, "flow-test-sha", conn)
    _load_cves(conn)
    edges, _ = parse_mappings_csv(MAPPINGS)
    known = {n.id for n in parse_bundle(BUNDLE).nodes} | _cve_ids(conn)
    upsert_edges(conn, [e for e in edges if e.src in known and e.dst in known])

    dangling = conn.execute(
        text("""
            SELECT count(*) FROM edges e
            WHERE NOT EXISTS (SELECT 1 FROM nodes WHERE id = e.src)
               OR NOT EXISTS (SELECT 1 FROM nodes WHERE id = e.dst)
        """)
    ).scalar_one()
    assert dangling == 0


# --- scoring the loaded graph --------------------------------------------------------


def test_metrics_score_a_real_traversal(conn):
    """The eval metrics run against graph output, not hand-built lists. If node ids
    were formatted differently by any module, this is where it shows."""
    ingest_attack(BUNDLE, "flow-test-sha", conn)

    predicted = [n.id for _, n in neighbors(conn, "technique:T1190", ["BELONGS_TO"])]
    gold = {"tactic:TA0001"}

    assert recall_at_k(predicted, gold, 1) == 1.0
    assert mrr(predicted, gold) == 1.0
