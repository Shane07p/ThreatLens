"""Bounded multi-hop traversal against a real Postgres.

A traversal that quietly stops one hop early, or silently drops the cheapest route when
the budget binds, returns a shorter answer that still looks entirely reasonable. Nothing
downstream can tell the difference. These assertions are what make each of those a
decision rather than an accident.

Graphs here are built inline. The shape under test is the point of each test, and a
reader should not have to open a fixture file to see it.
"""

from __future__ import annotations

import os

import pytest
from sqlalchemy import text

from threatlens.graph.store import get_engine, init_schema, upsert_edges, upsert_nodes
from threatlens.graph.traverse import PATH_EDGE_KINDS, chains, traverse
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


def node(node_id: str, kind: str = "technique") -> Node:
    """Minimal node. The id carries the identity; nothing else matters to a walk."""
    external = node_id.split(":", 1)[1]
    return Node(
        id=node_id,
        kind=kind,
        external_id=external,
        name=f"name of {external}",
        source_url=f"https://example.test/{external}",
    )


def edge(src: str, dst: str, kind: str = "ENABLES", weight: float = 1.0) -> Edge:
    return Edge(src=src, dst=dst, kind=kind, source="test", weight=weight)


def build(conn, nodes: list[Node], edges: list[Edge]) -> None:
    upsert_nodes(conn, nodes)
    upsert_edges(conn, edges)


def ids(hops) -> list[str]:
    return [h.node.id for h in hops]


# --- the basic shape ------------------------------------------------------------------


def test_anchor_is_returned_at_depth_zero(conn):
    build(conn, [node("technique:T1")], [])
    hops = traverse(conn, ["technique:T1"], ["ENABLES"], max_depth=3, node_budget=10)
    assert len(hops) == 1
    assert hops[0].depth == 0
    assert hops[0].path == ("technique:T1",)
    assert hops[0].cost == 0.0


def test_one_hop_reaches_the_neighbour(conn):
    build(conn, [node("cve:C1", "cve"), node("technique:T1")], [edge("cve:C1", "technique:T1")])
    hops = traverse(conn, ["cve:C1"], ["ENABLES"], max_depth=3, node_budget=10)
    assert ids(hops) == ["cve:C1", "technique:T1"]


def test_path_records_the_route_that_reached_the_node(conn):
    build(
        conn,
        [node("cve:C1", "cve"), node("technique:T1"), node("tactic:TA1", "tactic")],
        [edge("cve:C1", "technique:T1"), edge("technique:T1", "tactic:TA1", "BELONGS_TO")],
    )
    hops = traverse(conn, ["cve:C1"], PATH_EDGE_KINDS, max_depth=3, node_budget=10)
    reached = {h.node.id: h for h in hops}
    assert reached["tactic:TA1"].path == ("cve:C1", "technique:T1", "tactic:TA1")
    assert reached["tactic:TA1"].depth == 2


def test_traversal_is_directed(conn):
    """Edges read src -> dst. Walking from the destination must not reach the source."""
    build(conn, [node("cve:C1", "cve"), node("technique:T1")], [edge("cve:C1", "technique:T1")])
    hops = traverse(conn, ["technique:T1"], ["ENABLES"], max_depth=3, node_budget=10)
    assert ids(hops) == ["technique:T1"]


def test_edge_kind_filter_excludes_other_kinds(conn):
    build(
        conn,
        [node("technique:T1"), node("tactic:TA1", "tactic"), node("mitigation:M1", "mitigation")],
        [
            edge("technique:T1", "tactic:TA1", "BELONGS_TO"),
            edge("technique:T1", "mitigation:M1", "MITIGATED_BY"),
        ],
    )
    hops = traverse(conn, ["technique:T1"], ["BELONGS_TO"], max_depth=3, node_budget=10)
    assert ids(hops) == ["technique:T1", "tactic:TA1"]


def test_multiple_anchors_are_walked_together(conn):
    build(
        conn,
        [node("cve:C1", "cve"), node("cve:C2", "cve"), node("technique:T1")],
        [edge("cve:C1", "technique:T1"), edge("cve:C2", "technique:T1")],
    )
    hops = traverse(conn, ["cve:C1", "cve:C2"], ["ENABLES"], max_depth=3, node_budget=10)
    assert set(ids(hops)) == {"cve:C1", "cve:C2", "technique:T1"}


# --- termination ----------------------------------------------------------------------


@pytest.mark.timeout(10)
def test_a_cycle_returns_each_node_once(conn):
    """A two-node cycle must not yield a node twice, or a path that revisits one."""
    build(
        conn,
        [node("technique:T1"), node("technique:T2")],
        [
            edge("technique:T1", "technique:T2", "CHAINS_TO"),
            edge("technique:T2", "technique:T1", "CHAINS_TO"),
        ],
    )
    hops = traverse(conn, ["technique:T1"], ["CHAINS_TO"], max_depth=10, node_budget=100)
    assert set(ids(hops)) == {"technique:T1", "technique:T2"}
    assert all(len(set(h.path)) == len(h.path) for h in hops)


@pytest.mark.timeout(10)
def test_a_self_loop_returns_the_node_once(conn):
    build(conn, [node("technique:T1")], [edge("technique:T1", "technique:T1", "CHAINS_TO")])
    hops = traverse(conn, ["technique:T1"], ["CHAINS_TO"], max_depth=10, node_budget=100)
    assert ids(hops) == ["technique:T1"]


@pytest.mark.timeout(30)
def test_a_dense_cycle_does_not_blow_up_the_recursion(conn):
    """What the `NOT dst = ANY(path)` guard is actually for.

    The guard is often described as what stops a cycle recursing forever. It is not —
    `max_depth` already bounds that, and a route that revisits a node always costs more
    than the one that did not, so `DISTINCT ON ... ORDER BY cost` would discard it anyway.
    Remove the guard and every assertion about *results* still passes.

    What it stops is the row count. Six fully-connected nodes at depth 10 is six times
    five-to-the-tenth walk rows without the guard — tens of millions, from a graph of
    thirty edges. With it, a path cannot repeat a node, so nothing longer than six hops
    survives. CHAINS_TO makes dense cycles ordinary rather than exotic, so this is the
    real production shape, and the failure mode is a query that never comes back rather
    than a wrong answer.
    """
    n = 6
    nodes = [node(f"technique:T{i}") for i in range(n)]
    edges = [
        edge(f"technique:T{i}", f"technique:T{j}", "CHAINS_TO")
        for i in range(n)
        for j in range(n)
        if i != j
    ]
    build(conn, nodes, edges)

    hops = traverse(conn, ["technique:T0"], ["CHAINS_TO"], max_depth=10, node_budget=100)
    assert len(hops) == n
    assert all(len(h.path) <= n for h in hops)


@pytest.mark.timeout(10)
def test_a_long_chain_stops_at_max_depth(conn):
    nodes = [node(f"technique:T{i}") for i in range(8)]
    edges = [edge(f"technique:T{i}", f"technique:T{i + 1}", "CHAINS_TO") for i in range(7)]
    build(conn, nodes, edges)

    hops = traverse(conn, ["technique:T0"], ["CHAINS_TO"], max_depth=3, node_budget=100)
    assert max(h.depth for h in hops) == 3
    assert all(len(h.path) <= 4 for h in hops)
    assert "technique:T4" not in ids(hops)


# --- budget ---------------------------------------------------------------------------


def test_node_budget_caps_the_result(conn):
    nodes = [node("cve:C1", "cve")] + [node(f"technique:T{i}") for i in range(20)]
    edges = [edge("cve:C1", f"technique:T{i}") for i in range(20)]
    build(conn, nodes, edges)

    hops = traverse(conn, ["cve:C1"], ["ENABLES"], max_depth=3, node_budget=5)
    assert len(hops) == 5


def test_budget_keeps_the_cheapest_not_the_alphabetically_first(conn):
    """The regression test for collapsing the SQL into a single DISTINCT ON level.

    DISTINCT ON forces ORDER BY to lead with the distinct key, so a one-level query
    orders by id and LIMIT keeps the first ids alphabetically. Here the strongest edge
    points at the alphabetically last node, so that bug drops the best answer and keeps
    four worse ones — while still returning a plausible-looking result.
    """
    nodes = [node("cve:C1", "cve")] + [node(f"technique:T{i}") for i in range(5)]
    edges = [edge("cve:C1", f"technique:T{i}", weight=0.1) for i in range(4)]
    edges.append(edge("cve:C1", "technique:T4", weight=1.0))
    build(conn, nodes, edges)

    hops = traverse(conn, ["cve:C1"], ["ENABLES"], max_depth=1, node_budget=2)
    assert ids(hops) == ["cve:C1", "technique:T4"]


def test_results_are_ordered_by_cost_ascending(conn):
    nodes = [node("cve:C1", "cve"), node("technique:Ta"), node("technique:Tb")]
    build(
        conn,
        nodes,
        [edge("cve:C1", "technique:Ta", weight=0.2), edge("cve:C1", "technique:Tb", weight=1.0)],
    )
    hops = traverse(conn, ["cve:C1"], ["ENABLES"], max_depth=2, node_budget=10)
    assert [h.cost for h in hops] == sorted(h.cost for h in hops)
    assert ids(hops) == ["cve:C1", "technique:Tb", "technique:Ta"]


def test_a_node_reachable_twice_is_returned_once_by_its_cheapest_route(conn):
    """Two routes to one node. The strong one must win, and the node must not double."""
    build(
        conn,
        [node("cve:C1", "cve"), node("technique:Tmid"), node("technique:Tend")],
        [
            edge("cve:C1", "technique:Tend", weight=0.1),
            edge("cve:C1", "technique:Tmid", weight=1.0),
            edge("technique:Tmid", "technique:Tend", "CHAINS_TO", weight=1.0),
        ],
    )
    hops = traverse(conn, ["cve:C1"], ["ENABLES", "CHAINS_TO"], max_depth=3, node_budget=10)
    end = [h for h in hops if h.node.id == "technique:Tend"]
    assert len(end) == 1
    assert end[0].path == ("cve:C1", "technique:Tmid", "technique:Tend")


# --- awkward input ----------------------------------------------------------------------


def test_unknown_anchor_returns_nothing(conn):
    build(conn, [node("technique:T1")], [])
    assert traverse(conn, ["cve:NOPE"], ["ENABLES"], max_depth=3, node_budget=10) == []


def test_empty_anchors_returns_nothing_without_querying(conn):
    assert traverse(conn, [], ["ENABLES"], max_depth=3, node_budget=10) == []


def test_empty_edge_kinds_returns_nothing(conn):
    """Distinct from 'no edges matched': asking for no kinds is a caller mistake, and
    returning the anchors would look like a successful walk that found nothing."""
    build(conn, [node("technique:T1")], [])
    assert traverse(conn, ["technique:T1"], [], max_depth=3, node_budget=10) == []


def test_zero_depth_returns_only_the_anchors(conn):
    build(conn, [node("cve:C1", "cve"), node("technique:T1")], [edge("cve:C1", "technique:T1")])
    hops = traverse(conn, ["cve:C1"], ["ENABLES"], max_depth=0, node_budget=10)
    assert ids(hops) == ["cve:C1"]


@pytest.mark.security
def test_an_id_shaped_like_sql_is_a_parameter_not_a_fragment(conn):
    hostile = "cve:'; DROP TABLE nodes; --"
    build(conn, [node("cve:C1", "cve")], [])
    assert traverse(conn, [hostile], ["ENABLES"], max_depth=3, node_budget=10) == []
    assert conn.execute(text("SELECT count(*) FROM nodes")).scalar_one() == 1


def test_traversal_is_deterministic(conn):
    """Same graph, same query, byte-identical result. Ties broken by id, not by luck."""
    nodes = [node("cve:C1", "cve")] + [node(f"technique:T{i}") for i in range(6)]
    build(conn, nodes, [edge("cve:C1", f"technique:T{i}") for i in range(6)])

    first = traverse(conn, ["cve:C1"], ["ENABLES"], max_depth=3, node_budget=10)
    second = traverse(conn, ["cve:C1"], ["ENABLES"], max_depth=3, node_budget=10)
    assert [(h.node.id, h.depth, h.path, h.cost) for h in first] == [
        (h.node.id, h.depth, h.path, h.cost) for h in second
    ]


# --- chains ---------------------------------------------------------------------------


def test_chain_shape_is_cve_technique_tactic_mitigation(conn):
    """The shape the whole product is built to return."""
    build(
        conn,
        [
            node("cve:CVE-2021-44228", "cve"),
            node("technique:T1190"),
            node("tactic:TA0001", "tactic"),
            node("mitigation:M1030", "mitigation"),
        ],
        [
            edge("cve:CVE-2021-44228", "technique:T1190"),
            edge("technique:T1190", "tactic:TA0001", "BELONGS_TO"),
            edge("technique:T1190", "mitigation:M1030", "MITIGATED_BY"),
        ],
    )
    hops = traverse(conn, ["cve:CVE-2021-44228"], PATH_EDGE_KINDS, max_depth=3, node_budget=50)

    tactic_chains = chains(hops, ["cve", "technique", "tactic"])
    assert [n.id for n in tactic_chains[0]] == [
        "cve:CVE-2021-44228",
        "technique:T1190",
        "tactic:TA0001",
    ]

    mitigation_chains = chains(hops, ["cve", "technique", "mitigation"])
    assert [n.id for n in mitigation_chains[0]] == [
        "cve:CVE-2021-44228",
        "technique:T1190",
        "mitigation:M1030",
    ]


def test_incomplete_chains_are_not_returned(conn):
    """A CVE whose technique has no tactic yields no cve->technique->tactic chain."""
    build(
        conn,
        [node("cve:C1", "cve"), node("technique:T1")],
        [edge("cve:C1", "technique:T1")],
    )
    hops = traverse(conn, ["cve:C1"], PATH_EDGE_KINDS, max_depth=3, node_budget=50)
    assert chains(hops, ["cve", "technique", "tactic"]) == []


def test_chains_are_ordered_cheapest_first(conn):
    build(
        conn,
        [
            node("cve:C1", "cve"),
            node("technique:Tweak"),
            node("technique:Tstrong"),
            node("tactic:TA1", "tactic"),
        ],
        [
            edge("cve:C1", "technique:Tweak", weight=0.1),
            edge("cve:C1", "technique:Tstrong", weight=1.0),
            edge("technique:Tweak", "tactic:TA1", "BELONGS_TO"),
            edge("technique:Tstrong", "tactic:TA1", "BELONGS_TO"),
        ],
    )
    hops = traverse(conn, ["cve:C1"], PATH_EDGE_KINDS, max_depth=3, node_budget=50)
    # TA1 is reached twice; traverse keeps the cheap route, so exactly one chain survives
    # and it must be the one through the strong edge.
    result = chains(hops, ["cve", "technique", "tactic"])
    assert [n.id for n in result[0]] == ["cve:C1", "technique:Tstrong", "tactic:TA1"]


# --- direction ------------------------------------------------------------------------


def test_reverse_kinds_walk_from_destination_to_source(conn):
    """`USES` is stored actor -> technique, but "who uses this technique" starts at the
    technique. Without a reverse walk that question cannot be answered at all."""
    build(
        conn,
        [node("actor:G1", "actor"), node("technique:T1")],
        [edge("actor:G1", "technique:T1", "USES")],
    )
    hops = traverse(conn, ["technique:T1"], [], reverse_kinds=["USES"], max_depth=3, node_budget=10)
    assert ids(hops) == ["technique:T1", "actor:G1"]


def test_forward_and_reverse_kinds_walk_in_one_query(conn):
    """The real shape: from a technique, reach its tactic forwards and its actors
    backwards in a single traversal."""
    build(
        conn,
        [node("actor:G1", "actor"), node("technique:T1"), node("tactic:TA1", "tactic")],
        [
            edge("actor:G1", "technique:T1", "USES"),
            edge("technique:T1", "tactic:TA1", "BELONGS_TO"),
        ],
    )
    hops = traverse(
        conn,
        ["technique:T1"],
        ["BELONGS_TO"],
        reverse_kinds=["USES"],
        max_depth=3,
        node_budget=10,
    )
    assert set(ids(hops)) == {"technique:T1", "tactic:TA1", "actor:G1"}


def test_a_reverse_hop_records_its_path_and_depth(conn):
    build(
        conn,
        [node("actor:G1", "actor"), node("technique:T1")],
        [edge("actor:G1", "technique:T1", "USES")],
    )
    hops = traverse(conn, ["technique:T1"], [], reverse_kinds=["USES"], max_depth=3, node_budget=10)
    actor = next(h for h in hops if h.node.id == "actor:G1")
    assert actor.path == ("technique:T1", "actor:G1")
    assert actor.depth == 1


def test_a_kind_in_both_lists_is_walked_both_ways(conn):
    """CHAINS_TO is directed, but "what is this technique adjacent to" wants both ends."""
    build(
        conn,
        [node("technique:T1"), node("technique:T2"), node("technique:T3")],
        [
            edge("technique:T1", "technique:T2", "CHAINS_TO"),
            edge("technique:T3", "technique:T1", "CHAINS_TO"),
        ],
    )
    hops = traverse(
        conn,
        ["technique:T1"],
        ["CHAINS_TO"],
        reverse_kinds=["CHAINS_TO"],
        max_depth=1,
        node_budget=10,
    )
    assert set(ids(hops)) == {"technique:T1", "technique:T2", "technique:T3"}


def test_reverse_edges_carry_their_weight_into_the_cost(conn):
    """A weak reverse edge must rank below a strong one, exactly like a forward edge."""
    build(
        conn,
        [node("actor:Gweak", "actor"), node("actor:Gstrong", "actor"), node("technique:T1")],
        [
            edge("actor:Gweak", "technique:T1", "USES", weight=0.1),
            edge("actor:Gstrong", "technique:T1", "USES", weight=1.0),
        ],
    )
    hops = traverse(conn, ["technique:T1"], [], reverse_kinds=["USES"], max_depth=1, node_budget=10)
    assert ids(hops) == ["technique:T1", "actor:Gstrong", "actor:Gweak"]


@pytest.mark.timeout(10)
def test_a_reverse_walk_still_guards_against_cycles(conn):
    """Walking an edge both ways makes every edge a two-node cycle, so the guard matters
    more here than in a forward-only walk, not less."""
    build(
        conn,
        [node("technique:T1"), node("technique:T2")],
        [edge("technique:T1", "technique:T2", "CHAINS_TO")],
    )
    hops = traverse(
        conn,
        ["technique:T1"],
        ["CHAINS_TO"],
        reverse_kinds=["CHAINS_TO"],
        max_depth=8,
        node_budget=50,
    )
    assert set(ids(hops)) == {"technique:T1", "technique:T2"}
    assert all(len(set(h.path)) == len(h.path) for h in hops)


def test_no_reverse_kinds_is_unchanged_forward_only_behaviour(conn):
    """Regression guard on the default. Every existing caller passes no reverse kinds."""
    build(
        conn,
        [node("actor:G1", "actor"), node("technique:T1")],
        [edge("actor:G1", "technique:T1", "USES")],
    )
    hops = traverse(conn, ["technique:T1"], ["USES"], max_depth=3, node_budget=10)
    assert ids(hops) == ["technique:T1"]


def test_empty_forward_and_empty_reverse_returns_nothing(conn):
    build(conn, [node("technique:T1")], [])
    assert traverse(conn, ["technique:T1"], [], reverse_kinds=[], max_depth=3, node_budget=10) == []
