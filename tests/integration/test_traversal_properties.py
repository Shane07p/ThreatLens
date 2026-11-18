"""`traverse` agrees with a brute-force walk on every small graph Hypothesis can build.

The traversal prunes: at each depth it keeps only the cheapest `node_budget` routes and
drops the rest before expanding further. That is what keeps its work bounded, and it is
also exactly the kind of optimisation that returns a slightly wrong answer only when the
budget binds. The reference below prunes nothing — it enumerates every simple path — so
any route the pruning should not have dropped shows up as a disagreement.

Weights are drawn from {1, 0.5, 0.25}, whose inverses are exact in floating point. Equal
costs are therefore real ties, and the tie-breaking rule (cost, then depth, then id) is
tested rather than avoided.
"""

from __future__ import annotations

import os
from collections import defaultdict

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st
from sqlalchemy import text

from threatlens.graph.store import get_engine, init_schema, upsert_edges, upsert_nodes
from threatlens.graph.traverse import traverse
from threatlens.models import Edge, Node

pytestmark = [
    pytest.mark.db,
    pytest.mark.skipif(not os.getenv("THREATLENS_TEST_DSN"), reason="no THREATLENS_TEST_DSN"),
]

KINDS = ["ENABLES", "CHAINS_TO"]
WEIGHTS = [1.0, 0.5, 0.25]
MISSING = "technique:NOPE"


@pytest.fixture(scope="module")
def engine():
    eng = get_engine(os.environ["THREATLENS_TEST_DSN"])
    init_schema(eng)
    return eng


@st.composite
def walks(draw):
    n = draw(st.integers(1, 7))
    ids = [f"technique:T{i}" for i in range(n)]
    triples = [(a, b, k) for a in ids for b in ids for k in KINDS]
    chosen = draw(st.lists(st.sampled_from(triples), unique=True, max_size=30))
    edges = [(s, d, k, draw(st.sampled_from(WEIGHTS))) for s, d, k in chosen]
    return {
        "ids": ids,
        "edges": edges,
        "anchors": draw(
            st.lists(st.sampled_from([*ids, MISSING]), min_size=1, max_size=3, unique=True)
        ),
        "forward": draw(st.lists(st.sampled_from(KINDS), unique=True)),
        "reverse": draw(st.lists(st.sampled_from(KINDS), unique=True)),
        "max_depth": draw(st.integers(0, 4)),
        "budget": draw(st.integers(1, 8)),
    }


def arcs_of(case) -> dict[str, list[tuple[str, float]]]:
    arcs: dict[str, list[tuple[str, float]]] = defaultdict(list)
    for src, dst, kind, weight in case["edges"]:
        if kind in case["forward"]:
            arcs[src].append((dst, weight))
        if kind in case["reverse"]:
            arcs[dst].append((src, weight))
    return arcs


def step_cost(weight: float) -> float:
    return 1.0 / max(weight, 0.01)


def reference(case) -> list[tuple[str, int, float]]:
    """Every simple path up to max_depth, no pruning; best per node; then the budget."""
    if not (case["forward"] or case["reverse"]):
        return []
    arcs = arcs_of(case)
    best: dict[str, tuple[float, int]] = {}

    def walk(path: list[str], cost: float) -> None:
        here, depth = path[-1], len(path) - 1
        if here not in best or (cost, depth) < best[here]:
            best[here] = (cost, depth)
        if depth == case["max_depth"]:
            return
        for nxt, weight in arcs[here]:
            if nxt not in path:
                walk([*path, nxt], cost + step_cost(weight))

    for anchor in case["anchors"]:
        if anchor in case["ids"]:
            walk([anchor], 0.0)

    ranked = sorted(best.items(), key=lambda kv: (kv[1][0], kv[1][1], kv[0]))
    return [(node_id, depth, cost) for node_id, (cost, depth) in ranked[: case["budget"]]]


def load(conn, case) -> None:
    conn.execute(text("TRUNCATE nodes CASCADE"))
    upsert_nodes(
        conn,
        [
            Node(id=i, kind="technique", external_id=i.split(":")[1], name=i, source_url="u")
            for i in case["ids"]
        ],
    )
    upsert_edges(
        conn,
        [Edge(src=s, dst=d, kind=k, source="test", weight=w) for s, d, k, w in case["edges"]],
    )


@settings(deadline=None)
@given(walks())
def test_traverse_matches_an_unpruned_brute_force_walk(engine, case):
    with engine.begin() as conn:
        load(conn, case)
        hops = traverse(
            conn,
            case["anchors"],
            case["forward"],
            max_depth=case["max_depth"],
            node_budget=case["budget"],
            reverse_kinds=case["reverse"],
        )

    assert [(h.node.id, h.depth, h.cost) for h in hops] == reference(case)


@settings(deadline=None)
@given(walks())
def test_every_returned_route_is_a_real_simple_path_with_the_reported_cost(engine, case):
    with engine.begin() as conn:
        load(conn, case)
        hops = traverse(
            conn,
            case["anchors"],
            case["forward"],
            max_depth=case["max_depth"],
            node_budget=case["budget"],
            reverse_kinds=case["reverse"],
        )

    arcs = arcs_of(case)
    for hop in hops:
        assert hop.path[0] in case["anchors"]
        assert hop.path[-1] == hop.node.id
        assert len(hop.path) == hop.depth + 1
        assert len(set(hop.path)) == len(hop.path), "route revisits a node"
        cost = 0.0
        for here, nxt in zip(hop.path, hop.path[1:], strict=False):
            steps = [step_cost(w) for dst, w in arcs[here] if dst == nxt]
            assert steps, f"no {here} -> {nxt} arc in the walked kinds"
            cost += min(steps)
        assert hop.cost == cost
