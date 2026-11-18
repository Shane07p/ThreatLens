"""Bounded, weighted, direction-aware multi-hop walks over the edge table.

This is the piece the project is actually about. Naive vector RAG returns chunks that
look like the query; this returns a *path* — the CVE, the technique it enables, the
tactic that technique serves, and the mitigation that stops it — where every hop is a
row somebody can check.

Hand-written on purpose. Nothing off the shelf does bounded, weighted, direction-aware
multi-hop over a Postgres edge table, and a library's traversal would make the ablation
table measure that library rather than this design.

The walk expands one depth at a time and keeps only the cheapest `node_budget` routes
before expanding again, so its work is bounded by the budget, not by how many paths the
graph contains. decisions.md D20 explains why that pruning cannot change the answer.

Reads only. If something here needs to write, it belongs in `ingest/`.
"""

from __future__ import annotations

from dataclasses import dataclass

from sqlalchemy import text
from sqlalchemy.engine import Connection

from threatlens.models import Node

# Edges are followed src -> dst, so the order here is the order of the story: what the
# CVE enables, what that serves, what stops it.
PATH_EDGE_KINDS = ["ENABLES", "BELONGS_TO", "MITIGATED_BY"]

# Stored actor -> technique, but the question is always "who uses this technique", which
# starts at the technique. Answering it means walking the edge the other way.
ACTOR_EDGE_KINDS = ["USES"]

_ANCHORS = text("SELECT id FROM nodes WHERE id = ANY(:anchors)")

# One hop out of the current frontier, in both directions. Served by the (src, kind) and
# (dst, kind) indexes, and never asked about more than `node_budget` ids at once.
_ARCS = text("""
    SELECT src AS from_id, dst AS to_id, weight
    FROM edges WHERE kind = ANY(:edge_kinds) AND src = ANY(:frontier)
    UNION ALL
    SELECT dst AS from_id, src AS to_id, weight
    FROM edges WHERE kind = ANY(:reverse_kinds) AND dst = ANY(:frontier)
""")

_NODES = text("""
    SELECT id, kind, external_id, stix_id, name, description, attrs, source_url
    FROM nodes WHERE id = ANY(:ids)
""")

# A route to a node: total cost, then the ids from the anchor to it.
_Route = tuple[float, tuple[str, ...]]


def _step_cost(weight: float) -> float:
    """Inverse weight, so strong edges are cheap. The floor keeps a zero weight finite."""
    return 1.0 / max(weight, 0.01)


@dataclass(frozen=True)
class Hop:
    """One node reached by a walk, with the route that reached it.

    `path` starts at the anchor and ends at this node, so `len(path) == depth + 1`.
    `cost` is the sum of inverse edge weights along that route — lower is stronger.
    """

    node: Node
    depth: int
    path: tuple[str, ...]
    cost: float


def traverse(
    conn: Connection,
    anchors: list[str],
    edge_kinds: list[str],
    max_depth: int | None = None,
    node_budget: int | None = None,
    *,
    reverse_kinds: list[str] | None = None,
) -> list[Hop]:
    """Walk outward from `anchors`, cheapest routes first.

    `edge_kinds` are followed src -> dst; `reverse_kinds` are followed dst -> src. A kind
    given in both is walked both ways. Direction is a parameter rather than a property of
    the edge because the same stored edge answers different questions from each end:
    `USES` read forwards is "what does this actor do", read backwards it is "who does
    this", and only the second starts from a technique.

    Returns at most `node_budget` Hops, one per node, including the anchors themselves at
    depth 0. Each node comes with its cheapest route of at most `max_depth` hops; among
    equally cheap routes, the shortest. Results are ordered by cost, then depth, then id.

    `max_depth` and `node_budget` default to the configured values. They are recorded
    in eval run metadata, so passing them explicitly is how a measured number stays
    reproducible.

    Raises nothing for an unknown anchor — it simply contributes no rows. Query-time
    code that needs an id to exist should check with `get_node` and raise there.
    """
    reverse_kinds = reverse_kinds or []
    if not anchors or not (edge_kinds or reverse_kinds):
        return []

    if max_depth is None or node_budget is None:
        from threatlens.config import get_settings

        settings = get_settings()
        max_depth = settings.max_depth if max_depth is None else max_depth
        node_budget = settings.node_budget if node_budget is None else node_budget

    found = conn.execute(_ANCHORS, {"anchors": anchors}).scalars().all()
    frontier: dict[str, _Route] = {a: (0.0, (a,)) for a in found}
    best: dict[str, tuple[float, int, tuple[str, ...]]] = {a: (0.0, 0, (a,)) for a in found}

    for depth in range(1, max_depth + 1):
        if not frontier:
            break
        reached: dict[str, _Route] = {}
        arcs = conn.execute(
            _ARCS,
            {
                "edge_kinds": edge_kinds,
                "reverse_kinds": reverse_kinds,
                "frontier": list(frontier),
            },
        )
        for from_id, to_id, weight in arcs:
            cost, path = frontier[from_id]
            if to_id in path:  # a route that revisits a node is never the cheapest
                continue
            route = (cost + _step_cost(weight), (*path, to_id))
            if to_id not in reached or route < reached[to_id]:
                reached[to_id] = route

        # The pruning that bounds the work. A route dropped here costs at least as much
        # as `node_budget` other nodes already reached, so nothing it leads to can make
        # the final cut — every step adds a positive cost.
        kept = sorted(reached.items(), key=lambda item: (item[1][0], item[0]))[:node_budget]
        frontier = dict(kept)
        for node_id, (cost, path) in kept:
            if node_id not in best or cost < best[node_id][0]:
                best[node_id] = (cost, depth, path)

    ranked = sorted(best.items(), key=lambda item: (item[1][0], item[1][1], item[0]))
    ranked = ranked[:node_budget]
    rows = conn.execute(_NODES, {"ids": [node_id for node_id, _ in ranked]})
    nodes = {
        r.id: Node(
            id=r.id,
            kind=r.kind,
            external_id=r.external_id,
            name=r.name,
            source_url=r.source_url,
            description=r.description,
            stix_id=r.stix_id,
            attrs=r.attrs or {},
        )
        for r in rows
    }

    return [
        Hop(node=nodes[node_id], depth=depth, path=path, cost=cost)
        for node_id, (cost, depth, path) in ranked
    ]


def chains(hops: list[Hop], kinds: list[str]) -> list[list[Node]]:
    """Pick out the routes that visited `kinds` in order, cheapest first.

    `traverse` returns a flat set of reachable nodes. A reader wants the story:
    `cve -> technique -> tactic -> mitigation`. Each returned chain is the nodes along
    one route, in order, so the caller can render every step with its own name and
    citation instead of a bare list of ids.

    A route reaching only part of `kinds` is left out. A half-chain rendered as a chain
    reads as a complete answer that happens to be short, which is worse than no answer.

    Does not deduplicate by prefix: two mitigations for one technique yield two chains
    that share their first three nodes. The caller decides how to group them.
    """
    by_id = {h.node.id: h.node for h in hops}
    out: list[tuple[float, list[Node]]] = []

    for hop in hops:
        if len(hop.path) != len(kinds):
            continue
        # A node on this route can be absent from `hops` when node_budget truncated it.
        route = [by_id[node_id] for node_id in hop.path if node_id in by_id]
        if len(route) == len(kinds) and [n.kind for n in route] == kinds:
            out.append((hop.cost, route))

    out.sort(key=lambda pair: (pair[0], pair[1][-1].id))
    return [route for _, route in out]
