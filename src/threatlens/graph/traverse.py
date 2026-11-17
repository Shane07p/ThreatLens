"""Bounded, weighted, direction-aware multi-hop walks over the edge table.

This is the piece the project is actually about. Naive vector RAG returns chunks that
look like the query; this returns a *path* — the CVE, the technique it enables, the
tactic that technique serves, and the mitigation that stops it — where every hop is a
row somebody can check.

Hand-written on purpose. Nothing off the shelf does bounded, weighted, direction-aware
multi-hop over a Postgres edge table, and a library's traversal would make the ablation
table measure that library rather than this design.

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

_WALK = text("""
    WITH RECURSIVE arcs AS (
        SELECT src AS from_id, dst AS to_id, weight FROM edges WHERE kind = ANY(:edge_kinds)
        UNION ALL
        SELECT dst AS from_id, src AS to_id, weight FROM edges WHERE kind = ANY(:reverse_kinds)
    ),
    walk(id, depth, path, cost) AS (
        SELECT n.id, 0, ARRAY[n.id], 0.0::float8
        FROM nodes n
        WHERE n.id = ANY(:anchors)
      UNION ALL
        SELECT a.to_id,
               w.depth + 1,
               w.path || a.to_id,
               w.cost + (1.0 / GREATEST(a.weight, 0.01))
        FROM walk w
        JOIN arcs a ON a.from_id = w.id
        WHERE w.depth < :max_depth
          AND NOT a.to_id = ANY(w.path)
    )
    SELECT best.depth, best.path, best.cost,
           n.id, n.kind, n.external_id, n.stix_id, n.name, n.description,
           n.attrs, n.source_url
    FROM (
        SELECT DISTINCT ON (id) id, depth, path, cost
        FROM walk
        ORDER BY id, cost ASC
    ) best
    JOIN nodes n ON n.id = best.id
    ORDER BY best.cost ASC, best.depth ASC, best.id
    LIMIT :node_budget
""")
# The subquery is load-bearing. DISTINCT ON forces ORDER BY to lead with the
# distinct key, so collapsing this into one level orders the result by id and the
# LIMIT then keeps the alphabetically first N nodes rather than the cheapest N —
# silently returning a worse answer whenever the budget actually binds, and an
# identical one whenever it does not, which is when you would be testing.


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

    Returns one Hop per reachable node, including the anchors themselves at depth 0,
    ordered by cost ascending. A node reachable by several routes appears once, via
    its cheapest one.

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

    rows = conn.execute(
        _WALK,
        {
            "anchors": anchors,
            "edge_kinds": edge_kinds,
            "reverse_kinds": reverse_kinds,
            "max_depth": max_depth,
            "node_budget": node_budget,
        },
    )

    return [
        Hop(
            node=Node(
                id=r.id,
                kind=r.kind,
                external_id=r.external_id,
                name=r.name,
                source_url=r.source_url,
                description=r.description,
                stix_id=r.stix_id,
                attrs=r.attrs or {},
            ),
            depth=r.depth,
            path=tuple(r.path),
            cost=float(r.cost),
        )
        for r in rows
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
