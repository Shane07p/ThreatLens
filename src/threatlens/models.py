"""Shared types.

Every track depends on these. Changing them is a conversation with the whole team,
not a silent commit.
"""

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
