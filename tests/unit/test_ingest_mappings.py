"""Unit tests for partition_edges — the pure drop-count logic.

partition_edges is deliberately separated from ingest_mappings so it can be
tested without a database. The integration of ingest_mappings() with Postgres
is covered in tests/integration/.
"""

from __future__ import annotations

from threatlens.ingest.mappings import partition_edges
from threatlens.models import Edge


def _edge(src: str, dst: str, weight: float = 1.0) -> Edge:
    return Edge(src=src, dst=dst, kind="ENABLES", source="test", weight=weight)


# --- basic partitioning ---


def test_fully_resolvable_edges():
    """Both endpoints exist — all edges pass through."""
    edges = [_edge("cve:CVE-1", "technique:T1059"), _edge("cve:CVE-2", "technique:T1190")]
    existing = {"cve:CVE-1", "cve:CVE-2", "technique:T1059", "technique:T1190"}

    resolvable, dropped_tech, dropped_src = partition_edges(edges, existing)
    assert len(resolvable) == 2
    assert dropped_tech == []
    assert dropped_src == []


def test_absent_technique_is_dropped():
    """An edge pointing at a technique not in the graph is dropped."""
    edges = [_edge("cve:CVE-1", "technique:T1059"), _edge("cve:CVE-1", "technique:T9998")]
    existing = {"cve:CVE-1", "technique:T1059"}

    resolvable, dropped_tech, dropped_src = partition_edges(edges, existing)
    assert len(resolvable) == 1
    assert len(dropped_tech) == 1
    assert dropped_tech[0].dst == "technique:T9998"


def test_absent_cve_source_is_dropped():
    """An edge from a CVE that was never ingested is dropped separately."""
    edges = [_edge("cve:CVE-GHOST", "technique:T1059")]
    existing = {"technique:T1059"}

    resolvable, dropped_tech, dropped_src = partition_edges(edges, existing)
    assert resolvable == []
    assert dropped_tech == []
    assert len(dropped_src) == 1
    assert dropped_src[0].src == "cve:CVE-GHOST"


def test_technique_drop_takes_priority_over_source_drop():
    """When both src and dst are absent, the edge is classified as dropped-technique.

    This matters for the diagnostic: the user should fix their ATT&CK ingest first.
    """
    edges = [_edge("cve:CVE-GHOST", "technique:T9998")]
    existing: set[str] = set()

    resolvable, dropped_tech, dropped_src = partition_edges(edges, existing)
    assert len(dropped_tech) == 1
    assert dropped_src == []


# --- empty inputs ---


def test_no_edges_returns_empty_lists():
    resolvable, dropped_tech, dropped_src = partition_edges([], {"technique:T1059"})
    assert resolvable == []
    assert dropped_tech == []
    assert dropped_src == []


# --- counts ---


def test_multiple_edges_to_same_absent_technique():
    """Two CVEs map to the same absent technique — both are dropped."""
    edges = [
        _edge("cve:CVE-1", "technique:T9998"),
        _edge("cve:CVE-2", "technique:T9998"),
    ]
    existing = {"cve:CVE-1", "cve:CVE-2"}

    resolvable, dropped_tech, dropped_src = partition_edges(edges, existing)
    assert len(dropped_tech) == 2
    assert len(resolvable) == 0


def test_mixed_resolvable_and_dropped():
    """Realistic scenario with a mix of good and bad edges."""
    edges = [
        _edge("cve:CVE-1", "technique:T1059"),  # good
        _edge("cve:CVE-1", "technique:T1190"),  # good
        _edge("cve:CVE-2", "technique:T9998"),  # bad technique
        _edge("cve:CVE-GHOST", "technique:T1059"),  # bad source
    ]
    existing = {"cve:CVE-1", "cve:CVE-2", "technique:T1059", "technique:T1190"}

    resolvable, dropped_tech, dropped_src = partition_edges(edges, existing)
    assert len(resolvable) == 2
    assert len(dropped_tech) == 1
    assert len(dropped_src) == 1


# --- determinism ---


def test_partition_is_deterministic():
    """Same input twice must produce identical output."""
    edges = [
        _edge("cve:CVE-1", "technique:T1059"),
        _edge("cve:CVE-1", "technique:T9998"),
    ]
    existing = {"cve:CVE-1", "technique:T1059"}

    a = partition_edges(edges, existing)
    b = partition_edges(edges, existing)
    assert a == b
