"""Tests for the shared contract types.

These types are the interface all four tracks build against, so the properties
asserted here are the ones other people's code is entitled to rely on.
"""

from __future__ import annotations

from dataclasses import FrozenInstanceError

import pytest

from threatlens.models import EDGE_KINDS, NODE_KINDS, Edge, Graph, Node


def make_node(**overrides) -> Node:
    base = {
        "id": "technique:T1190",
        "kind": "technique",
        "external_id": "T1190",
        "name": "Exploit Public-Facing Application",
        "source_url": "https://attack.mitre.org/techniques/T1190",
    }
    return Node(**{**base, **overrides})


# --- id construction -----------------------------------------------------------------


def test_make_id_is_kind_colon_external_id():
    assert Node.make_id("technique", "T1190") == "technique:T1190"
    assert Node.make_id("cve", "CVE-2021-44228") == "cve:CVE-2021-44228"


def test_make_id_preserves_dotted_subtechnique_ids():
    assert Node.make_id("technique", "T1059.001") == "technique:T1059.001"


def test_make_id_is_stable_across_calls():
    """Ingestion idempotency depends on this being a pure function of its inputs."""
    assert Node.make_id("technique", "T1190") == Node.make_id("technique", "T1190")


def test_id_splits_back_into_kind_and_external_id():
    """path_correct() in eval/metrics parses ids this way — the split must round-trip."""
    node_id = Node.make_id("cve", "CVE-2021-44228")
    kind, external_id = node_id.split(":", 1)
    assert kind == "cve"
    assert external_id == "CVE-2021-44228"


# --- immutability --------------------------------------------------------------------


def test_node_is_frozen():
    """Nodes get passed across module boundaries; a mutation would be invisible action."""
    node = make_node()
    with pytest.raises(FrozenInstanceError):
        node.name = "changed"


def test_edge_is_frozen():
    edge = Edge(src="a", dst="b", kind="BELONGS_TO", source="test")
    with pytest.raises(FrozenInstanceError):
        edge.weight = 0.1


# --- defaults ------------------------------------------------------------------------


def test_optional_node_fields_default_to_none():
    node = make_node()
    assert node.description is None
    assert node.stix_id is None


def test_attrs_defaults_to_an_empty_dict():
    assert make_node().attrs == {}


def test_attrs_is_not_shared_between_instances():
    """The classic dataclass mutable-default bug: one shared dict across every Node."""
    a, b = make_node(), make_node(id="technique:T1059", external_id="T1059")
    a.attrs["only_on_a"] = True
    assert b.attrs == {}


def test_edge_weight_defaults_to_one():
    assert Edge(src="a", dst="b", kind="USES", source="t").weight == 1.0


def test_graph_skipped_defaults_to_zero():
    assert Graph(nodes=[], edges=[], version="19.1").skipped == 0


# --- equality ------------------------------------------------------------------------


def test_nodes_with_identical_fields_are_equal():
    """Frozen dataclass equality is what makes golden-graph comparison meaningful."""
    assert make_node() == make_node()


def test_nodes_differing_in_any_field_are_unequal():
    assert make_node() != make_node(name="Different")


def test_edges_compare_on_all_fields_including_weight():
    a = Edge(src="x", dst="y", kind="ENABLES", source="s", weight=1.0)
    b = Edge(src="x", dst="y", kind="ENABLES", source="s", weight=0.5)
    assert a != b


# --- vocabulary ----------------------------------------------------------------------


def test_node_kinds_cover_every_kind_the_schema_stores():
    assert {"technique", "tactic", "mitigation", "actor", "software", "cve"} <= NODE_KINDS


def test_edge_kinds_cover_every_edge_the_parser_emits():
    assert {
        "BELONGS_TO",
        "MITIGATED_BY",
        "USES",
        "USES_SOFTWARE",
        "SUBTECHNIQUE_OF",
    } <= EDGE_KINDS


def test_enables_and_chains_to_are_declared_before_they_are_built():
    """Not emitted by the ATT&CK parser, but declared here so the edge vocabulary lives
    in one place rather than being spread across whichever module happens to add one."""
    assert "ENABLES" in EDGE_KINDS
    assert "CHAINS_TO" in EDGE_KINDS


def test_kind_vocabularies_are_immutable():
    with pytest.raises(AttributeError):
        NODE_KINDS.add("nonsense")
