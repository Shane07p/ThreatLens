"""Every documented parsing correction is a test here.

A STIX parser fails silently and plausibly: drop 15% of the edges and the graph still
looks fine, but every number downstream is wrong. These assertions are what make a
dropped edge a deliberate choice rather than an accident.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from threatlens.ingest.attack import parse_bundle

FIXTURE = Path(__file__).parent.parent / "fixtures" / "mini-attack-bundle.json"
EXPECTED = Path(__file__).parent.parent / "fixtures" / "expected_graph.json"


@pytest.fixture(scope="module")
def graph():
    return parse_bundle(FIXTURE)


def _ids(graph) -> set[str]:
    return {n.id for n in graph.nodes}


def _pairs(graph, kind: str) -> set[tuple[str, str]]:
    return {(e.src, e.dst) for e in graph.edges if e.kind == kind}


# --- ATT&CK ids come from external_references ---------------------------------------


def test_attack_id_comes_from_external_references(graph):
    assert "technique:T1190" in _ids(graph)


def test_source_url_comes_from_external_references(graph):
    node = next(n for n in graph.nodes if n.id == "technique:T1190")
    assert node.source_url == "https://attack.mitre.org/techniques/T1190"


def test_non_mitre_external_reference_is_ignored(graph):
    """T1190 also carries a CAPEC reference; the mitre-attack one must win."""
    node = next(n for n in graph.nodes if n.id == "technique:T1190")
    assert node.external_id == "T1190"
    assert "capec" not in node.source_url


# --- retired objects ------------------------------------------------------------------


def test_revoked_objects_are_skipped(graph):
    assert "technique:T9998" not in _ids(graph)


def test_deprecated_objects_are_skipped(graph):
    assert "technique:T9999" not in _ids(graph)


def test_skipped_count_is_reported(graph):
    """Two dead objects plus the relationship pointing at one of them."""
    assert graph.skipped == 3


def test_edges_pointing_at_skipped_objects_are_dropped(graph):
    assert all("T9998" not in e.src and "T9998" not in e.dst for e in graph.edges)


# --- technique -> tactic comes from kill_chain_phases --------------------------------


def test_belongs_to_comes_from_kill_chain_phases(graph):
    assert ("technique:T1190", "tactic:TA0001") in _pairs(graph, "BELONGS_TO")


def test_technique_in_two_tactics_yields_two_edges(graph):
    dsts = {e.dst for e in graph.edges if e.kind == "BELONGS_TO" and e.src == "technique:T1059"}
    assert dsts == {"tactic:TA0001", "tactic:TA0002"}


def test_every_technique_has_a_tactic(graph):
    """The single most load-bearing assertion in this file.

    Zero tactic edges means the parser looked for a relationship object that does not
    exist, and the graph cannot answer what tactic a technique belongs to."""
    techniques = {n.id for n in graph.nodes if n.kind == "technique"}
    with_tactic = {e.src for e in graph.edges if e.kind == "BELONGS_TO"}
    assert techniques == with_tactic


# --- relationship mapping ------------------------------------------------------------


def test_subtechnique_keeps_dotted_id(graph):
    assert "technique:T1059.001" in _ids(graph)


def test_subtechnique_flag_is_recorded(graph):
    sub = next(n for n in graph.nodes if n.id == "technique:T1059.001")
    parent = next(n for n in graph.nodes if n.id == "technique:T1059")
    assert sub.attrs["is_subtechnique"] is True
    assert parent.attrs["is_subtechnique"] is False


def test_subtechnique_of_edge_direction(graph):
    assert ("technique:T1059.001", "technique:T1059") in _pairs(graph, "SUBTECHNIQUE_OF")


def test_mitigates_is_reversed_to_mitigated_by(graph):
    """STIX runs mitigation -> technique; the graph reads technique -> mitigation."""
    assert ("technique:T1190", "mitigation:M1030") in _pairs(graph, "MITIGATED_BY")


def test_actor_uses_technique(graph):
    assert ("actor:G0016", "technique:T1190") in _pairs(graph, "USES")


def test_actor_uses_software_is_a_distinct_kind(graph):
    assert ("actor:G0016", "software:S0154") in _pairs(graph, "USES_SOFTWARE")


def test_unmapped_relationship_types_are_ignored(graph):
    """A 'detects' relationship from a data source is not an edge kind we model yet."""
    assert all(e.kind != "DETECTED_BY" for e in graph.edges)


# --- structural invariants -----------------------------------------------------------


def test_no_edge_dangles(graph):
    ids = _ids(graph)
    for e in graph.edges:
        assert e.src in ids, f"dangling src {e.src}"
        assert e.dst in ids, f"dangling dst {e.dst}"


def test_node_kind_mapping(graph):
    kinds = {n.id: n.kind for n in graph.nodes}
    assert kinds["technique:T1190"] == "technique"
    assert kinds["tactic:TA0001"] == "tactic"
    assert kinds["mitigation:M1030"] == "mitigation"
    assert kinds["actor:G0016"] == "actor"
    assert kinds["software:S0154"] == "software"


def test_unmapped_stix_types_are_not_nodes(graph):
    """x-mitre-data-source is not in our schema yet and must not become a node."""
    assert not any(n.external_id == "DS0029" for n in graph.nodes)


def test_node_count(graph):
    """2 tactics + 3 live techniques + 1 mitigation + 1 actor + 1 software."""
    assert len(graph.nodes) == 8


def test_all_edge_kinds_present(graph):
    assert {e.kind for e in graph.edges} == {
        "BELONGS_TO",
        "MITIGATED_BY",
        "USES",
        "USES_SOFTWARE",
        "SUBTECHNIQUE_OF",
    }


# --- ATT&CK version -------------------------------------------------------------------


def test_collection_version_is_read(graph):
    assert graph.version == "19.1"


def test_edge_source_records_the_version(graph):
    assert all(e.source == "attack-stix v19.1" for e in graph.edges)


# --- B2: golden snapshot -------------------------------------------------------------


def test_golden_graph_matches(graph):
    """Regression gate. Update expected_graph.json deliberately, never to pass a test."""
    expected = json.loads(EXPECTED.read_text(encoding="utf-8"))
    actual = {
        "version": graph.version,
        "nodes": sorted(f"{n.id}|{n.kind}|{n.name}" for n in graph.nodes),
        "edges": sorted(f"{e.src}|{e.kind}|{e.dst}" for e in graph.edges),
    }
    assert actual["version"] == expected["version"]
    assert actual["nodes"] == expected["nodes"]
    assert actual["edges"] == expected["edges"]
