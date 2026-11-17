"""Structural invariants of the STIX parser, over generated bundles.

The example tests check the parser reads ATT&CK correctly. These check the guarantees the
rest of the system relies on, for arbitrary combinations of tactics, techniques, revoked
objects, unknown kill-chain phases, and relationships pointing at things that are not
there: no dangling edge, no retired object, every tactic link landing on a tactic, and the
same answer every time.
"""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

from hypothesis import given
from hypothesis import strategies as st

from threatlens.ingest.attack import parse_bundle

SHORTNAMES = ["reconnaissance", "initial-access", "execution", "persistence", "impact"]


def tactic(i: int) -> dict:
    return {
        "type": "x-mitre-tactic",
        "id": f"x-mitre-tactic--{i}",
        "name": SHORTNAMES[i],
        "x_mitre_shortname": SHORTNAMES[i],
        "external_references": [
            {"source_name": "mitre-attack", "external_id": f"TA{i:04d}", "url": "u"}
        ],
    }


def technique(n: int, phases: list[str], revoked: bool) -> dict:
    return {
        "type": "attack-pattern",
        "id": f"attack-pattern--{n}",
        "name": f"T{n}",
        "revoked": revoked,
        "kill_chain_phases": [{"kill_chain_name": "mitre-attack", "phase_name": p} for p in phases],
        "external_references": [
            {"source_name": "mitre-attack", "external_id": f"T{1000 + n}", "url": "u"}
        ],
    }


@st.composite
def bundles(draw) -> list[dict]:
    n_tactics = draw(st.integers(1, len(SHORTNAMES)))
    objects = [tactic(i) for i in range(n_tactics)]
    phase_names = st.sampled_from([*SHORTNAMES, "not-a-real-phase"])
    n_techniques = draw(st.integers(0, 8))
    for n in range(n_techniques):
        objects.append(
            technique(n, draw(st.lists(phase_names, max_size=3)), revoked=draw(st.booleans()))
        )
    # Relationships between techniques, some pointing at ids that do not exist.
    refs = st.sampled_from([f"attack-pattern--{n}" for n in range(n_techniques + 2)])
    for k in range(draw(st.integers(0, 6)) if n_techniques else 0):
        objects.append(
            {
                "type": "relationship",
                "id": f"relationship--{k}",
                "relationship_type": "subtechnique-of",
                "source_ref": draw(refs),
                "target_ref": draw(refs),
            }
        )
    objects.append({"type": "x-mitre-collection", "id": "c", "x_mitre_version": "1.0"})
    return objects


def parse(objects: list[dict]):
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "bundle.json"
        path.write_text(json.dumps({"type": "bundle", "objects": objects}), encoding="utf-8")
        return parse_bundle(path)


@given(bundles())
def test_no_edge_ever_points_at_a_missing_node(objects):
    graph = parse(objects)
    ids = {n.id for n in graph.nodes}
    assert all(e.src in ids and e.dst in ids for e in graph.edges)


@given(bundles())
def test_no_revoked_object_ever_becomes_a_node(objects):
    revoked = {
        f"technique:T{1000 + int(o['id'].split('--')[1])}"
        for o in objects
        if o["type"] == "attack-pattern" and o["revoked"]
    }
    assert revoked.isdisjoint(n.id for n in parse(objects).nodes)


@given(bundles())
def test_every_tactic_link_joins_a_technique_to_a_tactic(objects):
    graph = parse(objects)
    kind = {n.id: n.kind for n in graph.nodes}
    for e in graph.edges:
        if e.kind == "BELONGS_TO":
            assert (kind[e.src], kind[e.dst]) == ("technique", "tactic")


@given(bundles())
def test_parsing_the_same_bundle_twice_gives_the_same_graph(objects):
    first, second = parse(objects), parse(objects)
    assert [(n.id, n.kind) for n in first.nodes] == [(n.id, n.kind) for n in second.nodes]
    assert [(e.src, e.dst, e.kind) for e in first.edges] == [
        (e.src, e.dst, e.kind) for e in second.edges
    ]
