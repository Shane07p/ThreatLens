"""Robustness tests: what the parser does with malformed, hostile, or degenerate input.

test_stix_parse.py proves the parser is correct on a well-formed bundle. This file
proves it does not crash, silently corrupt, or quietly lose data on input that is
missing fields, self-referential, duplicated, or simply strange.

Every case here has been seen in real STIX data or is one bad upstream release away.
The bundles are built inline rather than as fixture files so each test states exactly
the shape it cares about, with no indirection.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from threatlens.ingest.attack import parse_bundle
from threatlens.models import Node

REAL_BUNDLE = Path("data/raw/enterprise-attack.json")


def write_bundle(tmp_path: Path, objects: list[dict], version: str | None = "19.1") -> Path:
    """Build a minimal bundle on disk. Pass version=None to omit the collection object."""
    objs = list(objects)
    if version is not None:
        objs.insert(
            0,
            {
                "type": "x-mitre-collection",
                "id": "x-mitre-collection--t",
                "name": "Test",
                "x_mitre_version": version,
            },
        )
    path = tmp_path / "bundle.json"
    path.write_text(json.dumps({"type": "bundle", "objects": objs}), encoding="utf-8")
    return path


def tactic(shortname: str, ext_id: str) -> dict:
    return {
        "type": "x-mitre-tactic",
        "id": f"x-mitre-tactic--{ext_id}",
        "name": shortname.title(),
        "x_mitre_shortname": shortname,
        "external_references": [{"source_name": "mitre-attack", "external_id": ext_id, "url": "u"}],
    }


def technique(ext_id: str, phases: list[str] | None = None, **extra) -> dict:
    obj = {
        "type": "attack-pattern",
        "id": f"attack-pattern--{ext_id}",
        "name": f"Technique {ext_id}",
        "kill_chain_phases": [
            {"kill_chain_name": "mitre-attack", "phase_name": p} for p in (phases or [])
        ],
        "external_references": [{"source_name": "mitre-attack", "external_id": ext_id, "url": "u"}],
    }
    obj.update(extra)
    return obj


# --- degenerate bundles --------------------------------------------------------------


def test_empty_bundle_returns_empty_graph(tmp_path):
    g = parse_bundle(write_bundle(tmp_path, []))
    assert g.nodes == []
    assert g.edges == []
    assert g.skipped == 0


def test_bundle_with_no_collection_object_reports_unknown_version(tmp_path):
    """Never guess a version. An unknown version must be visibly unknown, not invented."""
    g = parse_bundle(write_bundle(tmp_path, [tactic("execution", "TA0002")], version=None))
    assert g.version == "unknown"
    assert all(e.source == "attack-stix vunknown" for e in g.edges)


def test_bundle_missing_objects_key_raises(tmp_path):
    path = tmp_path / "bad.json"
    path.write_text(json.dumps({"type": "bundle"}), encoding="utf-8")
    with pytest.raises(KeyError):
        parse_bundle(path)


def test_malformed_json_raises(tmp_path):
    path = tmp_path / "bad.json"
    path.write_text("{not json", encoding="utf-8")
    with pytest.raises(json.JSONDecodeError):
        parse_bundle(path)


# --- missing and malformed fields ----------------------------------------------------


def test_object_without_external_references_is_skipped_and_counted(tmp_path):
    obj = {"type": "attack-pattern", "id": "attack-pattern--x", "name": "No refs"}
    g = parse_bundle(write_bundle(tmp_path, [obj]))
    assert g.nodes == []
    assert g.skipped == 1


def test_object_with_only_foreign_references_is_skipped(tmp_path):
    """A CAPEC reference is not an ATT&CK id. Accepting it would corrupt every join."""
    obj = {
        "type": "attack-pattern",
        "id": "attack-pattern--x",
        "name": "Foreign refs only",
        "external_references": [{"source_name": "capec", "external_id": "CAPEC-1", "url": "u"}],
    }
    g = parse_bundle(write_bundle(tmp_path, [obj]))
    assert g.nodes == []
    assert g.skipped == 1


def test_mitre_reference_without_external_id_is_skipped(tmp_path):
    obj = {
        "type": "attack-pattern",
        "id": "attack-pattern--x",
        "name": "No external_id",
        "external_references": [{"source_name": "mitre-attack", "url": "u"}],
    }
    g = parse_bundle(write_bundle(tmp_path, [obj]))
    assert g.nodes == []
    assert g.skipped == 1


def test_object_without_a_name_falls_back_to_its_id(tmp_path):
    obj = {
        "type": "attack-pattern",
        "id": "attack-pattern--x",
        "external_references": [
            {"source_name": "mitre-attack", "external_id": "T0001", "url": "u"}
        ],
    }
    g = parse_bundle(write_bundle(tmp_path, [obj]))
    assert g.nodes[0].name == "T0001"


def test_missing_description_is_none_not_empty_string(tmp_path):
    """None means 'absent'. An empty string would embed as real (empty) text later."""
    g = parse_bundle(write_bundle(tmp_path, [technique("T0001")]))
    assert g.nodes[0].description is None


def test_reference_without_url_yields_empty_source_url(tmp_path):
    obj = {
        "type": "attack-pattern",
        "id": "attack-pattern--x",
        "name": "No url",
        "external_references": [{"source_name": "mitre-attack", "external_id": "T0001"}],
    }
    g = parse_bundle(write_bundle(tmp_path, [obj]))
    assert g.nodes[0].source_url == ""


# --- kill_chain_phases edge cases ----------------------------------------------------


def test_non_mitre_kill_chain_is_ignored(tmp_path):
    """Bundles carry lockheed-martin kill chains too; those are not our tactics."""
    obj = technique("T0001")
    obj["kill_chain_phases"] = [
        {"kill_chain_name": "lockheed-martin-cyber-kill-chain", "phase_name": "exploitation"}
    ]
    g = parse_bundle(write_bundle(tmp_path, [tactic("execution", "TA0002"), obj]))
    assert [e for e in g.edges if e.kind == "BELONGS_TO"] == []


def test_unknown_tactic_shortname_is_counted_not_crashed(tmp_path):
    """An upstream rename would otherwise take out the whole ingest."""
    g = parse_bundle(write_bundle(tmp_path, [technique("T0001", ["no-such-tactic"])]))
    assert [e for e in g.edges if e.kind == "BELONGS_TO"] == []
    assert g.skipped == 1


def test_technique_with_no_phases_produces_no_tactic_edge(tmp_path):
    g = parse_bundle(write_bundle(tmp_path, [technique("T0001")]))
    assert g.nodes[0].id == "technique:T0001"
    assert g.edges == []


def test_duplicate_phase_entries_produce_duplicate_edges(tmp_path):
    """Documented behavior: the upsert dedupes on (src, dst, kind), so the parser need not.

    Asserted so a future change to dedupe here is a deliberate decision, not a surprise.
    """
    obj = technique("T0001", ["execution", "execution"])
    g = parse_bundle(write_bundle(tmp_path, [tactic("execution", "TA0002"), obj]))
    assert len([e for e in g.edges if e.kind == "BELONGS_TO"]) == 2


# --- relationship edge cases ---------------------------------------------------------


def test_relationship_with_missing_refs_is_ignored(tmp_path):
    rel = {"type": "relationship", "id": "relationship--r", "relationship_type": "uses"}
    g = parse_bundle(write_bundle(tmp_path, [rel]))
    assert g.edges == []
    assert g.skipped == 1


def test_relationship_to_unknown_object_is_counted(tmp_path):
    rel = {
        "type": "relationship",
        "id": "relationship--r",
        "relationship_type": "uses",
        "source_ref": "intrusion-set--ghost",
        "target_ref": "attack-pattern--ghost",
    }
    g = parse_bundle(write_bundle(tmp_path, [rel]))
    assert g.edges == []
    assert g.skipped == 1


def test_unmodelled_relationship_type_is_not_counted_as_skipped(tmp_path):
    """`detects` is out of scope, not lost. The real bundle has thousands of them —
    counting those as skipped would drown the signal we actually watch."""
    rel = {
        "type": "relationship",
        "id": "relationship--r",
        "relationship_type": "detects",
        "source_ref": "x-mitre-data-source--a",
        "target_ref": "attack-pattern--b",
    }
    g = parse_bundle(write_bundle(tmp_path, [rel]))
    assert g.skipped == 0


def test_revoked_relationship_object_is_ignored(tmp_path):
    """Relationships themselves can be revoked, not just the objects they connect."""
    objs = [
        tactic("execution", "TA0002"),
        technique("T0001", ["execution"]),
        technique("T0002", ["execution"]),
        {
            "type": "relationship",
            "id": "relationship--r",
            "relationship_type": "subtechnique-of",
            "source_ref": "attack-pattern--T0001",
            "target_ref": "attack-pattern--T0002",
            "revoked": True,
        },
    ]
    g = parse_bundle(write_bundle(tmp_path, objs))
    assert [e for e in g.edges if e.kind == "SUBTECHNIQUE_OF"] == []


def test_wrong_kind_pair_for_relationship_type_is_ignored(tmp_path):
    """`uses` from a technique to a technique is not a shape we model."""
    objs = [
        tactic("execution", "TA0002"),
        technique("T0001", ["execution"]),
        technique("T0002", ["execution"]),
        {
            "type": "relationship",
            "id": "relationship--r",
            "relationship_type": "uses",
            "source_ref": "attack-pattern--T0001",
            "target_ref": "attack-pattern--T0002",
        },
    ]
    g = parse_bundle(write_bundle(tmp_path, objs))
    assert all(e.kind == "BELONGS_TO" for e in g.edges)


def test_self_referential_relationship_produces_a_self_loop(tmp_path):
    """Documented: the parser does not filter self-loops, but traversal must survive them.

    If this ever appears in real data, the traversal cycle guard is what saves us.
    """
    objs = [
        tactic("execution", "TA0002"),
        technique("T0001", ["execution"]),
        {
            "type": "relationship",
            "id": "relationship--r",
            "relationship_type": "subtechnique-of",
            "source_ref": "attack-pattern--T0001",
            "target_ref": "attack-pattern--T0001",
        },
    ]
    g = parse_bundle(write_bundle(tmp_path, objs))
    loops = [e for e in g.edges if e.src == e.dst]
    assert len(loops) == 1


# --- duplicates and collisions -------------------------------------------------------


def test_duplicate_attack_ids_collapse_to_one_node(tmp_path):
    """Two STIX objects claiming T0001 must not create two nodes — the id is the key."""
    a = technique("T0001", ["execution"])
    b = technique("T0001", ["execution"])
    b["id"] = "attack-pattern--other"
    b["name"] = "Second claimant"
    g = parse_bundle(write_bundle(tmp_path, [tactic("execution", "TA0002"), a, b]))
    ids = [n.id for n in g.nodes if n.kind == "technique"]
    assert ids == ["technique:T0001"]
    assert g.nodes[-1].name == "Second claimant"  # last write wins, deterministically


def test_same_external_id_across_kinds_does_not_collide(tmp_path):
    """kind is part of the id, so a tactic and a technique sharing digits stay distinct."""
    objs = [tactic("execution", "0001"), technique("0001", ["execution"])]
    g = parse_bundle(write_bundle(tmp_path, objs))
    assert {n.id for n in g.nodes} == {"tactic:0001", "technique:0001"}


def test_no_duplicate_node_ids(tmp_path):
    objs = [tactic("execution", "TA0002"), technique("T0001", ["execution"])]
    g = parse_bundle(write_bundle(tmp_path, objs))
    ids = [n.id for n in g.nodes]
    assert len(ids) == len(set(ids))


# --- invariants that must hold for any input -----------------------------------------


def test_every_node_id_matches_make_id(tmp_path):
    objs = [tactic("execution", "TA0002"), technique("T0001", ["execution"])]
    g = parse_bundle(write_bundle(tmp_path, objs))
    for n in g.nodes:
        assert n.id == Node.make_id(n.kind, n.external_id)


def test_no_edge_ever_dangles(tmp_path):
    """The single most important invariant: an edge to a missing node breaks traversal."""
    objs = [
        tactic("execution", "TA0002"),
        technique("T0001", ["execution"]),
        technique("T9998", ["execution"], revoked=True),
        {
            "type": "relationship",
            "id": "relationship--r",
            "relationship_type": "subtechnique-of",
            "source_ref": "attack-pattern--T9998",
            "target_ref": "attack-pattern--T0001",
        },
    ]
    g = parse_bundle(write_bundle(tmp_path, objs))
    ids = {n.id for n in g.nodes}
    assert all(e.src in ids and e.dst in ids for e in g.edges)


def test_parsing_is_deterministic(tmp_path):
    """Two runs must agree exactly, or the golden test and the eval table are both noise."""
    objs = [
        tactic("execution", "TA0002"),
        tactic("initial-access", "TA0001"),
        technique("T0001", ["execution", "initial-access"]),
        technique("T0002", ["execution"]),
    ]
    path = write_bundle(tmp_path, objs)
    first, second = parse_bundle(path), parse_bundle(path)
    assert [n.id for n in first.nodes] == [n.id for n in second.nodes]
    assert [(e.src, e.kind, e.dst) for e in first.edges] == [
        (e.src, e.kind, e.dst) for e in second.edges
    ]


# --- content the parser must not mangle ----------------------------------------------


def test_unicode_survives_intact(tmp_path):
    obj = technique("T0001")
    obj["name"] = "Tëchnïque — 攻撃 — «quoted»"
    obj["description"] = "Description with emoji 🔒 and a NULL-ish \\u0000 escape"
    g = parse_bundle(write_bundle(tmp_path, [obj]))
    assert g.nodes[0].name == "Tëchnïque — 攻撃 — «quoted»"


def test_very_long_description_is_not_truncated(tmp_path):
    """Long text gets split later, deliberately and with a known chunk size. A parser
    that truncates instead loses the tail of exactly the most detailed descriptions."""
    obj = technique("T0001")
    obj["description"] = "x" * 200_000
    g = parse_bundle(write_bundle(tmp_path, [obj]))
    assert len(g.nodes[0].description) == 200_000


def test_sql_injection_shaped_text_is_stored_verbatim(tmp_path):
    """Parameterized queries make this safe; the assertion documents that we rely on it."""
    obj = technique("T0001")
    obj["name"] = "'; DROP TABLE nodes; --"
    g = parse_bundle(write_bundle(tmp_path, [obj]))
    assert g.nodes[0].name == "'; DROP TABLE nodes; --"


# --- scale -----------------------------------------------------------------------------


@pytest.mark.slow
def test_parses_a_large_synthetic_bundle(tmp_path):
    """5k techniques across 14 tactics — roughly 8x the real bundle."""
    tactics = [tactic(f"tac-{i}", f"TA{i:04d}") for i in range(14)]
    techniques = [technique(f"T{i:05d}", [f"tac-{i % 14}"]) for i in range(5000)]
    g = parse_bundle(write_bundle(tmp_path, tactics + techniques))
    assert len(g.nodes) == 5014
    assert len([e for e in g.edges if e.kind == "BELONGS_TO"]) == 5000
    assert g.skipped == 0


@pytest.mark.slow
@pytest.mark.skipif(not REAL_BUNDLE.exists(), reason="real bundle not downloaded")
def test_real_bundle_invariants():
    """The hard gates, against the actual snapshot rather than a hand-built bundle.

    Twelve inline objects cannot show that the parser survives 26,000 real ones. This is
    the only test that reads the file the graph is really built from.
    """
    g = parse_bundle(REAL_BUNDLE)
    ids = {n.id for n in g.nodes}

    techniques = {n.id for n in g.nodes if n.kind == "technique"}
    with_tactic = {e.src for e in g.edges if e.kind == "BELONGS_TO"}
    assert techniques - with_tactic == set(), "techniques with no tactic"

    dangling = [e for e in g.edges if e.src not in ids or e.dst not in ids]
    assert dangling == [], f"{len(dangling)} dangling edges"


@pytest.mark.slow
@pytest.mark.skipif(not REAL_BUNDLE.exists(), reason="real bundle not downloaded")
def test_real_bundle_yields_every_live_tactic():
    """Asserts correspondence with the bundle, not a fixed number.

    The phase doc says "exactly 14 tactics". That was true when it was written and is not
    now: v19.2 renamed TA0005 Defense Evasion to Stealth and split TA0112 Defense
    Impairment out of it, making 15. A pinned count fails on every upstream release for a
    reason that has nothing to do with this parser, and the third time that happens
    someone deletes the test.

    What must hold for any release is that every live tactic object in the bundle becomes
    a tactic node. The band below is only there so a catastrophic misread — zero tactics,
    or every object treated as one — still fails loudly.
    """
    raw = json.loads(REAL_BUNDLE.read_text(encoding="utf-8"))
    expected = {
        o["id"]
        for o in raw["objects"]
        if o.get("type") == "x-mitre-tactic"
        and not (o.get("revoked") or o.get("x_mitre_deprecated"))
    }

    g = parse_bundle(REAL_BUNDLE)
    parsed = {n.stix_id for n in g.nodes if n.kind == "tactic"}

    assert parsed == expected
    assert 10 <= len(parsed) <= 25, f"{len(parsed)} tactics is not a plausible enterprise matrix"


@pytest.mark.slow
@pytest.mark.skipif(not REAL_BUNDLE.exists(), reason="real bundle not downloaded")
def test_real_bundle_loses_almost_nothing():
    """The skipped count is a data-loss alarm, and an alarm has to be readable.

    On v19.2 this is 605: 446 revoked or deprecated objects, plus the edges that pointed
    at them. Before out-of-scope relationships were separated out it read 1,723, three
    quarters of which were `uses` edges to `campaign` objects — a type this schema does
    not model, and not a loss at all.

    The bound is deliberately loose. It is here to catch a parser that starts dropping
    thousands of objects, not to pin a number that shifts with every release.
    """
    g = parse_bundle(REAL_BUNDLE)
    total = len(json.loads(REAL_BUNDLE.read_text(encoding="utf-8"))["objects"])
    assert g.skipped < total * 0.05, f"skipped {g.skipped} of {total} objects"


# --- ignored is not lost --------------------------------------------------------------


def _actor(ext_id: str) -> dict:
    return {
        "type": "intrusion-set",
        "id": f"intrusion-set--{ext_id}",
        "name": f"Actor {ext_id}",
        "external_references": [{"source_name": "mitre-attack", "external_id": ext_id, "url": "u"}],
    }


def _uses(src: str, dst: str) -> dict:
    return {
        "type": "relationship",
        "id": f"relationship--{src}-{dst}",
        "relationship_type": "uses",
        "source_ref": src,
        "target_ref": dst,
    }


def test_relationships_to_unmodelled_object_types_are_not_counted_as_skipped(tmp_path):
    """The skipped count is a data-loss alarm, so out-of-scope must not inflate it.

    ATT&CK v19.2 carries 1,318 `uses` relationships pointing at `campaign` objects, a STIX
    type this schema does not model. Counting them as skipped made the real bundle report
    1,723 losses when only 2 objects were actually lost — an alarm nobody can read.
    """
    objs = [
        tactic("execution", "TA0002"),
        technique("T1059", ["execution"]),
        _actor("G0001"),
        {"type": "campaign", "id": "campaign--c1", "name": "Some Campaign"},
        _uses("intrusion-set--G0001", "campaign--c1"),
    ]
    g = parse_bundle(write_bundle(tmp_path, objs))

    assert g.skipped == 0, "a relationship to a type we never model is out of scope, not lost"
    assert {n.id for n in g.nodes} == {"tactic:TA0002", "technique:T1059", "actor:G0001"}


def test_relationships_to_a_filtered_modelled_object_are_still_counted_as_skipped(tmp_path):
    """The other half of the distinction. A revoked technique IS a type we model, so an
    edge to it is real loss and has to stay visible."""
    objs = [
        tactic("execution", "TA0002"),
        technique("T1059", ["execution"]),
        technique("T9999", ["execution"], revoked=True),
        _actor("G0001"),
        _uses("intrusion-set--G0001", "attack-pattern--T9999"),
    ]
    g = parse_bundle(write_bundle(tmp_path, objs))

    # 1 for the revoked technique itself, 1 for the edge that pointed at it.
    assert g.skipped == 2
    assert all("T9999" not in e.dst for e in g.edges)


def test_a_relationship_to_an_id_absent_from_the_bundle_is_counted_as_skipped(tmp_path):
    """An unresolvable reference is a broken bundle, not a modelling choice. Treating it
    as out of scope would hide a genuinely truncated upstream release."""
    objs = [
        tactic("execution", "TA0002"),
        technique("T1059", ["execution"]),
        _actor("G0001"),
        _uses("intrusion-set--G0001", "attack-pattern--DOES-NOT-EXIST"),
    ]
    g = parse_bundle(write_bundle(tmp_path, objs))
    assert g.skipped == 1
