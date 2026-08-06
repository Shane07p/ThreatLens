"""Mappings parser tests.

The weights (primary=1.0, secondary=0.5) and the skip/emit distinction are
the critical paths. The parser must not silently swallow anything — a row
it cannot use is counted, and a row pointing at an unknown technique is
emitted for the loader to decide on.
"""

from pathlib import Path

import pytest

from threatlens.ingest.mappings import parse_mappings_csv

FIXTURE = Path(__file__).parent.parent / "fixtures" / "mini-mappings.csv"


@pytest.fixture(scope="module")
def parsed():
    return parse_mappings_csv(FIXTURE)


# --- Edge weights ---


def test_primary_impact_weight_is_one(parsed):
    edges, _ = parsed
    e = next(e for e in edges if e.src == "cve:CVE-2021-44228" and e.dst == "technique:T1059")
    assert e.weight == pytest.approx(1.0)


def test_secondary_impact_weight_is_half(parsed):
    edges, _ = parsed
    e = next(e for e in edges if e.src == "cve:CVE-2021-44228" and e.dst == "technique:T1190")
    assert e.weight == pytest.approx(0.5)


# --- Edge kind ---


def test_edge_kind_is_enables(parsed):
    edges, _ = parsed
    assert {e.kind for e in edges} == {"ENABLES"}


# --- Skip handling ---


def test_rows_without_a_cve_id_are_counted_not_crashed(parsed):
    _, skipped = parsed
    assert skipped == 1


# --- Secondary-only rows ---


def test_secondary_only_row_still_produces_an_edge(parsed):
    """CVE-2019-0708 has no primary impact — only secondary. Must still emit."""
    edges, _ = parsed
    e = next(e for e in edges if e.src == "cve:CVE-2019-0708")
    assert e.dst == "technique:T1210"
    assert e.weight == pytest.approx(0.5)


# --- Unknown technique ---


def test_unknown_technique_is_still_emitted(parsed):
    """The loader drops unresolvable edges; the parser does not silently swallow them."""
    edges, _ = parsed
    assert any(e.dst == "technique:T9998" for e in edges)


# --- Provenance ---


def test_source_is_recorded(parsed):
    edges, _ = parsed
    assert all(e.source for e in edges)


def test_impact_type_recorded_in_attrs(parsed):
    """We track whether each edge came from primary or secondary for later analysis."""
    edges, _ = parsed
    primary = next(e for e in edges if e.src == "cve:CVE-2021-44228" and e.dst == "technique:T1059")
    secondary = next(
        e for e in edges if e.src == "cve:CVE-2021-44228" and e.dst == "technique:T1190"
    )
    assert primary.attrs["impact"] == "primary"
    assert secondary.attrs["impact"] == "secondary"


# --- Determinism ---


def test_parsing_is_deterministic():
    """Same input twice → identical output. Silent nondeterminism is a time bomb."""
    result_a = parse_mappings_csv(FIXTURE)
    result_b = parse_mappings_csv(FIXTURE)
    assert result_a == result_b


# --- Total edge count ---


def test_total_edge_count(parsed):
    """6 rows: row 1 yields 2 edges, rows 2-4 yield 1 each, row 5 skipped, row 6 yields 1."""
    edges, _ = parsed
    assert len(edges) == 7
