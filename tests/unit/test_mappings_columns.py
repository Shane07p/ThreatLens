"""Which mapping columns become ENABLES edges, and at what weight.

The upstream file has four technique columns. All four are read, weighted by how directly
the column ties the CVE to the technique:

    Primary Impact          1.0   what exploiting the CVE achieves
    Secondary Impact        0.5   a further consequence
    Exploitation Technique  0.5   how the CVE is exploited
    Uncategorized           0.25  mapped by MITRE, role not stated

Reading only the two impact columns left 451 of 836 CVEs with no edge at all: their
techniques sit only under `Uncategorized`. That halved the ground truth and made a 20%
holdout about 75 CVEs, too small for a gap between two configurations to reach
significance. With all four columns, 822 CVEs have edges and the holdout is about 164.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from threatlens.ingest.mappings import parse_mappings_csv

HEADER = "CVE ID,Primary Impact,Secondary Impact,Exploitation Technique,Uncategorized,Phase"


def write_csv(tmp_path: Path, body: str, header: str = HEADER) -> Path:
    path = tmp_path / "mappings.csv"
    path.write_text(header + "\n" + body, encoding="utf-8")
    return path


def edges_of(tmp_path: Path, body: str) -> dict[tuple[str, str], tuple[float, str]]:
    edges, _ = parse_mappings_csv(write_csv(tmp_path, body))
    return {(e.src, e.dst): (e.weight, e.attrs["impact"]) for e in edges}


@pytest.mark.parametrize(
    ("row", "weight", "impact"),
    [
        ("CVE-2020-0001,T1059,,,,", 1.0, "primary"),
        ("CVE-2020-0001,,T1059,,,", 0.5, "secondary"),
        ("CVE-2020-0001,,,T1059,,", 0.5, "exploitation"),
        ("CVE-2020-0001,,,,T1059,", 0.25, "uncategorized"),
    ],
    ids=["primary", "secondary", "exploitation", "uncategorized"],
)
def test_each_column_yields_an_edge_at_its_weight(tmp_path, row, weight, impact):
    got = edges_of(tmp_path, row + "\n")
    assert got == {("cve:CVE-2020-0001", "technique:T1059"): (weight, impact)}


def test_a_cve_mapped_only_under_uncategorized_still_gets_its_edges(tmp_path):
    """451 real CVEs look like this. Under the impact-only rule they had no route into
    ATT&CK at all."""
    got = edges_of(tmp_path, 'CVE-2020-0002,,,,"T1190; T1078",Phase 1\n')
    assert got == {
        ("cve:CVE-2020-0002", "technique:T1190"): (0.25, "uncategorized"),
        ("cve:CVE-2020-0002", "technique:T1078"): (0.25, "uncategorized"),
    }


@pytest.mark.parametrize(
    ("row", "weight", "impact"),
    [
        ("CVE-2020-0003,,,,T1059; T1059,", 0.25, "uncategorized"),
        ("CVE-2020-0003,,,T1059,T1059,", 0.5, "exploitation"),
        ("CVE-2020-0003,,T1059,T1059,T1059,", 0.5, "secondary"),
        ("CVE-2020-0003,T1059,,T1059,T1059,", 1.0, "primary"),
    ],
    ids=[
        "uncategorized-only",
        "exploitation-beats-uncategorized",
        "secondary-wins-ties",
        "primary",
    ],
)
def test_a_technique_in_several_columns_keeps_its_strongest_weight(tmp_path, row, weight, impact):
    """One edge per pair. Secondary and exploitation both weigh 0.5; the tie goes to the
    column that comes first in the file, so the result does not depend on dict order."""
    got = edges_of(tmp_path, row + "\n")
    assert got == {("cve:CVE-2020-0003", "technique:T1059"): (weight, impact)}


@pytest.mark.parametrize(
    "body",
    [
        "CVE-2020-0006,,,T1059,,\nCVE-2020-0006,,T1059,,,\n",
        "CVE-2020-0006,,T1059,,,\nCVE-2020-0006,,,T1059,,\n",
    ],
    ids=["exploitation-row-first", "secondary-row-first"],
)
def test_a_tie_across_rows_names_the_same_column_in_either_order(tmp_path, body):
    """Both orders, because with one order "first wins" passes by coincidence."""
    got = edges_of(tmp_path, body)
    assert got == {("cve:CVE-2020-0006", "technique:T1059"): (0.5, "secondary")}


def test_a_weaker_listing_on_a_later_row_never_lowers_a_weight(tmp_path):
    got = edges_of(tmp_path, "CVE-2020-0004,,,T1059,,\nCVE-2020-0004,,,,T1059,\n")
    assert got == {("cve:CVE-2020-0004", "technique:T1059"): (0.5, "exploitation")}


@pytest.mark.parametrize("dropped", ["Exploitation Technique", "Uncategorized"])
def test_a_missing_technique_column_fails_loudly(tmp_path, dropped):
    """A column the parser reads must be present. If upstream renamed `Uncategorized`, the
    parser would otherwise lose more than half its ground truth and report success."""
    header = ",".join(c for c in HEADER.split(",") if c != dropped)
    path = write_csv(tmp_path, "CVE-2020-0005,T1059,,,\n", header=header)
    with pytest.raises(ValueError, match=dropped):
        parse_mappings_csv(path)
