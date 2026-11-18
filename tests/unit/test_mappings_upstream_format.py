"""The mappings CSV as it really arrives, not as a tidy hand-written fixture.

Every existing mappings test passed while the real file produced **zero** edges. The
upstream CSV starts with a UTF-8 byte-order mark, so under plain `utf-8` its first header is
`\\ufeffCVE ID`, the lookup of `"CVE ID"` misses on every row, and all 839 rows are skipped
without an error. It also packs several techniques into one cell (`T1499; T1098`) in 86
places, which the parser turned into a single nonsense node id.

`mappings-upstream-sample.csv` is a byte-exact excerpt of the upstream file — BOM, CRLF line
endings, compound cells, and a CVE listed on two rows — so these tests exercise the format
the parser actually has to read. Robustness cases the upstream file does not happen to
contain are built inline.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from threatlens.ingest.fetch import collect_scoped_cve_ids
from threatlens.ingest.mappings import parse_mappings_csv

UPSTREAM = Path(__file__).parent.parent / "fixtures" / "mappings-upstream-sample.csv"
REAL_FILE = Path("data/raw/Att&ckToCveMappings.csv")
TECHNIQUE_ID = re.compile(r"^technique:T\d{4}(\.\d{3})?$")

HEADER = "CVE ID,Primary Impact,Secondary Impact,Exploitation Technique,Uncategorized,Phase"


def write_csv(tmp_path: Path, body: str, *, bom: bool = True) -> Path:
    """Write a mappings CSV the way upstream does: optional BOM, CRLF line endings."""
    text = (HEADER + "\n" + body).replace("\n", "\r\n")
    path = tmp_path / "mappings.csv"
    path.write_bytes((b"\xef\xbb\xbf" if bom else b"") + text.encode("utf-8"))
    return path


def pairs(edges) -> dict[tuple[str, str], float]:
    return {(e.src, e.dst): e.weight for e in edges}


# --- the upstream format ----------------------------------------------------------------


def test_the_fixture_really_starts_with_a_byte_order_mark():
    """Guards the guard. If an editor or git ever strips the BOM, every test below would pass
    for the wrong reason."""
    assert UPSTREAM.read_bytes().startswith(b"\xef\xbb\xbf")


def test_a_byte_order_mark_does_not_hide_the_header():
    edges, skipped = parse_mappings_csv(UPSTREAM)
    assert edges, "a BOM-prefixed file must still produce edges"
    assert skipped == 0


def test_each_technique_in_a_shared_cell_becomes_its_own_edge():
    edges, _ = parse_mappings_csv(UPSTREAM)
    got = pairs(edges)
    assert got[("cve:CVE-2019-15956", "technique:T1499")] == 1.0
    assert got[("cve:CVE-2019-15956", "technique:T1098")] == 1.0


def test_a_shared_secondary_cell_splits_at_secondary_weight():
    edges, _ = parse_mappings_csv(UPSTREAM)
    got = pairs(edges)
    assert got[("cve:CVE-2019-1942", "technique:T1005")] == 0.5
    assert got[("cve:CVE-2019-1942", "technique:T1565.001")] == 0.5
    assert got[("cve:CVE-2019-1942", "technique:T1059")] == 1.0


def test_every_destination_is_a_well_formed_technique_id():
    """The invariant the old parser broke: no id may contain a separator or a space."""
    edges, _ = parse_mappings_csv(UPSTREAM)
    bad = [e.dst for e in edges if not TECHNIQUE_ID.match(e.dst)]
    assert bad == []


def test_a_cve_listed_on_two_rows_yields_one_edge_per_technique():
    """CVE-2018-11049 appears twice upstream: once with a primary impact, once with only an
    Uncategorized sub-technique."""
    edges, _ = parse_mappings_csv(UPSTREAM)
    for_cve = [e for e in edges if e.src == "cve:CVE-2018-11049"]
    assert [(e.dst, e.weight) for e in for_cve] == [
        ("technique:T1574", 1.0),
        ("technique:T1574.008", 0.25),
    ]


def test_the_sample_produces_exactly_the_expected_edges():
    """Read by hand against the fixture, column by column:

    - impact columns: 2+2 ordinary, 2 from a split primary cell, 1+2 from CVE-2019-1942,
      1 from the duplicated CVE (10)
    - Exploitation Technique: 1+1, 2 from each of two split cells (6)
    - Uncategorized: 1 on the duplicated CVE's second row (1)
    """
    edges, _ = parse_mappings_csv(UPSTREAM)
    assert len(edges) == 17
    assert len(pairs(edges)) == len(edges), "no (cve, technique) pair may appear twice"


# --- robustness ---------------------------------------------------------------------------


def test_a_technique_in_both_columns_keeps_the_primary_weight(tmp_path):
    """Explicit policy: one edge per pair, at its strongest weight."""
    path = write_csv(tmp_path, "CVE-2020-0001,T1059,T1059; T1105,,,\n")
    got = pairs(parse_mappings_csv(path)[0])
    assert got == {
        ("cve:CVE-2020-0001", "technique:T1059"): 1.0,
        ("cve:CVE-2020-0001", "technique:T1105"): 0.5,
    }


@pytest.mark.parametrize(
    "body",
    [
        "CVE-2020-0002,,T1059,,,\nCVE-2020-0002,T1059,,,,\n",
        "CVE-2020-0002,T1059,,,,\nCVE-2020-0002,,T1059,,,\n",
    ],
    ids=["secondary-first", "primary-first"],
)
def test_duplicate_rows_never_lower_a_weight(tmp_path, body):
    """Order must not matter, so both orders are tested. With only one, "first wins" or
    "last wins" each passes by coincidence — mutation testing caught exactly that."""
    path = write_csv(tmp_path, body)
    got = pairs(parse_mappings_csv(path)[0])
    assert got == {("cve:CVE-2020-0002", "technique:T1059"): 1.0}


def test_an_invalid_token_is_counted_and_the_valid_ones_are_kept(tmp_path):
    """A malformed token is lost data, so it counts as skipped — and it must not take the
    valid techniques in the same cell down with it."""
    path = write_csv(tmp_path, "CVE-2020-0003,T1059; Phishing; T99,,,,\n")
    edges, skipped = parse_mappings_csv(path)
    assert pairs(edges) == {("cve:CVE-2020-0003", "technique:T1059"): 1.0}
    assert skipped == 2


@pytest.mark.parametrize(
    "cell",
    ["T1059;T1105", "T1059 ; T1105", "T1059,T1105", " T1059;  T1105 ;", "t1059; t1105"],
)
def test_separator_and_spacing_variants_all_split_the_same_way(tmp_path, cell):
    path = write_csv(tmp_path, f'CVE-2020-0004,"{cell}",,,,\n')
    got = set(pairs(parse_mappings_csv(path)[0]))
    assert got == {
        ("cve:CVE-2020-0004", "technique:T1059"),
        ("cve:CVE-2020-0004", "technique:T1105"),
    }


def test_a_file_without_a_bom_still_parses(tmp_path):
    """The fix must not depend on the BOM being there."""
    path = write_csv(tmp_path, "CVE-2020-0005,T1059,,,,\n", bom=False)
    assert pairs(parse_mappings_csv(path)[0]) == {("cve:CVE-2020-0005", "technique:T1059"): 1.0}


def test_a_missing_required_column_fails_loudly(tmp_path):
    """A renamed upstream column would otherwise skip every row and report success."""
    path = tmp_path / "mappings.csv"
    path.write_text("CVE,Primary,Secondary\nCVE-2020-0006,T1059,\n", encoding="utf-8")
    with pytest.raises(ValueError, match="CVE ID"):
        parse_mappings_csv(path)


def test_rows_that_yield_no_edges_at_all_fail_loudly(tmp_path):
    """The exact shape of the original bug: data present, nothing usable. Zero edges from a
    non-empty file is never a legitimate result."""
    path = write_csv(tmp_path, "CVE-2020-0007,Phishing,,,,\n,T1059,,,,\n")
    with pytest.raises(ValueError, match="no usable"):
        parse_mappings_csv(path)


def test_a_header_only_file_is_empty_not_an_error(tmp_path):
    """No rows is a legitimate (if useless) input; only rows-without-edges is suspicious."""
    path = write_csv(tmp_path, "")
    assert parse_mappings_csv(path) == ([], 0)


def test_parsing_is_deterministic():
    first = [(e.src, e.dst, e.weight) for e in parse_mappings_csv(UPSTREAM)[0]]
    second = [(e.src, e.dst, e.weight) for e in parse_mappings_csv(UPSTREAM)[0]]
    assert first == second


# --- the second reader of the same file ---------------------------------------------------


def test_the_scoped_cve_collector_reads_the_bom_file_too():
    """`fetch nvd` decides which CVEs to download from this same CSV. With the BOM bug it
    collected nothing from the mappings, so the NVD pull covered the KEV catalog only."""
    cves, invalid = collect_scoped_cve_ids(UPSTREAM, kev_data={"vulnerabilities": []})
    assert {"CVE-2019-15956", "CVE-2019-1942", "CVE-2018-11049"} <= set(cves)
    assert invalid == []


# --- the real file, when it has been fetched ------------------------------------------------


@pytest.mark.slow
@pytest.mark.skipif(not REAL_FILE.exists(), reason="mappings snapshot not fetched")
def test_the_real_snapshot_produces_its_full_edge_set():
    """839 upstream rows hold 1,682 distinct (CVE, technique) pairs across the four technique
    columns once compound cells are split (658 from the two impact columns alone). A loose
    floor rather than the exact count, so an upstream refresh does not turn this red on its
    own.

    The impact columns are clean. `Uncategorized` carries 23 malformed tokens (`T1078.003.`,
    `TT1565`, `T828`), each counted as skipped, so `skipped` is bounded rather than zero."""
    edges, skipped = parse_mappings_csv(REAL_FILE)
    assert len(edges) > 1500
    assert skipped < 50
    assert all(TECHNIQUE_ID.match(e.dst) for e in edges)
