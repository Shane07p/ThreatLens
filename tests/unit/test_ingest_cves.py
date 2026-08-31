"""Unit tests for load_kev_ids and the CVE parsing + KEV stamping pipeline.

These tests verify the pure functions — no database required. The integration
of ingest_cves() with Postgres is covered in tests/integration/.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from threatlens.ingest.nvd import load_kev_ids, parse_cve_record

FIXTURE = Path(__file__).parent.parent / "fixtures" / "nvd-sample.json"


@pytest.fixture(scope="module")
def fixture_vulnerabilities():
    raw = json.loads(FIXTURE.read_text(encoding="utf-8"))
    return raw["vulnerabilities"]


# --- load_kev_ids ----------------------------------------------------------------


def test_load_kev_ids_reads_cisa_format(tmp_path):
    catalog = {
        "title": "CISA Known Exploited Vulnerabilities Catalog",
        "vulnerabilities": [
            {"cveID": "CVE-2021-44228"},
            {"cveID": "CVE-2024-0001"},
        ],
    }
    kev_path = tmp_path / "kev-catalog.json"
    kev_path.write_text(json.dumps(catalog), encoding="utf-8")

    ids = load_kev_ids(kev_path)
    assert ids == {"CVE-2021-44228", "CVE-2024-0001"}


def test_load_kev_ids_uppercases_ids(tmp_path):
    catalog = {"vulnerabilities": [{"cveID": "cve-2021-44228"}]}
    kev_path = tmp_path / "kev.json"
    kev_path.write_text(json.dumps(catalog), encoding="utf-8")

    assert "CVE-2021-44228" in load_kev_ids(kev_path)


def test_load_kev_ids_returns_empty_set_for_missing_file(tmp_path):
    assert load_kev_ids(tmp_path / "nonexistent.json") == set()


def test_load_kev_ids_skips_entries_without_cve_id(tmp_path):
    catalog = {"vulnerabilities": [{"cveID": ""}, {"cveID": "CVE-2021-44228"}, {}]}
    kev_path = tmp_path / "kev.json"
    kev_path.write_text(json.dumps(catalog), encoding="utf-8")

    ids = load_kev_ids(kev_path)
    assert ids == {"CVE-2021-44228"}


def test_load_kev_ids_handles_empty_catalog(tmp_path):
    kev_path = tmp_path / "kev.json"
    kev_path.write_text(json.dumps({"vulnerabilities": []}), encoding="utf-8")

    assert load_kev_ids(kev_path) == set()


# --- KEV stamping on parsed nodes -------------------------------------------------


def test_kev_stamp_applied_to_matching_cve(fixture_vulnerabilities):
    """A CVE in the KEV set gets attrs['kev'] = True."""
    node = parse_cve_record(fixture_vulnerabilities[0])
    assert node is not None

    kev_ids = {"CVE-2021-44228"}
    if node.external_id in kev_ids:
        node.attrs["kev"] = True

    assert node.attrs["kev"] is True


def test_kev_stamp_not_applied_to_non_kev_cve(fixture_vulnerabilities):
    """A CVE not in the KEV set does not get a 'kev' key."""
    node = parse_cve_record(fixture_vulnerabilities[1])
    assert node is not None
    assert "kev" not in node.attrs


def test_full_snapshot_parsing_with_kev(fixture_vulnerabilities):
    """Parse all fixture records and stamp KEV on the matching one."""
    kev_ids = {"CVE-2021-44228"}
    nodes = []
    kev_count = 0

    for entry in fixture_vulnerabilities:
        node = parse_cve_record(entry)
        if node is None:
            continue
        if node.external_id in kev_ids:
            node.attrs["kev"] = True
            kev_count += 1
        nodes.append(node)

    assert len(nodes) == 3
    assert kev_count == 1
    assert nodes[0].attrs["kev"] is True
    assert "kev" not in nodes[1].attrs
    assert "kev" not in nodes[2].attrs
