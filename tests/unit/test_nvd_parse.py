"""CVE record parser tests.

The CVSS fallback chain and the missing-score case are the critical paths.
A fabricated 0.0 severity reads as "no risk" in an answer — that is not
a rounding error, it is a wrong answer someone may act on.
"""

import json
from pathlib import Path

import pytest

from threatlens.ingest.nvd import parse_cve_record

FIXTURE = Path(__file__).parent.parent / "fixtures" / "nvd-sample.json"


@pytest.fixture(scope="module")
def records():
    raw = json.loads(FIXTURE.read_text(encoding="utf-8"))
    return {v["cve"]["id"]: parse_cve_record(v["cve"]) for v in raw["vulnerabilities"]}


# --- Node identity ---


def test_node_id_follows_convention(records):
    n = records["CVE-2021-44228"]
    assert n.id == "cve:CVE-2021-44228"
    assert n.kind == "cve"
    assert n.external_id == "CVE-2021-44228"


# --- Description handling ---


def test_prefers_english_description(records):
    """Spanish translation must not leak through."""
    assert records["CVE-2021-44228"].description.startswith("Apache Log4j2")


# --- CVSS fallback chain ---


def test_cvss_v31_preferred(records):
    assert records["CVE-2021-44228"].attrs["cvss_score"] == pytest.approx(10.0)
    assert records["CVE-2021-44228"].attrs["cvss_version"] == "3.1"


def test_cvss_v40_accepted_when_v31_absent(records):
    assert records["CVE-2024-0001"].attrs["cvss_score"] == pytest.approx(7.5)
    assert records["CVE-2024-0001"].attrs["cvss_version"] == "4.0"


def test_missing_score_is_none_not_zero(records):
    """A fabricated 0.0 severity would surface in an answer as 'no risk'."""
    assert records["CVE-2024-0002"].attrs["cvss_score"] is None
    assert records["CVE-2024-0002"].attrs["cvss_score"] != 0.0


def test_cvss_vector_string_is_captured(records):
    assert "CVSS:3.1/" in records["CVE-2021-44228"].attrs["cvss_vector"]


# --- Source URL ---


def test_source_url_is_the_nvd_page(records):
    assert records["CVE-2021-44228"].source_url == (
        "https://nvd.nist.gov/vuln/detail/CVE-2021-44228"
    )


# --- Metadata ---


def test_published_date_is_kept(records):
    assert records["CVE-2021-44228"].attrs["published"].startswith("2021-12-10")


def test_references_are_extracted(records):
    refs = records["CVE-2021-44228"].attrs["references"]
    assert "https://logging.apache.org/log4j/2.x/security.html" in refs


def test_empty_references_produce_empty_list(records):
    assert records["CVE-2024-0002"].attrs["references"] == []


# --- Robustness ---


def test_record_without_id_returns_none():
    assert parse_cve_record({"descriptions": []}) is None


def test_record_with_empty_id_returns_none():
    assert parse_cve_record({"id": "", "descriptions": []}) is None


def test_record_with_empty_metrics_has_none_score():
    node = parse_cve_record(
        {
            "id": "CVE-9999-0001",
            "descriptions": [{"lang": "en", "value": "test"}],
            "metrics": {},
        }
    )
    assert node is not None
    assert node.attrs["cvss_score"] is None


def test_node_is_frozen(records):
    """Domain objects are immutable — a value cannot be changed behind its owner's back."""
    with pytest.raises(AttributeError):
        records["CVE-2021-44228"].name = "tampered"
