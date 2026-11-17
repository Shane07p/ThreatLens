"""Absent data and corrupt data must stay distinguishable.

The parser is tolerant: a malformed field never crashes an ingest. But tolerance that drops a
field silently makes a corrupt `baseScore: "high"` look exactly like a CVE that genuinely has
no score — and the graph would then present corrupted upstream data as honest absence.

So a field that is *absent or null* is quiet missing data, while a field that is *present but
unusable* is logged with the CVE id, recorded on the node under `malformed_fields`, and
counted by the ingest.
"""

from __future__ import annotations

import json
import logging

import pytest
from hypothesis import given
from hypothesis import strategies as st

from threatlens.ingest import nvd
from threatlens.ingest.nvd import MALFORMED_FIELD_NAMES, parse_cve_record

CVE = "CVE-2024-0001"


def record(**fields) -> dict:
    return {"id": CVE, "descriptions": [{"lang": "en", "value": "A flaw."}], **fields}


def metrics(**cvss_data) -> dict:
    return {"cvssMetricV31": [{"cvssData": cvss_data}]}


# --- absent is not malformed -------------------------------------------------------------


def test_a_record_with_no_metrics_has_no_malformed_fields(caplog):
    node = parse_cve_record(record())
    assert "malformed_fields" not in node.attrs
    assert not [r for r in caplog.records if r.levelno >= logging.WARNING]


def test_explicit_nulls_are_absence_not_corruption():
    node = parse_cve_record(record(metrics=None, references=None, published=None))
    assert "malformed_fields" not in node.attrs


def test_a_valid_record_has_no_malformed_fields():
    node = parse_cve_record(
        record(metrics=metrics(baseScore=9.8, vectorString="CVSS:3.1/AV:N"), published="2024-01-01")
    )
    assert "malformed_fields" not in node.attrs
    assert node.attrs["cvss_score"] == 9.8


# --- present but unusable is malformed -----------------------------------------------------


@pytest.mark.parametrize("bad_score", ["high", True, 11.0, -1, [9.8]])
def test_an_unusable_score_is_flagged_not_silently_dropped(bad_score):
    node = parse_cve_record(record(metrics=metrics(baseScore=bad_score)))
    assert node.attrs["cvss_score"] is None
    assert node.attrs["malformed_fields"] == ["cvss_score"]


@pytest.mark.parametrize(
    ("fields", "expected"),
    [
        ({"descriptions": "a string, not a list"}, ["descriptions"]),
        ({"descriptions": [None]}, ["descriptions"]),
        ({"metrics": "not a dict"}, ["metrics"]),
        ({"metrics": {"cvssMetricV31": "not a list"}}, ["metrics"]),
        ({"metrics": {"cvssMetricV31": [None]}}, ["metrics"]),
        ({"metrics": metrics(baseScore=5.0, vectorString=42)}, ["cvss_vector"]),
        ({"references": "https://example.test"}, ["references"]),
        ({"published": 20240101}, ["published"]),
        ({"lastModified": ["2024"]}, ["last_modified"]),
    ],
)
def test_each_kind_of_corruption_is_named(fields, expected):
    node = parse_cve_record({"id": CVE, **fields})
    assert node.attrs["malformed_fields"] == expected


def test_a_bad_reference_is_flagged_and_the_good_ones_are_kept():
    node = parse_cve_record(record(references=[None, {"url": 5}, {"url": "https://nvd.test/a"}]))
    assert node.attrs["references"] == ["https://nvd.test/a"]
    assert node.attrs["malformed_fields"] == ["references"]


def test_several_corrupt_fields_are_listed_once_each_in_order():
    node = parse_cve_record(
        {"id": CVE, "references": [None, None], "metrics": metrics(baseScore="x"), "published": 1}
    )
    assert node.attrs["malformed_fields"] == ["cvss_score", "published", "references"]


def test_the_warning_names_the_cve_and_the_field(caplog):
    with caplog.at_level(logging.WARNING, logger="threatlens.ingest.nvd"):
        parse_cve_record(record(metrics=metrics(baseScore="high")))
    message = " ".join(r.getMessage() for r in caplog.records)
    assert CVE in message
    assert "cvss_score" in message


# --- the ingest counts them ---------------------------------------------------------------


def test_ingest_reports_how_many_records_lost_data(tmp_path, monkeypatch, caplog):
    """The run-level number that makes upstream corruption visible at a glance."""
    snapshot = tmp_path / "nvd-scoped.json"
    snapshot.write_text(
        json.dumps(
            {
                "vulnerabilities": [
                    {"cve": record(metrics=metrics(baseScore="high"))},
                    {"cve": {"id": "CVE-2024-0002", "published": 7}},
                    {"cve": {"id": "CVE-2024-0003"}},
                ]
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr("threatlens.graph.store.upsert_nodes", lambda conn, nodes: len(nodes))
    monkeypatch.setattr("threatlens.graph.store.record_ingest_run", lambda *a, **k: 1)

    with caplog.at_level(logging.WARNING, logger="threatlens.ingest.nvd"):
        n_nodes, kev_count = nvd.ingest_cves(snapshot, "sha", conn=None)

    assert (n_nodes, kev_count) == (3, 0)
    assert any("2 of 3" in r.getMessage() for r in caplog.records), caplog.text


# --- invariants -----------------------------------------------------------------------------

json_values = st.recursive(
    st.none() | st.booleans() | st.integers() | st.text(max_size=8),
    lambda children: (
        st.lists(children, max_size=3) | st.dictionaries(st.text(max_size=8), children, max_size=3)
    ),
    max_leaves=8,
)


@given(
    st.fixed_dictionaries(
        {"id": st.just(CVE)},
        optional={
            k: json_values
            for k in ("descriptions", "metrics", "references", "published", "lastModified")
        },
    )
)
def test_malformed_fields_only_ever_names_known_fields_sorted_and_once(rec):
    flagged = parse_cve_record(rec).attrs.get("malformed_fields", [])
    assert set(flagged) <= MALFORMED_FIELD_NAMES
    assert flagged == sorted(set(flagged))


@given(st.sets(st.sampled_from(["descriptions", "metrics", "references", "published"])))
def test_fields_that_are_null_or_missing_never_count_as_malformed(null_fields):
    rec = {"id": CVE, **dict.fromkeys(null_fields)}
    assert "malformed_fields" not in parse_cve_record(rec).attrs
