"""Properties of the NVD record parser under arbitrary, malformed input.

Ingestion is tolerant on the way in: one bad record must be skipped, never crash a run that
has been downloading for twenty minutes. NVD's JSON is large and has changed shape before,
so these feed the parser records whose fields hold the wrong types entirely — strings where
lists belong, lists where dicts belong — and check it either returns a Node or None.
"""

from __future__ import annotations

import pytest
from hypothesis import given
from hypothesis import strategies as st

from threatlens.ingest.nvd import parse_cve_record
from threatlens.models import Node

json_values = st.recursive(
    st.none() | st.booleans() | st.integers() | st.floats(allow_nan=False) | st.text(max_size=20),
    lambda children: (
        st.lists(children, max_size=4) | st.dictionaries(st.text(max_size=12), children, max_size=4)
    ),
    max_leaves=12,
)

# Records shaped like NVD's, with every field allowed to hold anything at all.
records = st.fixed_dictionaries(
    {},
    optional={
        "id": json_values,
        "descriptions": json_values,
        "metrics": json_values,
        "references": json_values,
        "published": json_values,
        "lastModified": json_values,
    },
)


@given(records)
def test_any_record_yields_a_node_or_none_and_never_raises(record):
    result = parse_cve_record(record)
    assert result is None or isinstance(result, Node)


@given(records)
def test_a_parsed_score_is_none_or_a_real_cvss_value(record):
    """A fabricated 0.0 reads as 'no risk'. Whatever arrives, a score is either None or a
    number inside the CVSS range."""
    node = parse_cve_record(record)
    if node is not None:
        score = node.attrs["cvss_score"]
        assert score is None or (isinstance(score, float) and 0.0 <= score <= 10.0)


@given(
    st.from_regex(r"CVE-\d{4}-\d{4,7}", fullmatch=True),
    st.text(min_size=1, max_size=60),
)
def test_a_record_without_metrics_never_invents_a_score(cve_id, description):
    node = parse_cve_record({"id": cve_id, "descriptions": [{"lang": "en", "value": description}]})
    assert node is not None
    assert node.attrs["cvss_score"] is None
    assert node.attrs["cvss_version"] is None


@pytest.mark.parametrize(
    ("base_score", "expected"),
    [
        (9.8, 9.8),
        ("7.5", 7.5),
        (0, 0.0),
        (True, None),  # float(True) is 1.0: without a guard, `true` becomes a fake score
        (False, None),
        ("high", None),
        (11.0, None),
        (-1, None),
        (None, None),
    ],
)
def test_only_a_real_cvss_number_becomes_a_score(base_score, expected):
    record = {
        "id": "CVE-2024-0001",
        "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": base_score}}]},
    }
    node = parse_cve_record(record)
    assert node is not None
    assert node.attrs["cvss_score"] == expected
