"""Evaluation metric tests.

Table-driven against hand-computed values. Every row of the ablation table
runs through these same functions — if the math is wrong here, every
measured number is wrong.
"""

import pytest

from threatlens.eval.metrics import citation_coverage, mrr, path_correct, recall_at_k

# ---- recall@k ----


@pytest.mark.parametrize(
    "predicted,gold,k,expected",
    [
        (["T1190", "T1059"], {"T1190"}, 1, 1.0),  # gold at rank 1
        (["T1059", "T1190"], {"T1190"}, 1, 0.0),  # gold at rank 2, k=1 misses
        (["T1059", "T1190"], {"T1190"}, 2, 1.0),  # gold at rank 2, k=2 catches
        (["T1059", "T1078", "T1190"], {"T1190"}, 2, 0.0),  # gold at rank 3, k=2 misses
        ([], {"T1190"}, 5, 0.0),  # empty predictions
        (["T1190"], set(), 1, 0.0),  # empty gold
    ],
)
def test_recall_at_k(predicted, gold, k, expected):
    assert recall_at_k(predicted, gold, k) == pytest.approx(expected)


def test_recall_counts_any_gold_hit():
    """Multiple gold items — hitting any one of them counts as success."""
    assert recall_at_k(["T1059", "T1078"], {"T1190", "T1078"}, 2) == pytest.approx(1.0)


def test_recall_with_all_gold_items_present():
    assert recall_at_k(["T1190", "T1059"], {"T1190", "T1059"}, 2) == pytest.approx(1.0)


# ---- MRR ----


@pytest.mark.parametrize(
    "predicted,gold,expected",
    [
        (["T1190"], {"T1190"}, 1.0),  # rank 1 → 1/1
        (["T1059", "T1190"], {"T1190"}, 0.5),  # rank 2 → 1/2
        (["T1059", "T1078", "T1190"], {"T1190"}, 1 / 3),  # rank 3 → 1/3
        (["T1059"], {"T1190"}, 0.0),  # no hit
        ([], {"T1190"}, 0.0),  # empty predictions
    ],
)
def test_mrr(predicted, gold, expected):
    assert mrr(predicted, gold) == pytest.approx(expected)


def test_mrr_returns_first_hit_reciprocal():
    """When multiple gold items match, MRR uses the earliest one."""
    assert mrr(["T1059", "T1190", "T1078"], {"T1190", "T1078"}) == pytest.approx(0.5)


# ---- path_correct ----


def test_path_correct_matches_kind_sequence():
    path = ["cve:CVE-2021-44228", "technique:T1190", "tactic:TA0001"]
    assert path_correct(path, ["cve", "technique", "tactic"]) is True


def test_path_correct_rejects_wrong_order():
    path = ["technique:T1190", "cve:CVE-2021-44228", "tactic:TA0001"]
    assert path_correct(path, ["cve", "technique", "tactic"]) is False


def test_path_correct_rejects_wrong_length():
    assert path_correct(["cve:X"], ["cve", "technique"]) is False


def test_path_correct_empty_path():
    assert path_correct([], []) is True


def test_path_correct_single_node():
    assert path_correct(["technique:T1190"], ["technique"]) is True


# ---- citation_coverage ----


def test_citation_coverage_all_resolvable():
    claims = ["technique:T1190", "mitigation:M1030"]
    assert citation_coverage(claims, {"technique:T1190", "mitigation:M1030"}) == 1.0


def test_citation_coverage_partial():
    claims = ["technique:T1190", "technique:T9999"]
    assert citation_coverage(claims, {"technique:T1190"}) == pytest.approx(0.5)


def test_citation_coverage_none_resolvable():
    claims = ["technique:T9999"]
    assert citation_coverage(claims, {"technique:T1190"}) == pytest.approx(0.0)


def test_citation_coverage_of_no_claims_is_one():
    """Nothing asserted means nothing ungrounded."""
    assert citation_coverage([], {"technique:T1190"}) == 1.0


def test_citation_coverage_empty_evidence_with_claims():
    """Claims exist but evidence set is empty — nothing resolves."""
    assert citation_coverage(["technique:T1190"], set()) == pytest.approx(0.0)
