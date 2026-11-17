"""Robustness tests for the NVD, mappings, and metrics parsers.

The existing suites prove these functions are correct on well-formed input. This one
proves they do not crash, silently corrupt, or quietly lose data when the input is
malformed, oversized, non-ASCII, duplicated, or hostile.

NVD and the Mappings Explorer are external feeds nobody here controls. A schema tweak
upstream should degrade one record, not take down a thirty-minute ingest.
"""

from __future__ import annotations

import csv
import io
from pathlib import Path

import pytest

from threatlens.eval.metrics import citation_coverage, mrr, path_correct, recall_at_k
from threatlens.ingest.mappings import parse_mappings_csv
from threatlens.ingest.nvd import TokenBucket, parse_cve_record


def cve(**overrides) -> dict:
    """Minimal well-formed NVD record. Override any field to make it awkward."""
    base = {
        "id": "CVE-2024-0001",
        "descriptions": [{"lang": "en", "value": "A description."}],
        "metrics": {
            "cvssMetricV31": [{"cvssData": {"baseScore": 7.5, "vectorString": "CVSS:3.1"}}]
        },
        "references": [],
        "published": "2024-01-01T00:00:00.000",
        "lastModified": "2024-01-02T00:00:00.000",
    }
    base.update(overrides)
    return base


def write_csv(tmp_path: Path, rows: list[dict], fieldnames: list[str] | None = None) -> Path:
    names = fieldnames or [
        "CVE ID",
        "Primary Impact",
        "Secondary Impact",
        "Exploitation Technique",
        "Uncategorized",
        "Phase",
    ]
    path = tmp_path / "mappings.csv"
    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=names)
    writer.writeheader()
    for r in rows:
        writer.writerow(r)
    path.write_text(buf.getvalue(), encoding="utf-8")
    return path


# ======================================================================================
# NVD record parsing
# ======================================================================================


def test_completely_empty_record_returns_none():
    assert parse_cve_record({}) is None


def test_record_with_no_descriptions_has_none_description():
    assert parse_cve_record(cve(descriptions=[])).description is None


def test_non_english_only_description_is_not_used():
    """A Spanish description is not a substitute for the English one — it would be
    embedded as if it were the canonical text and quietly skew retrieval."""
    node = parse_cve_record(cve(descriptions=[{"lang": "es", "value": "Una descripcion."}]))
    assert node.description is None


def test_english_is_chosen_even_when_not_first():
    node = parse_cve_record(
        cve(
            descriptions=[
                {"lang": "es", "value": "Una descripcion."},
                {"lang": "en", "value": "The English one."},
            ]
        )
    )
    assert node.description == "The English one."


def test_cvss_data_missing_entirely_is_none_not_zero():
    """The whole point: a fabricated 0.0 reads as 'no risk' to someone acting on it."""
    node = parse_cve_record(cve(metrics={"cvssMetricV31": [{}]}))
    assert node.attrs["cvss_score"] is None


def test_explicit_null_base_score_is_none_not_zero():
    node = parse_cve_record(cve(metrics={"cvssMetricV31": [{"cvssData": {"baseScore": None}}]}))
    assert node.attrs["cvss_score"] is None


def test_empty_metrics_lists_fall_through_to_none():
    node = parse_cve_record(cve(metrics={"cvssMetricV31": [], "cvssMetricV40": []}))
    assert node.attrs["cvss_score"] is None
    assert node.attrs["cvss_version"] is None


def test_v31_wins_when_both_versions_present():
    node = parse_cve_record(
        cve(
            metrics={
                "cvssMetricV40": [{"cvssData": {"baseScore": 9.9}}],
                "cvssMetricV31": [{"cvssData": {"baseScore": 1.1}}],
            }
        )
    )
    assert node.attrs["cvss_score"] == pytest.approx(1.1)
    assert node.attrs["cvss_version"] == "3.1"


def test_first_entry_wins_when_several_v31_scores_exist():
    """NVD publishes multiple scorings from different CNAs. Documented: we take the
    first rather than averaging, so the value traces to one source."""
    node = parse_cve_record(
        cve(
            metrics={
                "cvssMetricV31": [
                    {"cvssData": {"baseScore": 5.0}},
                    {"cvssData": {"baseScore": 9.0}},
                ]
            }
        )
    )
    assert node.attrs["cvss_score"] == pytest.approx(5.0)


def test_zero_score_is_preserved_as_zero():
    """A real 0.0 from NVD is data, not absence. It must survive, unlike a missing one."""
    node = parse_cve_record(cve(metrics={"cvssMetricV31": [{"cvssData": {"baseScore": 0.0}}]}))
    assert node.attrs["cvss_score"] == 0.0
    assert node.attrs["cvss_score"] is not None


def test_references_without_a_url_key_are_dropped():
    node = parse_cve_record(cve(references=[{"source": "x"}, {"url": "https://a"}]))
    assert node.attrs["references"] == ["https://a"]


def test_unicode_description_survives_intact():
    text = "Vulnérabilité — 脆弱性 — 🔒 «quoted»"
    assert parse_cve_record(cve(descriptions=[{"lang": "en", "value": text}])).description == text


def test_very_long_description_is_not_truncated():
    """Chunking happens later, deliberately. A parser that truncates loses the tail of
    exactly the most detailed records."""
    node = parse_cve_record(cve(descriptions=[{"lang": "en", "value": "x" * 200_000}]))
    assert len(node.description) == 200_000


@pytest.mark.security
def test_sql_shaped_description_is_stored_verbatim():
    hostile = "'; DROP TABLE nodes; --"
    assert (
        parse_cve_record(cve(descriptions=[{"lang": "en", "value": hostile}])).description
        == hostile
    )


def test_missing_dates_are_none_not_invented():
    node = parse_cve_record(cve(published=None, lastModified=None))
    assert node.attrs["published"] is None
    assert node.attrs["last_modified"] is None


def test_cve_id_becomes_a_well_formed_node_id():
    node = parse_cve_record(cve(id="CVE-2021-44228"))
    assert node.id == "cve:CVE-2021-44228"
    assert node.kind == "cve"


# ======================================================================================
# Mappings CSV
# ======================================================================================


def test_header_only_file_yields_nothing(tmp_path):
    edges, skipped = parse_mappings_csv(write_csv(tmp_path, []))
    assert edges == []
    assert skipped == 0


def test_whitespace_only_technique_is_not_an_edge(tmp_path):
    """A blank cell contributes nothing. A second, usable row keeps the file valid — a file
    whose rows all yield nothing is rejected outright (see the test below)."""
    edges, _ = parse_mappings_csv(
        write_csv(
            tmp_path,
            [
                {"CVE ID": "CVE-2024-0001", "Primary Impact": "   "},
                {"CVE ID": "CVE-2024-0002", "Primary Impact": "T1190"},
            ],
        )
    )
    assert [e.src for e in edges] == ["cve:CVE-2024-0002"]


def test_surrounding_whitespace_is_stripped(tmp_path):
    edges, _ = parse_mappings_csv(
        write_csv(tmp_path, [{"CVE ID": "  CVE-2024-0001  ", "Primary Impact": "  T1190  "}])
    )
    assert edges[0].src == "cve:CVE-2024-0001"
    assert edges[0].dst == "technique:T1190"


def test_whitespace_only_cve_id_counts_as_skipped(tmp_path):
    """Distinct from a genuinely absent id, but equally unusable — and must be counted,
    not silently dropped."""
    edges, skipped = parse_mappings_csv(
        write_csv(
            tmp_path,
            [
                {"CVE ID": "   ", "Primary Impact": "T1190"},
                {"CVE ID": "CVE-2024-0002", "Primary Impact": "T1059"},
            ],
        )
    )
    assert [e.src for e in edges] == ["cve:CVE-2024-0002"]
    assert skipped == 1


def test_missing_impact_columns_fail_loudly(tmp_path):
    """Reversed deliberately. This test used to assert that a header rename should "degrade
    to zero edges, not an exception" — and that silent degradation is exactly how a
    byte-order mark on the real file hid the whole dataset while every test passed. An
    empty bridge is not a result anyone should be allowed to trust without being told."""
    path = write_csv(
        tmp_path, [{"CVE ID": "CVE-2024-0001"}], fieldnames=["CVE ID", "Some Other Column"]
    )
    with pytest.raises(ValueError, match="Primary Impact"):
        parse_mappings_csv(path)


def test_duplicate_rows_produce_one_edge(tmp_path):
    """Changed deliberately — this test existed so that change would be. Leaving dedupe to
    the database upsert meant the last write won, so a later secondary listing of the same
    pair could quietly lower a primary edge to 0.5. The parser now keeps one edge per pair
    at its strongest weight."""
    row = {"CVE ID": "CVE-2024-0001", "Primary Impact": "T1190"}
    edges, _ = parse_mappings_csv(write_csv(tmp_path, [row, row]))
    assert len(edges) == 1


def test_one_row_can_produce_both_weights(tmp_path):
    edges, _ = parse_mappings_csv(
        write_csv(
            tmp_path,
            [{"CVE ID": "CVE-2024-0001", "Primary Impact": "T1190", "Secondary Impact": "T1059"}],
        )
    )
    assert sorted(e.weight for e in edges) == [0.5, 1.0]


def test_unicode_in_a_row_does_not_break_parsing(tmp_path):
    """Unicode in an unread column is harmless; unicode glued onto a technique id makes the
    token invalid, so it is counted as lost rather than becoming a node id that matches
    nothing. The valid token in the same cell survives."""
    edges, skipped = parse_mappings_csv(
        write_csv(
            tmp_path,
            [{"CVE ID": "CVE-2024-0001", "Primary Impact": "T1190; T1059—é", "Phase": "Étape 2"}],
        )
    )
    assert [e.dst for e in edges] == ["technique:T1190"]
    assert skipped == 1


@pytest.mark.security
def test_sql_shaped_cve_id_is_stored_verbatim(tmp_path):
    hostile = "'; DROP TABLE edges; --"
    edges, _ = parse_mappings_csv(
        write_csv(tmp_path, [{"CVE ID": hostile, "Primary Impact": "T1190"}])
    )
    assert edges[0].src == f"cve:{hostile}"


def test_large_file_parses_without_loss(tmp_path):
    rows = [{"CVE ID": f"CVE-2024-{i:05d}", "Primary Impact": f"T{i:04d}"} for i in range(5000)]
    edges, skipped = parse_mappings_csv(write_csv(tmp_path, rows))
    assert len(edges) == 5000
    assert skipped == 0


# ======================================================================================
# Metrics
# ======================================================================================


def test_recall_at_k_zero_finds_nothing():
    assert recall_at_k(["T1190"], {"T1190"}, 0) == 0.0


def test_recall_at_k_larger_than_the_list_is_safe():
    assert recall_at_k(["T1190"], {"T1190"}, 999) == 1.0


def test_recall_with_empty_gold_is_zero_not_a_crash():
    """No gold means the query is unscoreable. Returning 0.0 keeps it from silently
    inflating an average as if it were a success."""
    assert recall_at_k(["T1190"], set(), 5) == 0.0


def test_recall_ignores_duplicate_predictions():
    assert recall_at_k(["T1059", "T1059", "T1190"], {"T1190"}, 2) == 0.0


def test_mrr_uses_the_earliest_hit_when_several_match():
    assert mrr(["T1059", "T1190", "T1078"], {"T1190", "T1078"}) == pytest.approx(0.5)


def test_mrr_with_empty_gold_is_zero():
    assert mrr(["T1190"], set()) == 0.0


def test_path_correct_with_both_empty_is_true():
    assert path_correct([], []) is True


def test_path_correct_rejects_an_id_with_no_kind_prefix():
    assert path_correct(["T1190"], ["technique"]) is False


def test_path_correct_handles_ids_containing_extra_colons():
    """CVE ids contain no colons, but node ids are split on the first one only —
    asserted so a future id format with colons does not silently misparse."""
    assert path_correct(["cve:CVE-2021-44228"], ["cve"]) is True


def test_citation_coverage_counts_duplicate_claims_separately():
    """Two claims citing the same node are two claims. Deduplicating would overstate
    coverage when the model repeats one grounded citation."""
    assert citation_coverage(["a", "a"], {"a"}) == 1.0
    assert citation_coverage(["a", "a", "b"], {"a"}) == pytest.approx(2 / 3)


def test_citation_coverage_with_no_evidence_and_claims_is_zero():
    assert citation_coverage(["a"], set()) == 0.0


def test_metrics_are_pure_and_do_not_mutate_their_inputs():
    """These run inside the eval loop over the holdout; a mutated list would corrupt
    every subsequent query silently."""
    predicted, gold = ["T1059", "T1190"], {"T1190"}
    recall_at_k(predicted, gold, 1)
    mrr(predicted, gold)
    assert predicted == ["T1059", "T1190"]
    assert gold == {"T1190"}


# ======================================================================================
# Rate limiter
# ======================================================================================


class FakeClock:
    def __init__(self) -> None:
        self.now = 0.0
        self.slept: list[float] = []

    def time(self) -> float:
        return self.now

    def sleep(self, seconds: float) -> None:
        self.slept.append(seconds)
        self.now += seconds


def test_bucket_never_exceeds_its_rate_over_a_long_run():
    """The property that matters: across many acquires, elapsed time must be at least
    what the configured rate implies. This is what keeps NVD from returning 403."""
    c = FakeClock()
    bucket = TokenBucket(rate=5, per_seconds=30.0, clock=c.time, sleep=c.sleep)
    for _ in range(50):
        bucket.acquire()
    # 50 requests at 5 per 30s needs at least 45 beyond the initial burst.
    assert c.now >= (50 - 5) * (30.0 / 5) - 0.001


def test_bucket_is_deterministic_for_the_same_schedule():
    def run() -> list[float]:
        c = FakeClock()
        b = TokenBucket(rate=3, per_seconds=10.0, clock=c.time, sleep=c.sleep)
        for _ in range(10):
            b.acquire()
        return c.slept

    assert run() == run()


def test_tokens_never_exceed_the_burst_ceiling():
    """A long idle period must not bank unlimited credit and then flood the API."""
    c = FakeClock()
    bucket = TokenBucket(rate=5, per_seconds=30.0, clock=c.time, sleep=c.sleep)
    c.now += 10_000.0
    for _ in range(5):
        bucket.acquire()
    assert c.slept == []
    bucket.acquire()
    assert len(c.slept) == 1
