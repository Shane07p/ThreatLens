"""The test-case report, exercised the way it is used: run pytest, read the CSV it writes.

Each test runs a small throwaway suite in a subprocess with `-p case_report`, so the
reporter sees real pytest outcomes — passes, assertion failures, skips, expected failures,
setup errors — rather than hand-built report objects that could drift from what pytest
actually produces.
"""

from __future__ import annotations

import csv
import os
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

TESTS_DIR = Path(__file__).resolve().parents[1]

SUITE = '''
import pytest

def test_values_add_up():
    """Arithmetic still works."""
    assert 1 + 1 == 2

def test_a_wrong_total_fails():
    assert 1 + 1 == 3, "totals disagree"

def test_dictionary_lookup_behaviour():
    with pytest.raises(KeyError):
        {}["k"]

@pytest.mark.parametrize("word, length", [("graph", 5), ("cve", 3)])
def test_lengths_match(word, length):
    assert len(word) == length

@pytest.mark.skip(reason="snapshot not fetched")
def test_needs_a_snapshot():
    pass

@pytest.mark.xfail(reason="known bug: zero edges", strict=True)
def test_a_known_bug():
    assert False

@pytest.fixture
def broken():
    raise RuntimeError("fixture exploded")

def test_setup_failure_is_reported(broken):
    pass

@pytest.mark.security
def test_secrets_are_masked():
    pass

@pytest.mark.case(input="CVE-2021-44228", expected="resolves to technique:T1190")
def test_with_an_explicit_case():
    pass

@pytest.mark.positive
def test_no_override_wins():
    """Named like a negative test, explicitly marked positive."""
    pass

def test_drives_the_cli():
    class Runner:
        def invoke(self, app, args):
            return None
    app = object()
    Runner().invoke(app, ["--help"])
'''


def run_report(tmp_path: Path, *extra: str) -> tuple[subprocess.CompletedProcess, Path]:
    (tmp_path / "test_sample.py").write_text(textwrap.dedent(SUITE), encoding="utf-8")
    out = tmp_path / "out" / "cases.csv"
    env = {**os.environ, "PYTHONPATH": str(TESTS_DIR)}
    env.pop("PYTEST_ADDOPTS", None)
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "pytest",
            "test_sample.py",
            "-p",
            "case_report",
            "-p",
            "no:cacheprovider",
            "-q",
            *extra,
            "--case-report",
            str(out),
        ],
        cwd=tmp_path,
        env=env,
        capture_output=True,
        text=True,
        timeout=120,
    )
    return result, out


@pytest.fixture(scope="module")
def report(tmp_path_factory) -> dict[str, dict[str, str]]:
    result, out = run_report(tmp_path_factory.mktemp("suite"))
    assert out.exists(), result.stdout + result.stderr
    with open(out, encoding="utf-8") as fh:
        rows = list(csv.DictReader(fh))
    return {row["id"].split("::", 1)[1]: row for row in rows}


def test_every_test_gets_exactly_one_row(report):
    assert len(report) == 12  # parametrized test counts once per parameter set


def test_columns_are_the_documented_ones(report):
    from case_report import COLUMNS

    assert list(next(iter(report.values())).keys()) == COLUMNS


def test_a_pass_is_recorded_with_its_description(report):
    row = report["test_values_add_up"]
    assert (row["status"], row["actual"]) == ("passed", "as expected")
    assert row["description"] == "Arithmetic still works."
    assert row["expected"] == "Values add up"


def test_a_failure_records_what_actually_happened(report):
    """The point of the `actual` column: the real outcome, from the run, not typed in."""
    row = report["test_a_wrong_total_fails"]
    assert row["status"] == "failed"
    assert "totals disagree" in row["actual"]


def test_pytest_raises_marks_a_test_negative(report):
    """The sample's name holds no negative word, so only `pytest.raises` can make it
    negative — an earlier sample was negative by name as well, and survived this rule being
    deleted."""
    assert report["test_dictionary_lookup_behaviour"]["type"] == "negative"


def test_a_negative_word_in_the_name_marks_a_test_negative(report):
    assert report["test_a_wrong_total_fails"]["type"] == "negative"


def test_an_explicit_marker_overrides_the_inferred_type(report):
    assert report["test_no_override_wins"]["type"] == "positive"


def test_ordinary_tests_are_positive(report):
    assert report["test_values_add_up"]["type"] == "positive"


def test_parametrized_inputs_are_recorded_per_case(report):
    assert report["test_lengths_match[graph-5]"]["input"] == "word='graph'; length=5"
    assert report["test_lengths_match[cve-3]"]["input"] == "word='cve'; length=3"


def test_a_skip_records_its_reason(report):
    row = report["test_needs_a_snapshot"]
    assert (row["status"], row["actual"]) == ("skipped", "snapshot not fetched")


def test_an_expected_failure_is_not_reported_as_a_failure(report):
    row = report["test_a_known_bug"]
    assert row["status"] == "xfailed"
    assert "known bug" in row["actual"]


def test_a_setup_error_is_an_error_not_a_failure(report):
    row = report["test_setup_failure_is_reported"]
    assert row["status"] == "error"
    assert "fixture exploded" in row["actual"]


def test_the_security_marker_is_reported(report):
    assert report["test_secrets_are_masked"]["security"] == "yes"
    assert report["test_values_add_up"]["security"] == "no"


def test_an_explicit_case_overrides_input_and_expected(report):
    row = report["test_with_an_explicit_case"]
    assert row["input"] == "CVE-2021-44228"
    assert row["expected"] == "resolves to technique:T1190"


def test_driving_the_cli_is_black_box(report):
    assert report["test_drives_the_cli"]["technique"] == "black-box"
    assert report["test_values_add_up"]["technique"] == "white-box"


def test_no_report_is_written_without_the_option(tmp_path):
    """Off by default: an ordinary test run must not leave files behind."""
    (tmp_path / "test_sample.py").write_text("def test_ok():\n    pass\n", encoding="utf-8")
    env = {**os.environ, "PYTHONPATH": str(TESTS_DIR)}
    subprocess.run(
        [
            sys.executable,
            "-m",
            "pytest",
            "test_sample.py",
            "-p",
            "case_report",
            "-p",
            "no:cacheprovider",
            "-q",
        ],
        cwd=tmp_path,
        env=env,
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert not list(tmp_path.rglob("*.csv"))


def test_paths_in_parameters_are_shown_relative_to_the_repository():
    """An absolute path would publish the local username in every report and CI artifact."""
    from case_report import _render

    root = Path.cwd()
    assert _render(root / "src" / "threatlens" / "cli.py", root) == "src/threatlens/cli.py"
    assert _render(Path("/elsewhere/secret/file.txt"), root) == "file.txt"
