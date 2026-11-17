"""Write one CSV row per test: what it checks, how it checks it, and what happened.

Enable with `--case-report=PATH`. Off by default, so an ordinary run writes nothing:

    uv run pytest -m "not eval" --case-report=test-results/test-cases.csv

Write it with `=`, not a space. The option is defined by a conftest, so pytest's early
argument pass does not know it yet and takes a space-separated value for a test path. Once
that file exists — after the first run — pytest discovers conftests from it instead of from
`tests/`, never loads this option, and stops with "unrecognized arguments". The first run
works, which makes the second failure look inexplicable.

Nearly every column is derived from the suite itself rather than typed in, so the report
cannot drift from the tests it describes:

| Column      | Comes from |
|-------------|------------|
| id          | the pytest node id, stable and unique |
| suite       | the test file |
| level       | `integration` if marked `db`, `eval` if marked `eval`, otherwise `unit` |
| technique   | `black-box` if the test drives the CLI the way a user would, else `white-box` |
| type        | `negative` if the test asserts something is rejected, refused, or absent —
|             | it uses `pytest.raises`, or its name says so — else `positive` |
| security    | `yes` for tests marked `@pytest.mark.security` |
| description | the first line of the docstring: why the test exists |
| input       | the parameters of a parametrized test, or `@pytest.mark.case(input=...)` |
| expected    | the test name read as a sentence — tests here are named after the behaviour
|             | they assert, so the name *is* the expected result |
| status      | passed / failed / skipped / error / xfailed / xpassed, from this run |
| actual      | what happened in this run: `as expected`, the first line of the failure, or
|             | the skip reason. Never written by hand. |
| duration_s  | wall time of the test body |

`type` and `technique` are inferred. When the inference is wrong, say so explicitly with
`@pytest.mark.negative`, `@pytest.mark.positive`, or `@pytest.mark.case(expected=...)`.

Loaded through `tests/conftest.py`, which re-exports the two hooks below. It is a plain
module rather than a registered plugin so it can also be loaded on its own with
`-p case_report`, which is how its own tests exercise it.
"""

from __future__ import annotations

import csv
import inspect
import re
from pathlib import Path
from typing import Any

import pytest

COLUMNS = [
    "id",
    "suite",
    "level",
    "technique",
    "type",
    "security",
    "description",
    "input",
    "expected",
    "status",
    "actual",
    "duration_s",
]

# Words in a test name that mean it asserts a rejection, a refusal, or an absence. Matched
# as whole underscore-separated words so `notify` does not count as `not`.
_NEGATIVE_WORDS = re.compile(
    r"(?:^|_)(?:invalid|malformed|missing|hostile|rejects?|rejected|refuses?|refused|fails?|"
    r"failing|absent|blocked|never|not|no|without|empty|skipped|dropped|cannot|unknown|"
    r"dangling|stale|wrong|errors?|unresolvable|ignored|lost|bad|denied|corrupt|truncated|"
    r"leaks?|exposes?)(?:_|$)"
)
_CLI_CALL = re.compile(r"\.invoke\(\s*app\b")
_MAX_CELL = 300


def pytest_addoption(parser: pytest.Parser) -> None:
    parser.addoption(
        "--case-report",
        metavar="PATH",
        default=None,
        help="write one CSV row per test to PATH; use the --case-report=PATH form",
    )


def pytest_configure(config: pytest.Config) -> None:
    path = config.getoption("--case-report")
    if path and not config.pluginmanager.has_plugin("case-report"):
        config.pluginmanager.register(CaseReport(Path(path)), "case-report")


class CaseReport:
    """Collects one row per test across the run and writes them when the session ends."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self.rows: dict[str, dict[str, str]] = {}

    @pytest.hookimpl(wrapper=True)
    def pytest_runtest_makereport(
        self, item: pytest.Item, call: pytest.CallInfo[None]
    ) -> pytest.TestReport:
        report: pytest.TestReport = yield
        row = self.rows.setdefault(item.nodeid, describe(item))
        record(row, report)
        return report

    def pytest_sessionfinish(self, session: pytest.Session) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.path, "w", newline="", encoding="utf-8") as fh:
            writer = csv.DictWriter(fh, fieldnames=COLUMNS)
            writer.writeheader()
            writer.writerows(self.rows.values())

    def pytest_terminal_summary(self, terminalreporter: Any) -> None:
        rows = list(self.rows.values())

        def count(col: str, value: str) -> int:
            return sum(1 for r in rows if r[col] == value)

        terminalreporter.write_sep("-", f"test-case report: {self.path}")
        terminalreporter.write_line(
            f"{len(rows)} cases | unit {count('level', 'unit')}, "
            f"integration {count('level', 'integration')} | "
            f"positive {count('type', 'positive')}, negative {count('type', 'negative')} | "
            f"white-box {count('technique', 'white-box')}, "
            f"black-box {count('technique', 'black-box')} | "
            f"security {count('security', 'yes')}"
        )


def describe(item: pytest.Item) -> dict[str, str]:
    """Everything about a test that does not depend on running it."""
    function = getattr(item, "function", None)
    source = _source(function)
    name = getattr(item, "originalname", None) or item.name
    case = item.get_closest_marker("case")
    case_kwargs = case.kwargs if case else {}

    return {
        "id": item.nodeid,
        "suite": item.nodeid.split("::", 1)[0],
        "level": _level(item),
        "technique": "black-box" if _CLI_CALL.search(source) else "white-box",
        "type": _test_type(item, name, source),
        "security": "yes" if item.get_closest_marker("security") else "no",
        "description": _clip(_first_docstring_line(function)),
        "input": _clip(str(case_kwargs["input"]) if "input" in case_kwargs else _params(item)),
        "expected": _clip(str(case_kwargs.get("expected") or _sentence(name))),
        "status": "not run",
        "actual": "",
        "duration_s": "",
    }


def record(row: dict[str, str], report: pytest.TestReport) -> None:
    """Fold one phase's report (setup, call, teardown) into the row's outcome."""
    if report.when == "setup":
        if report.failed:
            row.update(status="error", actual=_clip("setup: " + _failure_line(report)))
        elif report.skipped:
            row.update(status="skipped", actual=_clip(_skip_reason(report)))
    elif report.when == "call":
        row["duration_s"] = f"{report.duration:.3f}"
        if hasattr(report, "wasxfail"):
            row.update(
                status="xfailed" if report.skipped else "xpassed",
                actual=_clip(report.wasxfail or "expected failure"),
            )
        elif report.passed:
            row.update(status="passed", actual="as expected")
        elif report.failed:
            row.update(status="failed", actual=_clip(_failure_line(report)))
        elif report.skipped:
            row.update(status="skipped", actual=_clip(_skip_reason(report)))
    elif report.when == "teardown" and report.failed:
        row.update(status="error", actual=_clip("teardown: " + _failure_line(report)))


def _level(item: pytest.Item) -> str:
    if item.get_closest_marker("eval"):
        return "eval"
    if item.get_closest_marker("db"):
        return "integration"
    return "unit"


def _test_type(item: pytest.Item, name: str, source: str) -> str:
    if item.get_closest_marker("positive"):
        return "positive"
    if item.get_closest_marker("negative"):
        return "negative"
    if "pytest.raises" in source or _NEGATIVE_WORDS.search(name.removeprefix("test_")):
        return "negative"
    return "positive"


def _source(function: Any) -> str:
    try:
        return inspect.getsource(function) if function else ""
    except (OSError, TypeError):
        return ""


def _first_docstring_line(function: Any) -> str:
    doc = inspect.getdoc(function) if function else None
    return doc.strip().splitlines()[0] if doc else ""


def _params(item: pytest.Item) -> str:
    callspec = getattr(item, "callspec", None)
    if not callspec:
        return ""
    root = item.config.rootpath
    return "; ".join(f"{key}={_render(value, root)}" for key, value in callspec.params.items())


def _render(value: object, root: Path) -> str:
    """repr(), except paths are shown relative to the repository. An absolute path would put
    the local username and directory layout into every report, including CI artifacts."""
    if isinstance(value, Path):
        try:
            return value.resolve().relative_to(root.resolve()).as_posix()
        except ValueError:
            return value.name
    return repr(value)


def _sentence(name: str) -> str:
    words = name.removeprefix("test_").replace("_", " ").strip()
    return words[:1].upper() + words[1:]


def _failure_line(report: pytest.TestReport) -> str:
    """The first `E` line of a failure — the assertion or exception — or the last line."""
    lines = [ln for ln in report.longreprtext.splitlines() if ln.strip()]
    errors = [ln.lstrip("E").strip() for ln in lines if ln.startswith("E ")]
    return errors[0] if errors else (lines[-1].strip() if lines else "failed")


def _skip_reason(report: pytest.TestReport) -> str:
    longrepr = report.longrepr
    reason = longrepr[2] if isinstance(longrepr, tuple) and len(longrepr) == 3 else str(longrepr)
    return reason.removeprefix("Skipped: ")


def _clip(text: str) -> str:
    text = " ".join(text.split())
    return text if len(text) <= _MAX_CELL else text[: _MAX_CELL - 1] + "…"
