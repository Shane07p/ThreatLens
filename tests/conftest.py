"""Shared fixtures and guardrails.

Two rules enforced here:

1. Unit tests may not touch the network. A test that quietly reaches out to NVD or
   GitHub is a test that fails when those are slow, and a suite that fails for
   unrelated reasons is a suite people learn to ignore.
2. Database tests get a transaction that is rolled back, so they never leave state
   behind for the next test to trip over.
"""

from __future__ import annotations

import os
import socket

import psycopg
import pytest
from hypothesis import settings

# The test-case report (`--case-report=PATH`). Importing its hooks into this namespace is
# what registers them with pytest; see tests/case_report.py.
from case_report import pytest_addoption, pytest_configure  # noqa: F401

# Property-based tests. CI derandomizes, so a red build always reproduces with the same
# inputs instead of failing on one unlucky draw and passing on the rerun; local runs explore
# fresh inputs each time. No deadline: per-example timing on Windows and shared CI runners is
# too uneven to mean anything.
settings.register_profile("ci", max_examples=200, derandomize=True, deadline=None)
settings.register_profile("dev", max_examples=100, deadline=None)
settings.load_profile(os.getenv("HYPOTHESIS_PROFILE", "dev"))

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")


@pytest.fixture
def configured_env(monkeypatch: pytest.MonkeyPatch) -> str:
    """Set DATABASE_URL for a test that needs get_settings() to succeed.

    Opt-in rather than autouse: an autouse version sets the variable for every test
    in the suite, which makes the unset case unobservable — no test could then catch
    a regression where config stops rejecting a missing DATABASE_URL.

    Named `configured_env` rather than `database_url` because a session-scoped
    `database_url` fixture already exists below and would silently shadow this one.
    Duplicate fixture names do not error; the later definition simply wins.
    """
    dsn = os.getenv(
        "THREATLENS_TEST_DSN",
        "postgresql://threatlens:threatlens@localhost:5432/threatlens_test",
    )
    monkeypatch.setenv("DATABASE_URL", dsn)
    return dsn


@pytest.fixture(autouse=True)
def _no_network(monkeypatch: pytest.MonkeyPatch, request: pytest.FixtureRequest) -> None:
    """Block outbound sockets in unit tests.

    Tests marked `db` or `eval` legitimately need a network, so they opt out.
    """
    if request.node.get_closest_marker("db") or request.node.get_closest_marker("eval"):
        return

    def _blocked(*args: object, **kwargs: object) -> None:
        raise RuntimeError(
            "network access from a unit test — use a fixture, or mark the test `db`/`eval`"
        )

    monkeypatch.setattr(socket.socket, "connect", _blocked)

    # psycopg reaches Postgres through libpq, which opens its sockets in C and never calls
    # Python's socket module, so the patch above cannot see it. SQLAlchemy looks the
    # function up on the module at connect time, which is why the module attribute is
    # patched and not only the class method it aliases.
    monkeypatch.setattr(psycopg, "connect", _blocked)
    monkeypatch.setattr(psycopg.Connection, "connect", classmethod(_blocked))


@pytest.fixture(scope="session")
def database_url() -> str:
    """DSN for the throwaway test database."""
    return os.environ.get(
        "THREATLENS_TEST_DSN",
        "postgresql://threatlens:threatlens@localhost:5432/threatlens_test",
    )


@pytest.fixture
def fixtures_dir() -> str:
    """Path to `tests/fixtures/`."""
    return FIXTURES
