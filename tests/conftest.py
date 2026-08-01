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

import pytest

FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures")


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
