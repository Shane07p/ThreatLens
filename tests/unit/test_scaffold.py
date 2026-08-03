"""Scaffold tests.

These verify the harness itself, not the application — the package imports, the
markers are registered, and the network guard actually blocks. Real tests replace
this file's role with real ingestion tests; the network-guard test stays.
"""

from __future__ import annotations

import socket

import pytest

import threatlens


def test_package_imports() -> None:
    assert threatlens.__version__ == "0.1.0"


def test_network_is_blocked_in_unit_tests() -> None:
    """The guard in conftest must actually bite, or every later test is unguarded."""
    with pytest.raises(RuntimeError, match="network access from a unit test"):
        socket.socket().connect(("example.com", 80))


@pytest.mark.parametrize("marker", ["slow", "db", "eval"])
def test_markers_are_registered(marker: str, pytestconfig: pytest.Config) -> None:
    """`--strict-markers` turns an unregistered marker into an error; check they exist."""
    registered = {line.split(":")[0] for line in pytestconfig.getini("markers")}
    assert marker in registered
