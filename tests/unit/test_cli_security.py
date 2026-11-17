"""Security properties of the CLI, tested from the outside — the way a user runs it.

These are black-box tests: they invoke `threatlens` commands and inspect only what comes
back on the terminal, never the internals that produced it. What a command prints can end
up in a shell history, a pasted bug report, a CI log, or a screenshot, so anything secret
has to be kept out of it no matter how the command is implemented.
"""

from __future__ import annotations

import json

import pytest
from typer.testing import CliRunner

from threatlens.cli import app
from threatlens.config import get_settings

pytestmark = pytest.mark.security

PASSWORD = "s3cr3t-pw-91"
DSN = f"postgresql+psycopg://threatlens:{PASSWORD}@db.internal:5432/threatlens"
NVD_KEY = "nvd-key-0a1b2c3d4e5f"


@pytest.fixture
def secrets_in_env(monkeypatch: pytest.MonkeyPatch):
    """Settings carrying a real-looking password and API key.

    `get_settings()` is cached, so the cache is cleared on the way in — or the command
    would print whatever an earlier test configured — and on the way out, so these values
    never leak into a later test.
    """
    monkeypatch.setenv("DATABASE_URL", DSN)
    monkeypatch.setenv("NVD_API_KEY", NVD_KEY)
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


@pytest.mark.parametrize("args", [["config"], ["config", "--json"]], ids=["table", "json"])
def test_config_never_prints_the_database_password(secrets_in_env, args):
    """The command's own docstring promises it masks sensitive values; it masked the NVD
    key but printed the database URL — password included — verbatim."""
    out = CliRunner().invoke(app, args).output
    assert PASSWORD not in out


@pytest.mark.parametrize("args", [["config"], ["config", "--json"]], ids=["table", "json"])
def test_config_never_prints_the_nvd_api_key(secrets_in_env, args):
    out = CliRunner().invoke(app, args).output
    assert NVD_KEY not in out


def test_config_still_shows_where_the_database_is(secrets_in_env):
    """Masking must hide the secret, not the useful part. Host, port, user and database
    name are what someone debugging a connection actually needs to see."""
    shown = json.loads(CliRunner().invoke(app, ["config", "--json"]).output)["database_url"]
    for visible in ("threatlens", "db.internal", "5432"):
        assert visible in shown
    assert PASSWORD not in shown


def test_a_dsn_without_a_password_is_shown_unchanged(monkeypatch: pytest.MonkeyPatch):
    """Nothing to hide means nothing to mangle."""
    monkeypatch.setenv("DATABASE_URL", "postgresql+psycopg://localhost/threatlens")
    get_settings.cache_clear()
    try:
        shown = json.loads(CliRunner().invoke(app, ["config", "--json"]).output)["database_url"]
    finally:
        get_settings.cache_clear()
    assert shown == "postgresql+psycopg://localhost/threatlens"


@pytest.mark.parametrize(
    "dsn",
    [
        f"not a url :{PASSWORD}@",
        f"postgresql://threatlens:{PASSWORD}@localhost:not-a-port/threatlens",
    ],
    ids=["garbage", "non-numeric-port"],
)
def test_an_unparseable_dsn_is_hidden_and_the_command_still_works(monkeypatch, dsn):
    """If the URL cannot be parsed, its password cannot be located, so none of it is shown.

    Asserts the command *succeeded* and printed the mask. An earlier version only checked
    that the password was absent from the output — which a crash satisfies too, so the
    non-numeric-port case crashed `config` with a ValueError while this test stayed green.
    """
    monkeypatch.setenv("DATABASE_URL", dsn)
    get_settings.cache_clear()
    try:
        result = CliRunner().invoke(app, ["config", "--json"])
    finally:
        get_settings.cache_clear()
    assert result.exit_code == 0, repr(result.exception)
    assert json.loads(result.output)["database_url"] == "****"
