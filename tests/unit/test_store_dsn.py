"""DSN normalization — exhaustive edge cases.

SQLAlchemy maps a bare `postgresql://` to psycopg2, which this project does not install.
CI emits exactly that form, so without normalization every integration test fails with
`No module named 'psycopg2'` — an error that points nowhere near the actual cause.

These tests are the firewall: if normalize_dsn ever lets a bare scheme through,
every integration test on every contributor's machine breaks.
"""

from __future__ import annotations

import pytest

from threatlens.graph.store import normalize_dsn

# ── Core transformations ────────────────────────────────────────────────────


class TestCoreNormalization:
    @pytest.mark.parametrize(
        "given,expected",
        [
            # the form CI emits
            (
                "postgresql://threatlens:threatlens@localhost:5432/threatlens_test",
                "postgresql+psycopg://threatlens:threatlens@localhost:5432/threatlens_test",
            ),
            # the legacy Heroku-style prefix
            (
                "postgres://u:p@host/db",
                "postgresql+psycopg://u:p@host/db",
            ),
            # already explicit — must pass through untouched
            (
                "postgresql+psycopg://u:p@host/db",
                "postgresql+psycopg://u:p@host/db",
            ),
        ],
    )
    def test_normalize_dsn(self, given, expected):
        assert normalize_dsn(given) == expected

    def test_normalization_is_idempotent(self):
        """Running it twice must not double-prefix."""
        once = normalize_dsn("postgresql://u:p@host/db")
        twice = normalize_dsn(once)
        assert once == twice
        assert twice == "postgresql+psycopg://u:p@host/db"


# ── Non-Postgres schemes pass through ───────────────────────────────────────


class TestNonPostgresSchemes:
    @pytest.mark.parametrize(
        "url",
        [
            "sqlite:///local.db",
            "sqlite+aiosqlite:///local.db",
            "mysql://user:pass@host/db",
            "mysql+pymysql://user:pass@host/db",
            "mssql+pyodbc://user:pass@host/db",
            "oracle://user:pass@host/db",
        ],
    )
    def test_non_postgres_urls_are_left_alone(self, url):
        assert normalize_dsn(url) == url


# ── Tricky edge cases ──────────────────────────────────────────────────────


class TestEdgeCases:
    def test_only_the_first_scheme_is_rewritten(self):
        """A password containing 'postgresql://' must survive."""
        given = "postgresql://user:postgresql://@host/db"
        result = normalize_dsn(given)
        assert result == "postgresql+psycopg://user:postgresql://@host/db"

    def test_database_name_containing_postgresql(self):
        """DB named 'postgresql_backup' must not be mangled."""
        given = "postgresql://u:p@host/postgresql_backup"
        result = normalize_dsn(given)
        assert result == "postgresql+psycopg://u:p@host/postgresql_backup"

    def test_postgres_scheme_with_complex_password(self):
        """Passwords with special characters must survive normalization."""
        given = "postgres://user:p%40ss%3Dword@host:5432/db"
        result = normalize_dsn(given)
        assert result == "postgresql+psycopg://user:p%40ss%3Dword@host:5432/db"

    def test_postgres_with_options_querystring(self):
        """Connection options in the querystring must survive."""
        given = "postgresql://u:p@host/db?sslmode=require&connect_timeout=10"
        result = normalize_dsn(given)
        assert result == "postgresql+psycopg://u:p@host/db?sslmode=require&connect_timeout=10"

    def test_postgresql_with_ipv6_host(self):
        given = "postgresql://u:p@[::1]:5432/db"
        result = normalize_dsn(given)
        assert result == "postgresql+psycopg://u:p@[::1]:5432/db"

    def test_postgres_unix_socket_path(self):
        """Docker Compose with unix sockets emits this form."""
        given = "postgresql://u:p@/db?host=/var/run/postgresql"
        result = normalize_dsn(given)
        assert result == "postgresql+psycopg://u:p@/db?host=/var/run/postgresql"

    def test_postgresql_asyncpg_left_alone(self):
        """An explicitly async driver must not be rewritten."""
        given = "postgresql+asyncpg://u:p@host/db"
        assert normalize_dsn(given) == given

    def test_postgresql_psycopg2_left_alone(self):
        """If someone explicitly wants psycopg2, don't fight them."""
        given = "postgresql+psycopg2://u:p@host/db"
        assert normalize_dsn(given) == given

    def test_empty_string(self):
        """Edge case — should not crash."""
        assert normalize_dsn("") == ""

    def test_url_with_no_scheme(self):
        """No scheme at all — pass through without crashing."""
        assert normalize_dsn("host:5432/db") == "host:5432/db"
