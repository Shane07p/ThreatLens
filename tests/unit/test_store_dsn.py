"""DSN normalization — the one part of store.py testable without a database.

SQLAlchemy maps a bare `postgresql://` to psycopg2, which this project does not install.
CI emits exactly that form, so without normalization every integration test fails with
`No module named 'psycopg2'` — an error that points nowhere near the actual cause.
"""

from __future__ import annotations

import pytest

from threatlens.graph.store import normalize_dsn


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
def test_normalize_dsn(given, expected):
    assert normalize_dsn(given) == expected


def test_only_the_scheme_is_rewritten():
    """A password or database name containing the scheme text must survive intact."""
    given = "postgresql://user:postgresql://@host/db"
    assert normalize_dsn(given) == "postgresql+psycopg://user:postgresql://@host/db"


def test_non_postgres_urls_are_left_alone():
    assert normalize_dsn("sqlite:///local.db") == "sqlite:///local.db"


def test_normalization_is_idempotent():
    once = normalize_dsn("postgresql://u:p@host/db")
    assert normalize_dsn(once) == once
