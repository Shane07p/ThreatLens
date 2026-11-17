"""The database password never survives redaction, whatever it contains.

`threatlens config` prints the DSN through `redact_dsn`. The example tests use one password;
this one generates thousands — punctuation, unicode, characters that need URL-encoding —
because the passwords that break a redaction rule are the unusual ones.
"""

from __future__ import annotations

from urllib.parse import quote

import pytest
from hypothesis import given
from hypothesis import strategies as st

from threatlens.graph.store import redact_dsn

pytestmark = pytest.mark.security

names = st.text(alphabet="abcdefghijklmnopqrstuvwxyz", min_size=1, max_size=12)

# Prefixed with a marker no generated user, host, or database name can contain, so finding
# the password in the output can only mean it leaked.
passwords = st.text(min_size=1, max_size=40).map(lambda p: "PW#" + p)


@given(user=names, password=passwords, host=names, port=st.integers(1, 65535), db=names)
def test_the_password_never_appears_in_the_redacted_dsn(user, password, host, port, db):
    dsn = f"postgresql+psycopg://{user}:{quote(password, safe='')}@{host}:{port}/{db}"
    shown = redact_dsn(dsn)
    assert password not in shown
    assert quote(password, safe="") not in shown


@given(user=names, password=passwords, host=names, db=names)
def test_redaction_keeps_what_a_connection_needs(user, password, host, db):
    shown = redact_dsn(f"postgresql+psycopg://{user}:{quote(password, safe='')}@{host}/{db}")
    assert user in shown
    assert host in shown
    assert db in shown


@given(st.text(max_size=80))
def test_any_string_at_all_is_handled_without_raising(text):
    """`config` prints whatever is in DATABASE_URL, so redaction must never be the thing
    that crashes it."""
    assert isinstance(redact_dsn(text), str)
