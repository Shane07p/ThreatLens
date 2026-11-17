"""The guard that keeps unit tests off the network has to cover the database driver too.

`conftest.py` blocks Python's `socket.socket.connect`. psycopg reaches Postgres through
libpq, which opens its own sockets in C and never touches Python's socket module — so a unit
test that wandered into the database went straight past the guard. On Linux a refused
connection fails instantly and nobody notices; on Windows the TCP stack retries it, and a
nominal unit test stalled for long enough to time the suite out.
"""

from __future__ import annotations

import socket

import psycopg
import pytest


def test_a_plain_socket_connection_is_blocked():
    with pytest.raises(RuntimeError, match="network access from a unit test"):
        socket.create_connection(("127.0.0.1", 9))


def test_a_postgres_connection_is_blocked_before_libpq_is_reached():
    """The case the socket patch alone could not see."""
    with pytest.raises(RuntimeError, match="network access from a unit test"):
        psycopg.connect("postgresql://unused:unused@127.0.0.1:1/unused", connect_timeout=1)


def test_sqlalchemy_inherits_the_block():
    """The project never calls psycopg directly; every connection goes through SQLAlchemy,
    which looks psycopg up on the module. Blocking only the class would miss it."""
    from threatlens.graph.store import get_engine

    engine = get_engine("postgresql://unused:unused@127.0.0.1:1/unused")
    with pytest.raises(RuntimeError, match="network access from a unit test"):
        engine.connect()
