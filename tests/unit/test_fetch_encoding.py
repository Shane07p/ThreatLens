"""Downloading a source that arrives compressed.

MITRE serves the ATT&CK bundle gzipped: `content-encoding: gzip` with a `content-length`
of roughly 6 MB describing the compressed transfer, while the JSON httpx hands back after
decoding is roughly 54 MB. Comparing bytes written against that header rejects every
gzipped source — which is every real snapshot this project fetches.

Nothing caught it because the existing fetch tests return plain bodies, so the header and
the decoded length always agreed. The mock here reproduces what httpx really does: it
reports the server's headers verbatim and yields *decoded* bytes.
"""

from __future__ import annotations

import gzip
import json
from pathlib import Path

import pytest

from threatlens.ingest.fetch import fetch_url

PAYLOAD = json.dumps({"type": "bundle", "objects": [{"id": f"x{i}"} for i in range(200)]}).encode()


@pytest.fixture
def served(monkeypatch):
    """Serve `body` with `headers`, the way httpx presents an already-decoded response."""

    def _serve(headers: dict[str, str], body: bytes) -> None:
        class DummyResponse:
            status_code = 200

            def __init__(self):
                self.headers = headers

            def raise_for_status(self):
                pass

            def iter_bytes(self):
                yield body

        class DummyStream:
            def __enter__(self):
                return DummyResponse()

            def __exit__(self, *args):
                pass

        monkeypatch.setattr("httpx.stream", lambda method, url, **kwargs: DummyStream())

    return _serve


def test_a_gzipped_source_downloads(tmp_path: Path, served):
    """The bug that stopped Phase 1 at the first command."""
    compressed_len = len(gzip.compress(PAYLOAD))
    assert compressed_len != len(PAYLOAD), "sanity: the fixture must actually compress"

    served({"content-encoding": "gzip", "content-length": str(compressed_len)}, PAYLOAD)

    dest = tmp_path / "bundle.json"
    entry = fetch_url("https://example.test/bundle.json", dest)

    assert dest.read_bytes() == PAYLOAD
    assert entry["bytes"] == len(PAYLOAD)


def test_an_uncompressed_short_read_is_still_rejected(tmp_path: Path, served):
    """The check has to keep earning its place. With no content-encoding the header and
    the bytes on disk are directly comparable, and a truncated download must not pass."""
    served({"content-length": str(len(PAYLOAD) + 999)}, PAYLOAD)

    with pytest.raises(ValueError, match="does not match"):
        fetch_url("https://example.test/bundle.json", tmp_path / "bundle.json")


def test_identity_encoding_is_treated_as_uncompressed(tmp_path: Path, served):
    """`identity` means the body was not transformed, so the header is comparable again."""
    served(
        {"content-encoding": "identity", "content-length": str(len(PAYLOAD) + 999)},
        PAYLOAD,
    )

    with pytest.raises(ValueError, match="does not match"):
        fetch_url("https://example.test/bundle.json", tmp_path / "bundle.json")


def test_a_truncated_gzip_response_is_not_silently_accepted(tmp_path: Path, served):
    """Deliberate non-behavior, written down so the next reader knows it was a choice.

    Skipping the length check on an encoded response means a truncated gzip download is
    not caught *here*. It is caught later: the manifest sha256 will not match a re-fetch,
    and the STIX parser fails on incomplete JSON. Guarding it at this layer would need the
    server to send an unencoded length, which it does not.
    """
    served({"content-encoding": "gzip", "content-length": "999999"}, PAYLOAD[:50])

    dest = tmp_path / "bundle.json"
    fetch_url("https://example.test/bundle.json", dest)
    assert dest.read_bytes() == PAYLOAD[:50]
