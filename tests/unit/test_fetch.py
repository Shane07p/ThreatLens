import hashlib
import json
from datetime import datetime

import httpx
import pytest

from threatlens.ingest.fetch import fetch_url, sha256_file, update_manifest


def test_sha256_matches_hashlib(tmp_path):
    f = tmp_path / "x.json"
    f.write_bytes(b'{"a": 1}')
    assert sha256_file(f) == hashlib.sha256(b'{"a": 1}').hexdigest()


def test_sha256_handles_empty_file(tmp_path):
    f = tmp_path / "empty.json"
    f.write_bytes(b"")
    assert sha256_file(f) == hashlib.sha256(b"").hexdigest()


def test_sha256_handles_multi_chunk_file(tmp_path):
    f = tmp_path / "large.bin"
    # 2.5 MB to exercise the 1 MB block reading loop multiple times
    data = b"x" * (2 * 1024 * 1024 + 512 * 1024)
    f.write_bytes(data)
    assert sha256_file(f) == hashlib.sha256(data).hexdigest()


def test_update_manifest_creates_file(tmp_path):
    m = tmp_path / "manifest.json"
    entry = {"url": "https://example/x.json", "sha256": "abc", "version": "19.1"}
    result = update_manifest(m, "x.json", entry)
    assert result["x.json"]["sha256"] == "abc"
    assert json.loads(m.read_text())["x.json"]["url"] == "https://example/x.json"


def test_update_manifest_preserves_other_entries(tmp_path):
    m = tmp_path / "manifest.json"
    update_manifest(m, "a.json", {"sha256": "1"})
    update_manifest(m, "b.json", {"sha256": "2"})
    data = json.loads(m.read_text())
    assert set(data) == {"a.json", "b.json"}


def test_update_manifest_overwrites_existing_entry(tmp_path):
    m = tmp_path / "manifest.json"
    update_manifest(m, "a.json", {"sha256": "1"})
    update_manifest(m, "a.json", {"sha256": "2"})
    data = json.loads(m.read_text())
    assert data["a.json"]["sha256"] == "2"
    assert len(data) == 1


def test_update_manifest_stamps_fetched_at(tmp_path):
    m = tmp_path / "manifest.json"
    result = update_manifest(m, "a.json", {"sha256": "1"})
    assert "fetched_at" in result["a.json"]


def test_update_manifest_fetched_at_is_valid_iso8601(tmp_path):
    m = tmp_path / "manifest.json"
    result = update_manifest(m, "a.json", {"sha256": "1"})
    fetched_at = result["a.json"]["fetched_at"]
    parsed = datetime.fromisoformat(fetched_at)
    assert parsed is not None


def test_update_manifest_raises_on_corrupted_file(tmp_path):
    m = tmp_path / "manifest.json"
    m.write_text("{corrupted json")
    with pytest.raises(json.JSONDecodeError):
        update_manifest(m, "a.json", {"sha256": "1"})


def test_fetch_refuses_to_overwrite_without_force(tmp_path):
    dest = tmp_path / "existing.json"
    dest.write_text("{}")
    with pytest.raises(FileExistsError, match="--force"):
        fetch_url("https://example/x.json", dest, force=False)


def test_fetch_url_downloads_file_and_returns_provenance(tmp_path, monkeypatch):
    class DummyResponse:
        def raise_for_status(self):
            pass

        def iter_bytes(self):
            yield b'{"status":'
            yield b' "ok"}'

    class DummyStream:
        def __enter__(self):
            return DummyResponse()

        def __exit__(self, *args):
            pass

    monkeypatch.setattr("httpx.stream", lambda method, url, **kwargs: DummyStream())
    dest = tmp_path / "out.json"
    result = fetch_url("https://example/x.json", dest)
    expected_bytes = b'{"status": "ok"}'
    assert dest.read_bytes() == expected_bytes
    assert result == {
        "url": "https://example/x.json",
        "sha256": hashlib.sha256(expected_bytes).hexdigest(),
        "bytes": len(expected_bytes),
    }


def test_fetch_url_raises_on_http_error(tmp_path, monkeypatch):
    class DummyErrorResponse:
        def raise_for_status(self):
            req = httpx.Request("GET", "https://example/x.json")
            res = httpx.Response(404, request=req)
            raise httpx.HTTPStatusError("404 Not Found", request=req, response=res)

        def iter_bytes(self):
            return iter([])

    class DummyErrorStream:
        def __enter__(self):
            return DummyErrorResponse()

        def __exit__(self, *args):
            pass

    monkeypatch.setattr("httpx.stream", lambda method, url, **kwargs: DummyErrorStream())
    dest = tmp_path / "out.json"
    with pytest.raises(httpx.HTTPStatusError):
        fetch_url("https://example/x.json", dest)


def test_fetch_url_overwrites_when_forced(tmp_path, monkeypatch):
    dest = tmp_path / "existing.json"
    dest.write_bytes(b"old content")

    class DummyResponse:
        def raise_for_status(self):
            pass

        def iter_bytes(self):
            yield b"new content"

    class DummyStream:
        def __enter__(self):
            return DummyResponse()

        def __exit__(self, *args):
            pass

    monkeypatch.setattr("httpx.stream", lambda method, url, **kwargs: DummyStream())
    result = fetch_url("https://example/x.json", dest, force=True)
    assert dest.read_bytes() == b"new content"
    assert result["bytes"] == len(b"new content")
