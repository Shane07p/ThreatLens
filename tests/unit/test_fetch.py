import hashlib
import json
import time
from datetime import datetime
from pathlib import Path

import httpx
import pytest

from threatlens.ingest.fetch import _atomic_write_path, fetch_url, sha256_file, update_manifest


@pytest.fixture
def mock_httpx_stream(monkeypatch):
    """Factory fixture to mock httpx.stream responses with byte chunks or errors."""

    def _setup(chunks: list[bytes], error: Exception | None = None):
        class DummyResponse:
            def raise_for_status(self):
                pass

            def iter_bytes(self):
                yield from chunks
                if error:
                    raise error

        class DummyStream:
            def __enter__(self):
                return DummyResponse()

            def __exit__(self, *args):
                pass

        monkeypatch.setattr("httpx.stream", lambda method, url, **kwargs: DummyStream())

    return _setup


def _find_temp_files(dir_path: Path) -> list[Path]:
    """Find any temporary files (including hidden ones starting with .) in a directory."""
    if not dir_path.exists():
        return []
    return [p for p in dir_path.iterdir() if p.name.endswith(".tmp") or ".tmp." in p.name]


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


def test_update_manifest_updates_fetched_at_timestamp_on_reupdate(tmp_path):
    """Re-updating an entry updates its fetched_at timestamp."""
    m = tmp_path / "manifest.json"
    res1 = update_manifest(m, "a.json", {"sha256": "1"})
    t1 = res1["a.json"]["fetched_at"]

    time.sleep(0.001)

    res2 = update_manifest(m, "a.json", {"sha256": "1"})
    t2 = res2["a.json"]["fetched_at"]

    assert t2 >= t1


def test_update_manifest_raises_on_corrupted_file(tmp_path):
    m = tmp_path / "manifest.json"
    m.write_text("{corrupted json")
    with pytest.raises(json.JSONDecodeError):
        update_manifest(m, "a.json", {"sha256": "1"})


def test_update_manifest_preserves_original_file_on_write_error(tmp_path, monkeypatch):
    """If an error occurs while writing manifest content, original file stays untouched."""
    m = tmp_path / "manifest.json"
    m.write_text('{"a": {"sha256": "original"}}')

    def _failing_write_text(self, *args, **kwargs):
        raise OSError("Disk write error")

    monkeypatch.setattr("pathlib.Path.write_text", _failing_write_text)

    with pytest.raises(OSError, match="Disk write error"):
        update_manifest(m, "b.json", {"sha256": "new"})

    assert m.read_text() == '{"a": {"sha256": "original"}}'
    assert _find_temp_files(tmp_path) == []


def test_fetch_refuses_to_overwrite_without_force(tmp_path):
    dest = tmp_path / "existing.json"
    dest.write_text("{}")
    with pytest.raises(FileExistsError, match="--force"):
        fetch_url("https://example/x.json", dest, force=False)


def test_fetch_url_downloads_file_and_returns_provenance(tmp_path, mock_httpx_stream):
    mock_httpx_stream([b'{"status":', b' "ok"}'])
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
    assert not dest.exists()
    assert _find_temp_files(tmp_path) == []


def test_fetch_url_overwrites_when_forced(tmp_path, mock_httpx_stream):
    dest = tmp_path / "existing.json"
    dest.write_bytes(b"old content")

    mock_httpx_stream([b"new content"])
    result = fetch_url("https://example/x.json", dest, force=True)
    assert dest.read_bytes() == b"new content"
    assert result["bytes"] == len(b"new content")


def test_fetch_url_cleans_up_temp_file_and_preserves_destination_on_stream_failure(
    tmp_path, mock_httpx_stream
):
    """If download stream fails midway,
    destination file remains intact and temp files are unlinked."""
    dest = tmp_path / "target.json"
    dest.write_bytes(b"original content")

    mock_httpx_stream(
        [b"partial data"],
        error=RuntimeError("Stream interrupted mid-download"),
    )

    with pytest.raises(RuntimeError, match="Stream interrupted mid-download"):
        fetch_url("https://example/x.json", dest, force=True)

    assert dest.read_bytes() == b"original content"
    assert _find_temp_files(tmp_path) == []


def test_atomic_write_path_creates_nested_parent_directory(tmp_path):
    """Context manager creates parent directories automatically if they do not exist."""
    dest = tmp_path / "sub" / "dir" / "file.txt"
    with _atomic_write_path(dest) as tmp_p:
        tmp_p.write_text("nested content", encoding="utf-8")

    assert dest.read_text(encoding="utf-8") == "nested content"


def test_atomic_write_path_cleans_up_temp_file_on_permission_error(tmp_path, monkeypatch):
    """Permission error during file writing cleans up temporary file and re-raises exception."""
    dest = tmp_path / "protected.json"

    def _failing_open(*args, **kwargs):
        raise PermissionError("Permission denied")

    monkeypatch.setattr("builtins.open", _failing_open)

    with (
        pytest.raises(PermissionError, match="Permission denied"),
        _atomic_write_path(dest) as tmp_p,
        open(tmp_p, "wb") as fh,
    ):
        fh.write(b"data")

    assert not dest.exists()
    assert _find_temp_files(tmp_path) == []


def test_atomic_write_path_cleans_up_temp_file_if_replace_fails(tmp_path, monkeypatch):
    """If atomic replacement fails, temporary file is unlinked and destination stays intact."""
    dest = tmp_path / "dest.json"
    dest.write_text("original content")

    def _failing_replace(self, target):
        raise PermissionError("Replace forbidden")

    monkeypatch.setattr("pathlib.Path.replace", _failing_replace)

    with (
        pytest.raises(PermissionError, match="Replace forbidden"),
        _atomic_write_path(dest) as tmp_p,
    ):
        tmp_p.write_text("new content")

    assert dest.read_text() == "original content"
    assert _find_temp_files(tmp_path) == []
