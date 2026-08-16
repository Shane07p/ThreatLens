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
    """Factory fixture to mock httpx.stream responses.

    Supports byte chunks, status codes, headers, or errors.
    """

    def _setup(
        chunks: list[bytes],
        error: Exception | None = None,
        status_code: int = 200,
        headers: dict | None = None,
    ):
        class DummyResponse:
            def __init__(self):
                self.status_code = status_code
                self.headers = headers or {}

            def raise_for_status(self):
                if self.status_code >= 400:
                    req = httpx.Request("GET", "https://example/x.json")
                    res = httpx.Response(self.status_code, request=req)
                    raise httpx.HTTPStatusError(
                        f"HTTP {self.status_code}", request=req, response=res
                    )

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
        status_code = 404
        headers = {}

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


def test_fetch_url_content_length_mismatch_raises_value_error(tmp_path, mock_httpx_stream):
    """If Content-Length header differs from actual downloaded size, ValueError is raised."""
    dest = tmp_path / "mismatch.json"
    mock_httpx_stream([b"data"], headers={"content-length": "100"})

    with pytest.raises(ValueError, match="does not match Content-Length"):
        fetch_url("https://example/x.json", dest)

    assert not dest.exists()


def test_fetch_url_conditional_request_304_not_modified(tmp_path, mock_httpx_stream):
    """Conditional GET returns 304 Not Modified when remote resource is unchanged."""
    dest = tmp_path / "cached.json"
    dest.write_bytes(b"cached payload")
    manifest = tmp_path / "manifest.json"
    manifest.write_text(json.dumps({"cached.json": {"etag": "abc-123"}}))

    mock_httpx_stream([], status_code=304)
    result = fetch_url("https://example/x.json", dest, manifest_path=manifest)

    assert result["not_modified"] is True
    assert result["bytes"] == len(b"cached payload")


def test_fetch_url_progress_callback_invoked(tmp_path, mock_httpx_stream):
    """Progress callback is called during download with chunk sizes and total bytes."""
    dest = tmp_path / "progress.json"
    mock_httpx_stream([b"chunk1", b"chunk2"], headers={"content-length": "12"})

    calls = []

    def _progress(chunk_size, total):
        calls.append((chunk_size, total))

    result = fetch_url("https://example/x.json", dest, progress_callback=_progress)

    assert len(calls) == 2
    assert calls[0] == (6, 12)
    assert calls[1] == (6, 12)
    assert result["bytes"] == 12


def test_fetch_url_retry_on_transient_error(tmp_path, monkeypatch):
    """Transient errors trigger retries up to max attempts."""
    dest = tmp_path / "retry.json"
    attempts = 0

    class TransientStream:
        def __enter__(self):
            nonlocal attempts
            attempts += 1
            if attempts == 1:
                req = httpx.Request("GET", "https://example/x.json")
                res = httpx.Response(503, request=req)
                raise httpx.HTTPStatusError("503 Service Unavailable", request=req, response=res)

            class SuccessResponse:
                status_code = 200
                headers = {}

                def raise_for_status(self):
                    pass

                def iter_bytes(self):
                    yield b"success data"

            return SuccessResponse()

        def __exit__(self, *args):
            pass

    monkeypatch.setattr("httpx.stream", lambda method, url, **kwargs: TransientStream())
    result = fetch_url("https://example/x.json", dest)

    assert attempts == 2
    assert dest.read_bytes() == b"success data"
    assert result["bytes"] == len(b"success data")


def test_fetch_url_stores_etag_and_last_modified(tmp_path, mock_httpx_stream):
    """ETag and Last-Modified headers are included in returned metadata if present."""
    dest = tmp_path / "headers.json"
    mock_httpx_stream(
        [b"content"],
        headers={"etag": '"v123"', "last-modified": "Wed, 21 Oct 2015 07:28:00 GMT"},
    )
    result = fetch_url("https://example/x.json", dest)

    assert result["etag"] == '"v123"'
    assert result["last_modified"] == "Wed, 21 Oct 2015 07:28:00 GMT"


def test_fetch_url_fails_after_max_retries(tmp_path, monkeypatch):
    """Persistent transient errors re-raise after exhausting retry attempts."""
    dest = tmp_path / "fail.json"

    class FailingStream:
        def __enter__(self):
            req = httpx.Request("GET", "https://example/x.json")
            res = httpx.Response(500, request=req)
            raise httpx.HTTPStatusError("500 Internal Error", request=req, response=res)

        def __exit__(self, *args):
            pass

    monkeypatch.setattr("httpx.stream", lambda method, url, **kwargs: FailingStream())

    with pytest.raises(httpx.HTTPStatusError):
        fetch_url("https://example/x.json", dest)

    assert not dest.exists()


def test_mappings_url_preserves_url_encoding():
    """MAPPINGS_URL must keep %26 encoded instead of raw & to avoid 404 response."""
    from threatlens.ingest.fetch import MAPPINGS_URL

    assert "%26" in MAPPINGS_URL
    assert "Att%26ckToCveMappings.csv" in MAPPINGS_URL
    assert "Att&ckToCveMappings.csv" not in MAPPINGS_URL


def test_fetch_mappings_snapshot_creates_file_and_manifest_entry(tmp_path, mock_httpx_stream):
    """fetch_url for MAPPINGS_URL downloads Att&ckToCveMappings.csv and updates manifest."""
    from threatlens.ingest.fetch import MAPPINGS_URL

    mock_httpx_stream([b"CVE ID,Primary Impact\nCVE-2021-44228,Log4Shell\n"])
    dest = tmp_path / "Att&ckToCveMappings.csv"
    manifest = tmp_path / "manifest.json"

    res = fetch_url(MAPPINGS_URL, dest, manifest_path=manifest)
    data = update_manifest(manifest, dest.name, res)

    assert dest.exists()
    assert dest.read_bytes() == b"CVE ID,Primary Impact\nCVE-2021-44228,Log4Shell\n"
    assert res["sha256"] == sha256_file(dest)

    entry = data["Att&ckToCveMappings.csv"]
    assert entry["url"] == MAPPINGS_URL
    assert entry["sha256"] == res["sha256"]
    assert "timestamp" in entry
    assert "fetched_at" in entry


def test_fetch_mappings_partial_download_failure_does_not_corrupt_manifest_or_file(
    tmp_path, mock_httpx_stream
):
    """Failed download stream leaves existing file intact and does not pollute manifest."""
    dest = tmp_path / "Att&ckToCveMappings.csv"
    dest.write_bytes(b"existing valid data")
    manifest = tmp_path / "manifest.json"
    manifest.write_text(json.dumps({"Att&ckToCveMappings.csv": {"sha256": "original"}}))

    mock_httpx_stream(
        [b"corrupted partial"],
        error=RuntimeError("Connection reset"),
    )

    with pytest.raises(RuntimeError, match="Connection reset"):
        fetch_url("https://example/mappings.csv", dest, force=True, manifest_path=manifest)

    assert dest.read_bytes() == b"existing valid data"
    manifest_data = json.loads(manifest.read_text())
    assert manifest_data["Att&ckToCveMappings.csv"]["sha256"] == "original"


def test_collect_scoped_cve_ids_union_and_deduplication(tmp_path):
    """collect_scoped_cve_ids combines mappings CSV and KEV catalog, deduplicating IDs."""
    from threatlens.ingest.fetch import collect_scoped_cve_ids

    mappings_file = tmp_path / "Att&ckToCveMappings.csv"
    mappings_file.write_text(
        "CVE ID,Primary Impact\n"
        "CVE-2021-44228,Log4Shell\n"
        "CVE-2021-44228,DuplicateLog4j\n"
        "CVE-2022-22965,Spring4Shell\n"
    )

    kev_data = {
        "vulnerabilities": [
            {"cveID": "CVE-2021-44228"},
            {"cveID": "cve-2023-23397"},
        ]
    }

    valid_ids, invalid_ids = collect_scoped_cve_ids(mappings_path=mappings_file, kev_data=kev_data)
    assert valid_ids == ["CVE-2021-44228", "CVE-2022-22965", "CVE-2023-23397"]
    assert invalid_ids == []


def test_collect_scoped_cve_ids_handles_invalid_cves(tmp_path):
    """Malformed or invalid CVE ID formats are separated into invalid_ids."""
    from threatlens.ingest.fetch import collect_scoped_cve_ids

    mappings_file = tmp_path / "Att&ckToCveMappings.csv"
    mappings_file.write_text(
        "CVE ID,Primary Impact\nCVE-2021-44228,Valid\nINVALID-ID,Bad\nN/A,Bad\n"
    )

    kev_data = {"vulnerabilities": [{"cveID": "CVE-INVALID-FORMAT"}]}

    valid_ids, invalid_ids = collect_scoped_cve_ids(mappings_path=mappings_file, kev_data=kev_data)
    assert valid_ids == ["CVE-2021-44228"]
    assert set(invalid_ids) == {"INVALID-ID", "N/A", "CVE-INVALID-FORMAT"}


def test_collect_scoped_cve_ids_missing_mappings_file_raises_error(tmp_path):
    """Missing mappings file raises FileNotFoundError."""
    from threatlens.ingest.fetch import collect_scoped_cve_ids

    missing_file = tmp_path / "nonexistent.csv"
    with pytest.raises(FileNotFoundError, match="Mappings file not found"):
        collect_scoped_cve_ids(mappings_path=missing_file, kev_data={})


def test_fetch_scoped_nvd_success_and_parse_compatibility(tmp_path):
    """fetch_scoped_nvd queries NVD 2.0 API, writes snapshot, and produces valid Nodes."""
    from threatlens.ingest.fetch import TokenBucket, fetch_scoped_nvd
    from threatlens.ingest.nvd import parse_cve_record

    mappings_file = tmp_path / "Att&ckToCveMappings.csv"
    mappings_file.write_text("CVE ID,Primary Impact\nCVE-2021-44228,Log4Shell\n")
    dest = tmp_path / "nvd-scoped.json"
    manifest = tmp_path / "manifest.json"

    kev_data = {"vulnerabilities": []}

    class MockTransport(httpx.BaseTransport):
        def handle_request(self, request):
            url_str = str(request.url)
            assert "cveId=CVE-2021-44228" in url_str
            body = json.dumps(
                {
                    "totalResults": 1,
                    "vulnerabilities": [
                        {
                            "cve": {
                                "id": "CVE-2021-44228",
                                "descriptions": [{"lang": "en", "value": "Log4j2 vuln"}],
                                "metrics": {
                                    "cvssMetricV31": [
                                        {
                                            "cvssData": {
                                                "baseScore": 10.0,
                                                "vectorString": "CVSS:3.1/AV:N",
                                            }
                                        }
                                    ]
                                },
                            }
                        }
                    ],
                }
            ).encode()
            return httpx.Response(200, content=body)

    client = httpx.Client(transport=MockTransport())
    tb = TokenBucket(api_key="test-api-key")

    res = fetch_scoped_nvd(
        dest=dest,
        mappings_path=mappings_file,
        manifest_path=manifest,
        api_key="test-api-key",
        client=client,
        rate_limiter=tb,
        kev_data=kev_data,
    )

    assert dest.exists()
    assert res["requested_cve_count"] == 1
    assert res["fetched_cve_count"] == 1
    assert res["missing_cve_count"] == 0
    assert "timestamp" in json.loads(manifest.read_text())["nvd-scoped.json"]

    snapshot_raw = json.loads(dest.read_text(encoding="utf-8"))
    nodes = [parse_cve_record(v["cve"]) for v in snapshot_raw["vulnerabilities"]]
    assert len(nodes) == 1
    assert nodes[0].id == "cve:CVE-2021-44228"
    assert nodes[0].attrs["cvss_score"] == 10.0


def test_fetch_scoped_nvd_pagination_support(tmp_path):
    """Paginates using startIndex if NVD totalResults > len(vulnerabilities)."""
    from threatlens.ingest.fetch import TokenBucket, fetch_scoped_nvd

    mappings_file = tmp_path / "Att&ckToCveMappings.csv"
    mappings_file.write_text("CVE ID,Primary Impact\nCVE-2021-44228,Log4Shell\n")
    dest = tmp_path / "nvd-scoped.json"

    class PagedTransport(httpx.BaseTransport):
        def handle_request(self, request):
            url_str = str(request.url)
            if "startIndex=1" in url_str:
                body = json.dumps(
                    {
                        "totalResults": 2,
                        "vulnerabilities": [{"cve": {"id": "CVE-2021-44228", "page": 2}}],
                    }
                ).encode()
            else:
                body = json.dumps(
                    {
                        "totalResults": 2,
                        "vulnerabilities": [{"cve": {"id": "CVE-2021-44228", "page": 1}}],
                    }
                ).encode()
            return httpx.Response(200, content=body)

    client = httpx.Client(transport=PagedTransport())
    tb = TokenBucket(api_key="test-key")

    res = fetch_scoped_nvd(
        dest=dest,
        mappings_path=mappings_file,
        client=client,
        rate_limiter=tb,
        kev_data={"vulnerabilities": []},
    )

    assert res["fetched_cve_count"] == 2


def test_fetch_scoped_nvd_missing_cve_record_handled(tmp_path):
    """CVE record absent from NVD is recorded as missing without creating fake records."""
    from threatlens.ingest.fetch import TokenBucket, fetch_scoped_nvd

    mappings_file = tmp_path / "Att&ckToCveMappings.csv"
    mappings_file.write_text("CVE ID,Primary Impact\nCVE-9999-0000,NonExistent\n")
    dest = tmp_path / "nvd-scoped.json"

    class EmptyTransport(httpx.BaseTransport):
        def handle_request(self, request):
            body = json.dumps({"totalResults": 0, "vulnerabilities": []}).encode()
            return httpx.Response(200, content=body)

    client = httpx.Client(transport=EmptyTransport())

    res = fetch_scoped_nvd(
        dest=dest,
        mappings_path=mappings_file,
        client=client,
        rate_limiter=TokenBucket(),
        kev_data={"vulnerabilities": []},
    )

    assert res["requested_cve_count"] == 1
    assert res["fetched_cve_count"] == 0
    assert res["missing_cve_count"] == 1
    snapshot_raw = json.loads(dest.read_text())
    assert snapshot_raw["vulnerabilities"] == []


def test_fetch_scoped_nvd_refuses_overwrite_without_force(tmp_path):
    """FileExistsError raised if nvd-scoped.json exists and force is False."""
    from threatlens.ingest.fetch import fetch_scoped_nvd

    dest = tmp_path / "nvd-scoped.json"
    dest.write_text("{}")
    mappings_file = tmp_path / "Att&ckToCveMappings.csv"
    mappings_file.write_text("CVE ID,Primary Impact\nCVE-2021-44228,Log4Shell\n")

    with pytest.raises(FileExistsError, match="--force"):
        fetch_scoped_nvd(dest, mappings_file, force=False, kev_data={"vulnerabilities": []})


def test_fetch_scoped_nvd_failure_preserves_destination_and_manifest(tmp_path):
    """Network failure mid-download preserves existing snapshot and leaves manifest unpolluted."""
    from threatlens.ingest.fetch import fetch_scoped_nvd

    dest = tmp_path / "nvd-scoped.json"
    dest.write_text('{"original": "data"}')
    manifest = tmp_path / "manifest.json"
    manifest.write_text(json.dumps({"nvd-scoped.json": {"sha256": "orig-sha"}}))
    mappings_file = tmp_path / "Att&ckToCveMappings.csv"
    mappings_file.write_text("CVE ID,Primary Impact\nCVE-2021-44228,Log4Shell\n")

    class FailingTransport(httpx.BaseTransport):
        def handle_request(self, request):
            return httpx.Response(500, content=b"Server error")

    client = httpx.Client(transport=FailingTransport())

    with pytest.raises(httpx.HTTPStatusError):
        fetch_scoped_nvd(
            dest=dest,
            mappings_path=mappings_file,
            force=True,
            manifest_path=manifest,
            client=client,
            kev_data={"vulnerabilities": []},
        )

    assert dest.read_text() == '{"original": "data"}'
    manifest_data = json.loads(manifest.read_text())
    assert manifest_data["nvd-scoped.json"]["sha256"] == "orig-sha"


def test_should_retry_nvd_exception_predicate_rules():
    """_should_retry_nvd_exception retries 403, 503, 5xx, and transport errors; rejects 400, 404."""
    from threatlens.ingest.fetch import _should_retry_nvd_exception

    req = httpx.Request("GET", "https://services.nvd.nist.gov/rest/json/cves/2.0")

    assert _should_retry_nvd_exception(httpx.TransportError("connection error")) is True
    assert _should_retry_nvd_exception(httpx.TimeoutException("timeout")) is True
    res403 = httpx.HTTPStatusError("403", request=req, response=httpx.Response(403))
    assert _should_retry_nvd_exception(res403) is True
    res503 = httpx.HTTPStatusError("503", request=req, response=httpx.Response(503))
    assert _should_retry_nvd_exception(res503) is True
    res500 = httpx.HTTPStatusError("500", request=req, response=httpx.Response(500))
    assert _should_retry_nvd_exception(res500) is True

    res400 = httpx.HTTPStatusError("400", request=req, response=httpx.Response(400))
    assert _should_retry_nvd_exception(res400) is False
    res404 = httpx.HTTPStatusError("404", request=req, response=httpx.Response(404))
    assert _should_retry_nvd_exception(res404) is False
    res401 = httpx.HTTPStatusError("401", request=req, response=httpx.Response(401))
    assert _should_retry_nvd_exception(res401) is False


def test_nvd_retry_403_followed_by_success(tmp_path, monkeypatch):
    """HTTP 403 triggers a retry which acquires a rate token and succeeds."""
    from threatlens.ingest.fetch import TokenBucket, fetch_scoped_nvd

    monkeypatch.setattr("tenacity.nap.sleep", lambda s: None)

    mappings_file = tmp_path / "Att&ckToCveMappings.csv"
    mappings_file.write_text("CVE ID,Primary Impact\nCVE-2021-44228,Log4Shell\n")
    dest = tmp_path / "nvd-scoped.json"

    attempts = 0

    class Retry403Transport(httpx.BaseTransport):
        def handle_request(self, request):
            nonlocal attempts
            attempts += 1
            if attempts == 1:
                return httpx.Response(403, content=b"Rate limit 403 storm")
            body = json.dumps(
                {"totalResults": 1, "vulnerabilities": [{"cve": {"id": "CVE-2021-44228"}}]}
            ).encode()
            return httpx.Response(200, content=body)

    client = httpx.Client(transport=Retry403Transport())

    class TrackedLimiter(TokenBucket):
        def __init__(self):
            super().__init__()
            self.acquire_count = 0

        def acquire(self, api_key=None):
            self.acquire_count += 1
            super().acquire(api_key)

    tb = TrackedLimiter()

    res = fetch_scoped_nvd(
        dest=dest,
        mappings_path=mappings_file,
        client=client,
        rate_limiter=tb,
        kev_data={"vulnerabilities": []},
    )

    assert attempts == 2
    assert tb.acquire_count == 2
    assert res["fetched_cve_count"] == 1


def test_nvd_retry_503_followed_by_success(tmp_path, monkeypatch):
    """HTTP 503 Service Unavailable triggers a retry and succeeds."""
    from threatlens.ingest.fetch import TokenBucket, fetch_scoped_nvd

    monkeypatch.setattr("tenacity.nap.sleep", lambda s: None)

    mappings_file = tmp_path / "Att&ckToCveMappings.csv"
    mappings_file.write_text("CVE ID,Primary Impact\nCVE-2021-44228,Log4Shell\n")
    dest = tmp_path / "nvd-scoped.json"

    attempts = 0

    class Retry503Transport(httpx.BaseTransport):
        def handle_request(self, request):
            nonlocal attempts
            attempts += 1
            if attempts == 1:
                return httpx.Response(503, content=b"Service Unavailable")
            body = json.dumps(
                {"totalResults": 1, "vulnerabilities": [{"cve": {"id": "CVE-2021-44228"}}]}
            ).encode()
            return httpx.Response(200, content=body)

    client = httpx.Client(transport=Retry503Transport())

    res = fetch_scoped_nvd(
        dest=dest,
        mappings_path=mappings_file,
        client=client,
        rate_limiter=TokenBucket(),
        kev_data={"vulnerabilities": []},
    )

    assert attempts == 2
    assert res["fetched_cve_count"] == 1


def test_nvd_retry_multiple_transient_failures_then_success(tmp_path, monkeypatch):
    """Multiple transient errors (503 then 403) are retried up to max attempts."""
    from threatlens.ingest.fetch import TokenBucket, fetch_scoped_nvd

    monkeypatch.setattr("tenacity.nap.sleep", lambda s: None)

    mappings_file = tmp_path / "Att&ckToCveMappings.csv"
    mappings_file.write_text("CVE ID,Primary Impact\nCVE-2021-44228,Log4Shell\n")
    dest = tmp_path / "nvd-scoped.json"

    attempts = 0

    class MultiFailTransport(httpx.BaseTransport):
        def handle_request(self, request):
            nonlocal attempts
            attempts += 1
            if attempts == 1:
                return httpx.Response(503, content=b"Service Unavailable")
            if attempts == 2:
                return httpx.Response(403, content=b"Forbidden")
            body = json.dumps(
                {"totalResults": 1, "vulnerabilities": [{"cve": {"id": "CVE-2021-44228"}}]}
            ).encode()
            return httpx.Response(200, content=body)

    client = httpx.Client(transport=MultiFailTransport())

    res = fetch_scoped_nvd(
        dest=dest,
        mappings_path=mappings_file,
        client=client,
        rate_limiter=TokenBucket(),
        kev_data={"vulnerabilities": []},
    )

    assert attempts == 3
    assert res["fetched_cve_count"] == 1


def test_nvd_retry_max_attempts_exhausted_reraises_exception(tmp_path, monkeypatch):
    """Persistent 503 failures stop after max attempts (3) and reraise exception."""
    from threatlens.ingest.fetch import TokenBucket, fetch_scoped_nvd

    monkeypatch.setattr("tenacity.nap.sleep", lambda s: None)

    mappings_file = tmp_path / "Att&ckToCveMappings.csv"
    mappings_file.write_text("CVE ID,Primary Impact\nCVE-2021-44228,Log4Shell\n")
    dest = tmp_path / "nvd-scoped.json"

    attempts = 0

    class PersistentFailTransport(httpx.BaseTransport):
        def handle_request(self, request):
            nonlocal attempts
            attempts += 1
            return httpx.Response(503, content=b"Persistent Unavailable")

    client = httpx.Client(transport=PersistentFailTransport())

    with pytest.raises(httpx.HTTPStatusError) as exc_info:
        fetch_scoped_nvd(
            dest=dest,
            mappings_path=mappings_file,
            client=client,
            rate_limiter=TokenBucket(),
            kev_data={"vulnerabilities": []},
        )

    assert exc_info.value.response.status_code == 503
    assert attempts == 3
    assert not dest.exists()


def test_nvd_non_retryable_400_fails_immediately_without_retry(tmp_path, monkeypatch):
    """HTTP 400 Bad Request is non-retryable and fails on attempt 1."""
    from threatlens.ingest.fetch import TokenBucket, fetch_scoped_nvd

    monkeypatch.setattr("tenacity.nap.sleep", lambda s: None)

    mappings_file = tmp_path / "Att&ckToCveMappings.csv"
    mappings_file.write_text("CVE ID,Primary Impact\nCVE-2021-44228,Log4Shell\n")
    dest = tmp_path / "nvd-scoped.json"

    attempts = 0

    class Fail400Transport(httpx.BaseTransport):
        def handle_request(self, request):
            nonlocal attempts
            attempts += 1
            return httpx.Response(400, content=b"Bad Request")

    client = httpx.Client(transport=Fail400Transport())

    with pytest.raises(httpx.HTTPStatusError) as exc_info:
        fetch_scoped_nvd(
            dest=dest,
            mappings_path=mappings_file,
            client=client,
            rate_limiter=TokenBucket(),
            kev_data={"vulnerabilities": []},
        )

    assert exc_info.value.response.status_code == 400
    assert attempts == 1


def test_nvd_non_retryable_404_fails_immediately_without_retry(tmp_path, monkeypatch):
    """HTTP 404 Not Found is non-retryable and fails on attempt 1."""
    from threatlens.ingest.fetch import TokenBucket, fetch_scoped_nvd

    monkeypatch.setattr("tenacity.nap.sleep", lambda s: None)

    mappings_file = tmp_path / "Att&ckToCveMappings.csv"
    mappings_file.write_text("CVE ID,Primary Impact\nCVE-2021-44228,Log4Shell\n")
    dest = tmp_path / "nvd-scoped.json"

    attempts = 0

    class Fail404Transport(httpx.BaseTransport):
        def handle_request(self, request):
            nonlocal attempts
            attempts += 1
            return httpx.Response(404, content=b"Not Found")

    client = httpx.Client(transport=Fail404Transport())

    with pytest.raises(httpx.HTTPStatusError) as exc_info:
        fetch_scoped_nvd(
            dest=dest,
            mappings_path=mappings_file,
            client=client,
            rate_limiter=TokenBucket(),
            kev_data={"vulnerabilities": []},
        )

    assert exc_info.value.response.status_code == 404
    assert attempts == 1


def test_retries_respect_rate_limiter_and_fake_clock(tmp_path, monkeypatch):
    """Retries invoke rate_limiter.acquire, triggering clock sleep if rate budget is exhausted."""
    from threatlens.ingest.fetch import TokenBucket, fetch_scoped_nvd

    monkeypatch.setattr("tenacity.nap.sleep", lambda s: None)

    mappings_file = tmp_path / "Att&ckToCveMappings.csv"
    mappings_file.write_text("CVE ID,Primary Impact\nCVE-2021-44228,Log4Shell\n")
    dest = tmp_path / "nvd-scoped.json"

    attempts = 0

    class Transport403Then200(httpx.BaseTransport):
        def handle_request(self, request):
            nonlocal attempts
            attempts += 1
            if attempts == 1:
                return httpx.Response(403, content=b"Rate limit 403")
            body = json.dumps(
                {"totalResults": 1, "vulnerabilities": [{"cve": {"id": "CVE-2021-44228"}}]}
            ).encode()
            return httpx.Response(200, content=body)

    client = httpx.Client(transport=Transport403Then200())

    class FakeClock:
        def __init__(self):
            self.now = 0.0
            self.slept = []

        def time(self):
            return self.now

        def sleep(self, s):
            self.slept.append(s)
            self.now += s

    c = FakeClock()
    tb = TokenBucket(rate=1, per_seconds=10.0, clock=c.time, sleep=c.sleep)

    res = fetch_scoped_nvd(
        dest=dest,
        mappings_path=mappings_file,
        client=client,
        rate_limiter=tb,
        kev_data={"vulnerabilities": []},
    )

    assert attempts == 2
    assert len(c.slept) == 1
    assert c.slept[0] == 10.0
    assert res["fetched_cve_count"] == 1
