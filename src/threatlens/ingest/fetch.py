"""Download snapshots and record their provenance.

Query-time code must never call these. Snapshots are fetched once and pinned to ensure
reproducible results across evaluations.
"""

from __future__ import annotations

import hashlib
import json
import logging
import tempfile
from collections.abc import Callable, Generator
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path

import httpx
from tenacity import retry, retry_if_exception, stop_after_attempt, wait_exponential

logger = logging.getLogger(__name__)

ATTACK_URL = (
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/"
    "master/enterprise-attack/enterprise-attack.json"
)

HTTP_TIMEOUT = httpx.Timeout(connect=10.0, read=120.0, write=30.0, pool=10.0)


def _should_retry_exception(exc: BaseException) -> bool:
    """Determine whether an exception during HTTP fetch is transient and should be retried.

    Retries on network transport errors, timeouts, and 5xx server errors.
    4xx client errors (e.g. 404, 403) are not retried.
    """
    if isinstance(exc, (httpx.TransportError, httpx.TimeoutException)):
        return True
    if isinstance(exc, httpx.HTTPStatusError):
        return exc.response.status_code >= 500
    return False


@contextmanager
def _atomic_write_path(dest: Path) -> Generator[Path, None, None]:
    """Yield a temporary file path in dest.parent, replacing dest atomically on success.

    Creates dest.parent if it does not exist. Writes are directed to a temporary file
    in the same directory to guarantee atomic replacement on the same filesystem.
    If an exception is raised inside the context block, the temporary file is unlinked
    and dest remains untouched.

    Raises Exception: Any exception raised during writing is re-raised after cleanup.
    """
    dest.parent.mkdir(parents=True, exist_ok=True)
    tmp_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            dir=dest.parent,
            delete=False,
            prefix=f".{dest.name}.",
            suffix=".tmp",
        ) as tmp_file:
            tmp_path = Path(tmp_file.name)
        yield tmp_path
        tmp_path.replace(dest)
    except Exception:
        if tmp_path is not None and tmp_path.exists():
            tmp_path.unlink(missing_ok=True)
        raise


def sha256_file(path: Path) -> str:
    """Compute the SHA-256 hash of a file on disk.

    Reads the file in 1 MB chunks to handle large snapshot files efficiently without
    excessive memory usage.

    Returns the hex digest string.
    """
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for block in iter(lambda: fh.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def update_manifest(manifest_path: Path, key: str, entry: dict) -> dict:
    """Record or update a snapshot entry in the manifest file.

    Loads the existing manifest if present, adds or updates the given key with metadata
    and an ISO timestamp, and atomically persists the JSON back to disk.

    Returns the updated manifest dictionary.
    """
    data: dict = {}
    if manifest_path.exists():
        data = json.loads(manifest_path.read_text(encoding="utf-8"))
    existing_entry = data.get(key, {})
    data[key] = {**existing_entry, **entry, "fetched_at": datetime.now(UTC).isoformat()}
    content = json.dumps(data, indent=2, sort_keys=True) + "\n"
    with _atomic_write_path(manifest_path) as tmp_path:
        tmp_path.write_text(content, encoding="utf-8")
    return data


def fetch_url(
    url: str,
    dest: Path,
    force: bool = False,
    progress_callback: Callable[[int, int | None], None] | None = None,
    manifest_path: Path | None = None,
) -> dict:
    """Download a file from a URL to the specified destination path atomically.

    Supports conditional GET requests (If-None-Match / If-Modified-Since) if cached manifest
    metadata is available. Verifies Content-Length header if supplied by the server.
    Retries up to 3 times on transient network errors or 5xx HTTP server responses.

    Raises FileExistsError if the destination file exists and force is False.
    Raises ValueError if downloaded size differs from Content-Length header.
    Raises httpx.HTTPStatusError if HTTP request fails with a non-2xx/304 status code.
    Returns a dict with url, sha256 checksum, file size in bytes, etag, and last_modified.
    """
    headers: dict[str, str] = {}

    if dest.exists() and not force:
        if manifest_path and manifest_path.exists():
            try:
                manifest_data = json.loads(manifest_path.read_text(encoding="utf-8"))
                cached_entry = manifest_data.get(dest.name, {})
                if "etag" in cached_entry:
                    headers["If-None-Match"] = cached_entry["etag"]
                if "last_modified" in cached_entry:
                    headers["If-Modified-Since"] = cached_entry["last_modified"]
            except json.JSONDecodeError:
                pass
        if not headers:
            raise FileExistsError(f"{dest} already exists; pass --force to re-download")

    @retry(
        retry=retry_if_exception(_should_retry_exception),
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=0.1, min=0.1, max=1.0),
        reraise=True,
    )
    def _do_fetch() -> dict:
        logger.info("Fetching snapshot from %s", url)
        with httpx.stream(
            "GET",
            url,
            headers=headers,
            follow_redirects=True,
            timeout=HTTP_TIMEOUT,
        ) as response:
            if response.status_code == 304 and dest.exists():
                logger.info("Snapshot unchanged (304 Not Modified): %s", dest)
                return {
                    "url": url,
                    "sha256": sha256_file(dest),
                    "bytes": dest.stat().st_size,
                    "not_modified": True,
                }
            response.raise_for_status()

            raw_cl = response.headers.get("content-length")
            expected_bytes = int(raw_cl) if raw_cl and raw_cl.isdigit() else None
            etag = response.headers.get("etag")
            last_modified = response.headers.get("last-modified")

            downloaded_bytes = 0
            with _atomic_write_path(dest) as tmp_path, open(tmp_path, "wb") as fh:
                for chunk in response.iter_bytes():
                    fh.write(chunk)
                    downloaded_bytes += len(chunk)
                    if progress_callback:
                        progress_callback(len(chunk), expected_bytes)

                if expected_bytes is not None and downloaded_bytes != expected_bytes:
                    raise ValueError(
                        f"Downloaded size ({downloaded_bytes} bytes) does not match "
                        f"Content-Length header ({expected_bytes} bytes)"
                    )

            res = {
                "url": url,
                "sha256": sha256_file(dest),
                "bytes": dest.stat().st_size,
            }
            if etag:
                res["etag"] = etag
            if last_modified:
                res["last_modified"] = last_modified
            return res

    return _do_fetch()
