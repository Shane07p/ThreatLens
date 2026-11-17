"""Download snapshots and record their provenance.

Query-time code must never call these. Snapshots are fetched once and pinned to ensure
reproducible results across evaluations.
"""

from __future__ import annotations

import hashlib
import json
import logging
import re
import tempfile
import threading
import time
from collections.abc import Callable, Generator
from contextlib import contextmanager, suppress
from datetime import UTC, datetime
from pathlib import Path

import httpx
from tenacity import retry, retry_if_exception, stop_after_attempt, wait_exponential

from threatlens.ingest.mappings import read_mappings_rows

logger = logging.getLogger(__name__)

ATTACK_URL = (
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/"
    "master/enterprise-attack/enterprise-attack.json"
)

MAPPINGS_URL = (
    "https://raw.githubusercontent.com/center-for-threat-informed-defense/"
    "attack_to_cve/master/Att%26ckToCveMappings.csv"
)

CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

# The KEV catalog is written here so `ingest cves` can read it back and stamp
# attrs.kev. Fetching it only into memory to pick which CVEs to pull leaves the
# triage signal unrecoverable, and the flagging silently never fires.
KEV_FILENAME = "kev-catalog.json"
NVD_ENDPOINT = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CVE_ID_PATTERN = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)

# NVD returns at most one record per cveId query in practice.  Cap per-CVE
# pagination at this value as a safety net against a server that reports a
# bogus totalResults and would otherwise spin the loop indefinitely.
_MAX_PAGES_PER_CVE = 10


HTTP_TIMEOUT = httpx.Timeout(connect=10.0, read=120.0, write=30.0, pool=10.0)

DEFAULT_NVD_RATE_WITH_KEY = 50
DEFAULT_NVD_RATE_WITHOUT_KEY = 5
DEFAULT_NVD_WINDOW_SECONDS = 30.0


class TokenBucket:
    """Token-bucket rate limiter with per-API-key isolation and injectable clock.

    Rate limits requests to external services like the NVD API. When an API key is
    configured, NVD allows 50 requests per 30 seconds; without a key, it allows
    only 5 requests per 30 seconds. Exceeding the limit produces HTTP 403 errors.

    Token states are tracked per API key to ensure key isolation.

    Args:
        rate: Optional explicit rate limit (requests per window). If None, chosen
            based on whether an API key is provided (50 with key, 5 without).
        per_seconds: Duration of the rate limit window in seconds (default 30.0).
        api_key: Default API key for this bucket instance.
        clock: Injectable monotonic clock returning current timestamp as float.
        sleep: Injectable sleep callable taking duration in seconds.
    """

    # Floating-point round-trip through (per_seconds/rate)*(rate/per_seconds) is not
    # always exactly 1.0. Without this tolerance the token check fires again after the
    # computed sleep and schedules another infinitesimally small sleep, repeating forever.
    _EPSILON: float = 1e-9

    def __init__(
        self,
        rate: int | None = None,
        per_seconds: float = DEFAULT_NVD_WINDOW_SECONDS,
        api_key: str | None = None,
        clock: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        if rate is not None and rate <= 0:
            raise ValueError("rate must be greater than 0")
        if per_seconds <= 0:
            raise ValueError("per_seconds must be greater than 0")
        self.default_rate = rate
        self.per_seconds = per_seconds
        self.default_api_key = api_key
        self._clock = clock
        self._sleep = sleep
        self._lock = threading.Lock()
        self._states: dict[str | None, dict[str, float]] = {}

    def acquire(self, api_key: str | None = None) -> None:
        """Block until a token is available for the given API key, then consume one.

        If api_key is None, uses default_api_key passed at initialization.
        Calculates exact refill based on elapsed time. If tokens are exhausted,
        sleeps for the calculated duration outside the lock before refilling and consuming.
        """
        key = api_key if api_key is not None else self.default_api_key
        while True:
            with self._lock:
                rate = self._resolve_rate(key)
                now = self._clock()

                if key not in self._states:
                    self._states[key] = {
                        "tokens": float(rate),
                        "last_refill": now,
                    }

                state = self._states[key]
                self._refill(state, rate, now)

                if state["tokens"] >= 1.0 - self._EPSILON:
                    state["tokens"] = max(0.0, state["tokens"] - 1.0)
                    break

                deficit = 1.0 - state["tokens"]
                wait_time = deficit * (self.per_seconds / float(rate))

            self._sleep(wait_time)

    def get_tokens(self, api_key: str | None = None) -> float:
        """Return available tokens for an API key after refilling to current time."""
        key = api_key if api_key is not None else self.default_api_key
        with self._lock:
            rate = self._resolve_rate(key)
            now = self._clock()
            if key not in self._states:
                return float(rate)
            state = self._states[key]
            self._refill(state, rate, now)
            return state["tokens"]

    def get_rate(self, api_key: str | None = None) -> int:
        """Return the effective rate limit (requests per window) for an API key."""
        key = api_key if api_key is not None else self.default_api_key
        return self._resolve_rate(key)

    def _resolve_rate(self, key: str | None) -> int:
        if self.default_rate is not None:
            return self.default_rate
        if key and isinstance(key, str) and key.strip():
            return DEFAULT_NVD_RATE_WITH_KEY
        return DEFAULT_NVD_RATE_WITHOUT_KEY

    def _refill(self, state: dict[str, float], rate: int, now: float) -> None:
        if now > state["last_refill"]:
            elapsed = now - state["last_refill"]
            state["last_refill"] = now
            refill_amount = elapsed * (float(rate) / self.per_seconds)
            state["tokens"] = min(float(rate), state["tokens"] + refill_amount)


def _should_retry_exception(exc: BaseException) -> bool:
    """Determine whether an exception during HTTP fetch is transient and should be retried.

    Retries on network transport errors, timeouts, and 5xx server errors.
    4xx client errors (e.g. 404, 403) are not retried.
    """
    if isinstance(exc, (httpx.TransportError, httpx.TimeoutException)):
        return True
    if isinstance(exc, httpx.HTTPStatusError):
        return exc.response is not None and exc.response.status_code >= 500
    return False


def _should_retry_nvd_exception(exc: BaseException) -> bool:
    """Determine whether an exception during NVD API fetch is transient and should be retried.

    Retries on transport errors, timeouts, 5xx server errors (e.g. 503 Service Unavailable),
    and HTTP 403. NVD returns 403 during rate-limit storms even when the bucket is respected,
    so a single 403 is treated as transient and retried (the token bucket re-acquires before
    the next attempt, giving the server time to recover).

    HTTP 400, 401, 404, 422, and other client errors are permanent and are NOT retried.
    """
    if isinstance(exc, (httpx.TransportError, httpx.TimeoutException)):
        return True
    if isinstance(exc, httpx.HTTPStatusError):
        if exc.response is None:
            return False
        status = exc.response.status_code
        # 403 is the only sub-500 code NVD emits during rate-limit storms.
        # All 5xx codes (including 503) are covered by the >= 500 branch.
        return status == 403 or status >= 500
    return False


@retry(
    retry=retry_if_exception(_should_retry_nvd_exception),
    stop=stop_after_attempt(3),
    wait=wait_exponential(multiplier=0.1, min=0.1, max=1.0),
    reraise=True,
)
def _fetch_nvd_page_with_retry(
    client: httpx.Client,
    req_url: str,
    headers: dict[str, str],
    rate_limiter: TokenBucket,
    api_key: str | None,
) -> dict:
    """Fetch a single page from NVD API with TokenBucket rate limiting and Tenacity retry.

    Acquires a token from the rate limiter before every attempt (including retries).
    """
    rate_limiter.acquire(api_key)
    resp = client.get(req_url, headers=headers)
    resp.raise_for_status()
    return resp.json()


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
            with suppress(Exception):
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
    iso_now = datetime.now(UTC).isoformat()
    data[key] = {
        **existing_entry,
        **entry,
        "fetched_at": iso_now,
        "timestamp": iso_now,
    }
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

            # Content-Length describes the *encoded* transfer. httpx decodes gzip and br
            # transparently, so on a compressed response the bytes we write are the decoded
            # ones and the two are not comparable — MITRE serves the ATT&CK bundle as 6 MB
            # gzipped and 54 MB decoded, and comparing them rejected every real snapshot.
            # A truncated compressed download is caught later instead: the sha256 will not
            # reproduce, and the parser fails on incomplete JSON.
            encoding = response.headers.get("content-encoding", "").strip().lower()
            if encoding and encoding != "identity":
                expected_bytes = None
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


def collect_scoped_cve_ids(
    mappings_path: Path | None = None,
    kev_url: str = CISA_KEV_URL,
    client: httpx.Client | None = None,
    kev_data: dict | None = None,
) -> tuple[list[str], list[str]]:
    """Extract and deduplicate valid CVE IDs from mappings CSV and CISA KEV catalog.

    Args:
        mappings_path: Path to local Att&ckToCveMappings.csv file.
        kev_url: Remote URL for CISA KEV JSON catalog feed.
        client: Optional httpx.Client for fetching KEV feed.
        kev_data: Optional pre-parsed KEV catalog dictionary (for testing).

    Returns:
        (valid_cve_ids, invalid_raw_cve_ids) where valid_cve_ids is a sorted, unique
        list of upper-case CVE IDs (e.g. ['CVE-2021-44228']).

    Raises:
        FileNotFoundError: If mappings_path is specified but does not exist.
    """
    valid_cves: set[str] = set()
    invalid_cves: set[str] = set()

    if mappings_path is not None:
        if not mappings_path.exists():
            raise FileNotFoundError(f"Mappings file not found at {mappings_path}")
        # The same reader the parser uses, so this file's byte-order mark and column checks
        # are handled in one place. Reading it separately as plain utf-8 collected no CVEs at
        # all, leaving the NVD pull covering the KEV catalog only.
        for row in read_mappings_rows(mappings_path, required=("CVE ID",)):
            raw_id = (row.get("CVE ID") or "").strip().upper()
            if not raw_id:
                continue
            if CVE_ID_PATTERN.match(raw_id):
                valid_cves.add(raw_id)
            else:
                invalid_cves.add(raw_id)

    if kev_data is None:
        close_client = False
        if client is None:
            client = httpx.Client(timeout=HTTP_TIMEOUT, follow_redirects=True)
            close_client = True
        try:
            resp = client.get(kev_url)
            resp.raise_for_status()
            kev_data = resp.json()
        finally:
            if close_client and client is not None:
                client.close()

    if kev_data and isinstance(kev_data, dict):
        vulnerabilities = kev_data.get("vulnerabilities", [])
        for item in vulnerabilities:
            raw_id = (item.get("cveID") or "").strip().upper()
            if not raw_id:
                continue
            if CVE_ID_PATTERN.match(raw_id):
                valid_cves.add(raw_id)
            else:
                invalid_cves.add(raw_id)

    return sorted(list(valid_cves)), sorted(list(invalid_cves))


def _get_kev_catalog(client: httpx.Client, kev_url: str) -> dict:
    """Download the CISA KEV catalog. Returns the parsed JSON object."""
    resp = client.get(kev_url)
    resp.raise_for_status()
    return resp.json()


def _write_kev_catalog(
    kev_data: dict | None,
    dest: Path,
    kev_url: str,
    manifest_path: Path | None,
) -> None:
    """Persist the KEV catalog next to the NVD snapshot and pin it in the manifest.

    Overwrites unconditionally, unlike the other fetchers. The catalog is a derived
    copy of what this run actually used, not a snapshot a user chose to keep, so
    refusing to overwrite it would leave the NVD pull and the KEV flags describing
    two different days.

    A missing or malformed catalog is not fatal: the CVE pull still succeeds, and
    ingestion reports that nothing was KEV-flagged rather than inventing flags.
    """
    if not kev_data:
        logger.warning("no KEV catalog to write to %s; CVEs will not be KEV-flagged", dest)
        return

    dest.parent.mkdir(parents=True, exist_ok=True)
    with _atomic_write_path(dest) as tmp_p:
        tmp_p.write_text(json.dumps(kev_data, indent=2) + "\n", encoding="utf-8")

    if manifest_path:
        update_manifest(
            manifest_path,
            dest.name,
            {
                "url": kev_url,
                "sha256": sha256_file(dest),
                "bytes": dest.stat().st_size,
                "cve_count": len(kev_data.get("vulnerabilities", [])),
            },
        )


def fetch_scoped_nvd(
    dest: Path,
    mappings_path: Path,
    force: bool = False,
    manifest_path: Path | None = None,
    api_key: str | None = None,
    kev_url: str = CISA_KEV_URL,
    client: httpx.Client | None = None,
    rate_limiter: TokenBucket | None = None,
    progress_callback: Callable[[int, int], None] | None = None,
    kev_data: dict | None = None,
) -> dict:
    """Perform a scoped download of NVD CVE records for mapped and KEV CVEs.

    Collects target CVE IDs from the mappings snapshot and CISA KEV catalog, queries
    the NVD 2.0 API rate-limited per API key via TokenBucket, and atomically writes the
    resulting snapshot to dest. Updates manifest metadata if manifest_path is provided.

    Args:
        dest: Destination path for nvd-scoped.json.
        mappings_path: Path to local Att&ckToCveMappings.csv file.
        force: Overwrite dest if it already exists.
        manifest_path: Path to data/manifest.json.
        api_key: Optional NVD API key string.
        kev_url: CISA KEV JSON catalog endpoint.
        client: Optional httpx.Client for network requests.
        rate_limiter: Optional TokenBucket instance for rate limiting.
        progress_callback: Callback(processed_count, total_count) for progress reporting.
        kev_data: Optional pre-parsed KEV dictionary for unit tests.

    Returns:
        Dict with url, sha256, bytes, requested_cve_count, fetched_cve_count, missing_cve_count.

    Raises:
        FileExistsError: If dest exists and force is False.
        FileNotFoundError: If mappings_path does not exist.
        httpx.HTTPStatusError: On non-retryable NVD API HTTP errors.
    """
    if dest.exists() and not force:
        raise FileExistsError(f"{dest} already exists; pass --force to re-download")

    close_client = False
    if client is None:
        client = httpx.Client(timeout=HTTP_TIMEOUT, follow_redirects=True)
        close_client = True

    try:
        # Resolved here rather than inside collect_scoped_cve_ids so the catalog can be
        # written to disk on the way past. Passing it down means the collector skips its
        # own fetch, so this costs no extra request.
        if kev_data is None:
            kev_data = _get_kev_catalog(client, kev_url)
        _write_kev_catalog(kev_data, dest.parent / KEV_FILENAME, kev_url, manifest_path)

        cve_ids, _invalid_ids = collect_scoped_cve_ids(
            mappings_path=mappings_path,
            kev_url=kev_url,
            client=client,
            kev_data=kev_data,
        )

        if rate_limiter is None:
            rate_limiter = TokenBucket(api_key=api_key)

        headers: dict[str, str] = {}
        if api_key and isinstance(api_key, str) and api_key.strip():
            headers["apiKey"] = api_key.strip()

        fetched_vulnerabilities: list[dict] = []
        missing_cve_ids: list[str] = []
        total_cves = len(cve_ids)

        for idx, cve_id in enumerate(cve_ids, start=1):
            url = f"{NVD_ENDPOINT}?cveId={cve_id}"

            data = _fetch_nvd_page_with_retry(
                client=client,
                req_url=url,
                headers=headers,
                rate_limiter=rate_limiter,
                api_key=api_key,
            )
            vuln_items = data.get("vulnerabilities", [])

            page_count = 1
            total_results = data.get("totalResults", len(vuln_items))
            while len(vuln_items) < total_results and page_count < _MAX_PAGES_PER_CVE:
                paged_url = f"{NVD_ENDPOINT}?cveId={cve_id}&startIndex={len(vuln_items)}"
                paged_data = _fetch_nvd_page_with_retry(
                    client=client,
                    req_url=paged_url,
                    headers=headers,
                    rate_limiter=rate_limiter,
                    api_key=api_key,
                )
                new_items = paged_data.get("vulnerabilities", [])
                if not new_items:
                    break
                prev_len = len(vuln_items)
                vuln_items.extend(new_items)
                page_count += 1
                if len(vuln_items) <= prev_len:
                    break

            if not vuln_items:
                missing_cve_ids.append(cve_id)
            else:
                fetched_vulnerabilities.extend(vuln_items)

            if progress_callback:
                progress_callback(idx, total_cves)

        snapshot_content = {
            "format": "NVD_CVE",
            "version": "2.0",
            "vulnerabilities": fetched_vulnerabilities,
        }

        with _atomic_write_path(dest) as tmp_p:
            tmp_p.write_text(json.dumps(snapshot_content, indent=2) + "\n", encoding="utf-8")

        res_entry = {
            "url": NVD_ENDPOINT,
            "sha256": sha256_file(dest),
            "bytes": dest.stat().st_size,
            "requested_cve_count": total_cves,
            "fetched_cve_count": len(fetched_vulnerabilities),
            "missing_cve_count": len(missing_cve_ids),
        }

        if manifest_path:
            update_manifest(manifest_path, dest.name, res_entry)

        return res_entry

    finally:
        if close_client and client is not None:
            client.close()
