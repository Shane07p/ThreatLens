"""Download snapshots and record their provenance.

Query-time code must never call these. Snapshots are fetched once and pinned to ensure
reproducible results across evaluations.
"""

from __future__ import annotations

import hashlib
import json
import tempfile
from collections.abc import Generator
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path

import httpx

ATTACK_URL = (
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/"
    "master/enterprise-attack/enterprise-attack.json"
)


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
    data[key] = {**entry, "fetched_at": datetime.now(UTC).isoformat()}
    content = json.dumps(data, indent=2, sort_keys=True) + "\n"
    with _atomic_write_path(manifest_path) as tmp_path:
        tmp_path.write_text(content, encoding="utf-8")
    return data


def fetch_url(url: str, dest: Path, force: bool = False) -> dict:
    """Download a file from a URL to the specified destination path atomically.

    Refuses to overwrite an existing file unless force is True to prevent accidental
    data shifts during experiments. Downloads chunks to a temporary file and atomically
    replaces the destination on success. If an error occurs during download, the destination
    file is preserved untouched and temporary files are cleaned up.

    Raises FileExistsError if the destination file exists and force is False.
    Raises httpx.HTTPStatusError if HTTP request fails.
    Returns a dictionary containing url, sha256 checksum, and file size in bytes.
    """
    if dest.exists() and not force:
        raise FileExistsError(f"{dest} already exists; pass --force to re-download")
    with (
        _atomic_write_path(dest) as tmp_path,
        httpx.stream("GET", url, follow_redirects=True, timeout=120.0) as response,
    ):
        response.raise_for_status()
        with open(tmp_path, "wb") as fh:
            for chunk in response.iter_bytes():
                fh.write(chunk)
    return {"url": url, "sha256": sha256_file(dest), "bytes": dest.stat().st_size}
