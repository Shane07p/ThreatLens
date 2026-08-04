"""Download snapshots and record their provenance.

Query-time code must never call these. Snapshots are fetched once and pinned to ensure
reproducible results across evaluations.
"""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path

import httpx

ATTACK_URL = (
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/"
    "master/enterprise-attack/enterprise-attack.json"
)


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
    and an ISO timestamp, and persists the JSON back to disk.

    Returns the updated manifest dictionary.
    """
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    data: dict = {}
    if manifest_path.exists():
        data = json.loads(manifest_path.read_text(encoding="utf-8"))
    data[key] = {**entry, "fetched_at": datetime.now(UTC).isoformat()}
    manifest_path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return data


def fetch_url(url: str, dest: Path, force: bool = False) -> dict:
    """Download a file from a URL to the specified destination path.

    Refuses to overwrite an existing file unless force is True to prevent accidental
    data shifts during experiments.

    Raises FileExistsError if the destination file exists and force is False.
    Raises httpx.HTTPStatusError if HTTP request fails.
    Returns a dictionary containing url, sha256 checksum, and file size in bytes.
    """
    if dest.exists() and not force:
        raise FileExistsError(f"{dest} already exists; pass --force to re-download")
    dest.parent.mkdir(parents=True, exist_ok=True)
    with httpx.stream("GET", url, follow_redirects=True, timeout=120.0) as response:
        response.raise_for_status()
        with open(dest, "wb") as fh:
            for chunk in response.iter_bytes():
                fh.write(chunk)
    return {"url": url, "sha256": sha256_file(dest), "bytes": dest.stat().st_size}
