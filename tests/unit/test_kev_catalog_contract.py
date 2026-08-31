"""The seam between fetching the KEV catalog and reading it back at ingest time.

`fetch nvd` needs the KEV catalog to decide which CVEs to pull. `ingest cves` needs the
same catalog to stamp `attrs.kev`. Those are two different modules written by two different
people, and each side had passing tests while the pipeline as a whole flagged nothing:
the fetcher pulled the catalog into memory and dropped it, and the ingester looked for a
file that was never written.

Every test on either side passed because they all handed the catalog in directly. These
tests exercise the handoff instead.
"""

from __future__ import annotations

import json
from pathlib import Path

import httpx
import pytest

from threatlens.ingest.fetch import KEV_FILENAME, fetch_scoped_nvd
from threatlens.ingest.nvd import load_kev_ids

MAPPINGS_CSV = "CVE ID,Technique ID,Mapping Type\nCVE-2021-44228,T1190,primary\n"

KEV_CATALOG = {
    "title": "CISA Catalog of Known Exploited Vulnerabilities",
    "vulnerabilities": [{"cveID": "CVE-2021-44228"}, {"cveID": "CVE-2014-0160"}],
}

NVD_PAGE = {
    "vulnerabilities": [
        {
            "cve": {
                "id": "CVE-2021-44228",
                "descriptions": [{"lang": "en", "value": "Log4Shell."}],
                "metrics": {},
                "references": [],
            }
        }
    ]
}


def _stub_client() -> httpx.Client:
    """An NVD that always answers, so the test never touches the network."""
    return httpx.Client(transport=httpx.MockTransport(lambda _: httpx.Response(200, json=NVD_PAGE)))


@pytest.fixture
def raw_dir(tmp_path: Path) -> Path:
    d = tmp_path / "raw"
    d.mkdir()
    (d / "Att&ckToCveMappings.csv").write_text(MAPPINGS_CSV, encoding="utf-8")
    return d


def _fetch(raw_dir: Path, kev_data: dict | None = KEV_CATALOG) -> dict:
    return fetch_scoped_nvd(
        dest=raw_dir / "nvd-scoped.json",
        mappings_path=raw_dir / "Att&ckToCveMappings.csv",
        manifest_path=raw_dir.parent / "manifest.json",
        client=_stub_client(),
        kev_data=kev_data,
    )


def test_fetch_writes_the_catalog_where_ingest_reads_it(raw_dir: Path):
    """The whole point of this file. One side's output path is the other side's input."""
    _fetch(raw_dir)
    assert load_kev_ids(raw_dir / KEV_FILENAME) == {"CVE-2021-44228", "CVE-2014-0160"}


def test_catalog_is_pinned_in_the_manifest(raw_dir: Path):
    """A snapshot the graph depends on but nobody can identify later is unreproducible."""
    _fetch(raw_dir)
    manifest = json.loads((raw_dir.parent / "manifest.json").read_text(encoding="utf-8"))
    entry = manifest[KEV_FILENAME]
    assert entry["sha256"] and entry["url"]
    assert entry["cve_count"] == 2


def test_a_second_fetch_overwrites_the_catalog(raw_dir: Path):
    """Deliberate non-behavior: this file does NOT honour the no-clobber rule the other
    snapshots follow. It is a record of what this run used, so leaving a stale copy would
    describe the CVE pull and the KEV flags as of two different days."""
    _fetch(raw_dir)
    (raw_dir / "nvd-scoped.json").unlink()

    fetch_scoped_nvd(
        dest=raw_dir / "nvd-scoped.json",
        mappings_path=raw_dir / "Att&ckToCveMappings.csv",
        manifest_path=raw_dir.parent / "manifest.json",
        client=_stub_client(),
        kev_data={"vulnerabilities": [{"cveID": "CVE-2099-0001"}]},
    )
    assert load_kev_ids(raw_dir / KEV_FILENAME) == {"CVE-2099-0001"}


def test_an_empty_catalog_does_not_abort_the_cve_pull(raw_dir: Path):
    """Losing the triage signal is bad. Losing the CVEs as well is worse."""
    res = _fetch(raw_dir, kev_data={"vulnerabilities": []})
    assert res["fetched_cve_count"] >= 1
    assert load_kev_ids(raw_dir / KEV_FILENAME) == set()


def test_ingest_finds_the_catalog_without_being_told_where_it_is(raw_dir: Path, monkeypatch):
    """`ingest cves` auto-detects the catalog. This asserts the auto-detection actually
    fires after a real fetch — the case every existing KEV test skipped by injecting the
    ids directly."""
    from typer.testing import CliRunner

    from threatlens.cli import app

    _fetch(raw_dir)
    monkeypatch.setattr(
        "threatlens.cli._get_data_paths", lambda: (raw_dir, raw_dir.parent / "manifest.json")
    )
    monkeypatch.setenv("DATABASE_URL", "postgresql+psycopg://unused:unused@127.0.0.1:1/unused")

    out = CliRunner().invoke(app, ["ingest", "cves"]).stdout
    assert "No KEV catalog found" not in out, out
    assert "Loaded 2 KEV CVE IDs" in out, out
