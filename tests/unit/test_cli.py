import sys
import types
from unittest.mock import MagicMock, patch

import pytest
from typer.testing import CliRunner

from threatlens.cli import app
from threatlens.models import Edge, Node

runner = CliRunner()


def test_root_help():
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    assert "threatlens" in result.output.lower()


def test_db_help():
    result = runner.invoke(app, ["db", "--help"])
    assert result.exit_code == 0
    assert "init" in result.output


def test_fetch_help():
    result = runner.invoke(app, ["fetch", "--help"])
    assert result.exit_code == 0
    assert "attack" in result.output


def test_ingest_help():
    result = runner.invoke(app, ["ingest", "--help"])
    assert result.exit_code == 0
    assert "attack" in result.output


def test_stats_help():
    result = runner.invoke(app, ["stats", "--help"])
    assert result.exit_code == 0
    assert "stats" in result.output.lower() or "node" in result.output.lower()


def test_show_help():
    result = runner.invoke(app, ["show", "--help"])
    assert result.exit_code == 0
    assert "show" in result.output.lower() or "node" in result.output.lower()


@patch("threatlens.graph.store.init_schema")
@patch("threatlens.graph.store.get_engine")
def test_db_init_command_success(mock_get_engine, mock_init_schema):
    result = runner.invoke(app, ["db", "init"])
    assert result.exit_code == 0
    assert "schema applied" in result.output
    mock_get_engine.assert_called_once()
    mock_init_schema.assert_called_once()


@patch("threatlens.graph.store.init_schema")
@patch("threatlens.graph.store.get_engine")
def test_db_init_command_failure(mock_get_engine, mock_init_schema):
    mock_init_schema.side_effect = RuntimeError("Database connection failed")
    result = runner.invoke(app, ["db", "init"])
    assert result.exit_code != 0
    assert isinstance(result.exception, RuntimeError)


@patch("threatlens.ingest.fetch.update_manifest")
@patch("threatlens.ingest.fetch.fetch_url")
def test_fetch_attack_command_success(mock_fetch_url, mock_update_manifest):
    mock_fetch_url.return_value = {
        "url": "https://example.com/attack.json",
        "sha256": "1234567890abcdef1234567890abcdef",
        "bytes": 1024,
    }
    result = runner.invoke(app, ["fetch", "attack"])
    assert result.exit_code == 0
    assert "sha256=1234567890ab..." in result.output
    assert "1024 bytes" in result.output
    mock_fetch_url.assert_called_once()
    mock_update_manifest.assert_called_once()


@patch("threatlens.ingest.fetch.update_manifest")
@patch("threatlens.ingest.fetch.fetch_url")
def test_fetch_attack_command_with_force_flag(mock_fetch_url, mock_update_manifest):
    mock_fetch_url.return_value = {
        "url": "https://example.com/attack.json",
        "sha256": "1234567890abcdef1234567890abcdef",
        "bytes": 1024,
    }
    result = runner.invoke(app, ["fetch", "attack", "--force"])
    assert result.exit_code == 0
    mock_fetch_url.assert_called_once()
    assert mock_fetch_url.call_args.kwargs.get("force") is True


@patch("threatlens.ingest.fetch.fetch_url")
def test_fetch_attack_command_file_exists_error(mock_fetch_url):
    mock_fetch_url.side_effect = FileExistsError("file exists; pass --force")
    result = runner.invoke(app, ["fetch", "attack"])
    assert result.exit_code == 1
    assert "file exists; pass --force" in result.output


def test_ingest_attack_command_missing_snapshot(tmp_path, monkeypatch):
    monkeypatch.setattr("threatlens.cli.DATA_RAW", tmp_path / "missing")
    result = runner.invoke(app, ["ingest", "attack"])
    assert result.exit_code == 1
    assert "snapshot missing" in result.output


def test_ingest_attack_command_parser_unavailable(tmp_path, monkeypatch):
    dest = tmp_path / "data" / "raw" / "enterprise-attack.json"
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text("{}")
    monkeypatch.setattr("threatlens.cli.DATA_RAW", tmp_path / "data" / "raw")
    monkeypatch.setitem(sys.modules, "threatlens.ingest.attack", None)

    result = runner.invoke(app, ["ingest", "attack"])
    assert result.exit_code == 1
    assert "ingest attack parser unavailable" in result.output


def test_ingest_attack_command_success(tmp_path, monkeypatch):
    dest = tmp_path / "data" / "raw" / "enterprise-attack.json"
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text("{}")
    manifest = tmp_path / "data" / "manifest.json"
    manifest.write_text('{"enterprise-attack.json": {"sha256": "abc123456"}}')

    monkeypatch.setattr("threatlens.cli.DATA_RAW", tmp_path / "data" / "raw")
    monkeypatch.setattr("threatlens.cli.MANIFEST", manifest)

    mock_ingest_attack = MagicMock(return_value=(650, 1200))
    fake_module = types.ModuleType("threatlens.ingest.attack")
    fake_module.ingest_attack = mock_ingest_attack
    monkeypatch.setitem(sys.modules, "threatlens.ingest.attack", fake_module)

    mock_conn = MagicMock()
    mock_engine = MagicMock()
    mock_engine.begin.return_value.__enter__.return_value = mock_conn
    monkeypatch.setattr("threatlens.graph.store.get_engine", lambda: mock_engine)

    result = runner.invoke(app, ["ingest", "attack"])
    assert result.exit_code == 0
    assert "ingested 650 nodes, 1200 edges" in result.output


def test_ingest_attack_command_corrupted_manifest(tmp_path, monkeypatch):
    dest = tmp_path / "data" / "raw" / "enterprise-attack.json"
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text("{}")
    manifest = tmp_path / "data" / "manifest.json"
    manifest.write_text("{corrupted json")

    monkeypatch.setattr("threatlens.cli.DATA_RAW", tmp_path / "data" / "raw")
    monkeypatch.setattr("threatlens.cli.MANIFEST", manifest)

    mock_ingest_attack = MagicMock(return_value=(10, 5))
    fake_module = types.ModuleType("threatlens.ingest.attack")
    fake_module.ingest_attack = mock_ingest_attack
    monkeypatch.setitem(sys.modules, "threatlens.ingest.attack", fake_module)

    mock_conn = MagicMock()
    mock_engine = MagicMock()
    mock_engine.begin.return_value.__enter__.return_value = mock_conn
    monkeypatch.setattr("threatlens.graph.store.get_engine", lambda: mock_engine)

    result = runner.invoke(app, ["ingest", "attack"])
    assert result.exit_code == 0
    assert "ingested 10 nodes, 5 edges" in result.output
    mock_ingest_attack.assert_called_once_with(dest, "", mock_conn)


@patch("threatlens.graph.store.edge_counts")
@patch("threatlens.graph.store.node_counts")
@patch("threatlens.graph.store.get_engine")
def test_stats_command(mock_get_engine, mock_node_counts, mock_edge_counts):
    mock_node_counts.return_value = {"technique": 650, "tactic": 14}
    mock_edge_counts.return_value = {"BELONGS_TO": 650, "USES": 300}

    mock_conn = MagicMock()
    mock_engine = MagicMock()
    mock_engine.connect.return_value.__enter__.return_value = mock_conn
    mock_get_engine.return_value = mock_engine

    result = runner.invoke(app, ["stats"])
    assert result.exit_code == 0
    assert "technique" in result.output
    assert "650" in result.output
    assert "tactic" in result.output
    assert "14" in result.output
    assert "BELONGS_TO" in result.output


@patch("threatlens.graph.store.edge_counts")
@patch("threatlens.graph.store.node_counts")
@patch("threatlens.graph.store.get_engine")
def test_stats_command_empty_database(mock_get_engine, mock_node_counts, mock_edge_counts):
    mock_node_counts.return_value = {}
    mock_edge_counts.return_value = {}

    mock_conn = MagicMock()
    mock_engine = MagicMock()
    mock_engine.connect.return_value.__enter__.return_value = mock_conn
    mock_get_engine.return_value = mock_engine

    result = runner.invoke(app, ["stats"])
    assert result.exit_code == 0
    assert "nodes:" in result.output
    assert "edges:" in result.output


@patch("threatlens.graph.store.get_node")
@patch("threatlens.graph.store.neighbors")
@patch("threatlens.graph.store.get_engine")
def test_show_command_existing_node_with_edges(mock_get_engine, mock_neighbors, mock_get_node):
    node = Node(
        id="technique:T1190",
        kind="technique",
        external_id="T1190",
        name="Exploit Public-Facing Application",
        source_url="https://attack.mitre.org/techniques/T1190",
        description="Adversaries may attempt to exploit...",
    )
    tactic_node = Node(
        id="tactic:TA0001",
        kind="tactic",
        external_id="TA0001",
        name="Initial Access",
        source_url="https://attack.mitre.org/tactics/TA0001",
    )
    edge = Edge(src="technique:T1190", dst="tactic:TA0001", kind="BELONGS_TO", source="test")

    mock_get_node.return_value = node
    mock_neighbors.return_value = [(edge, tactic_node)]

    mock_conn = MagicMock()
    mock_engine = MagicMock()
    mock_engine.connect.return_value.__enter__.return_value = mock_conn
    mock_get_engine.return_value = mock_engine

    result = runner.invoke(app, ["show", "T1190"])
    assert result.exit_code == 0
    assert "technique:T1190" in result.output
    assert "Exploit Public-Facing Application" in result.output
    assert "edges:" in result.output
    assert "BELONGS_TO" in result.output
    assert "tactic:TA0001" in result.output


@patch("threatlens.graph.store.get_node")
@patch("threatlens.graph.store.neighbors")
@patch("threatlens.graph.store.get_engine")
def test_show_command_existing_node_no_edges(mock_get_engine, mock_neighbors, mock_get_node):
    node = Node(
        id="technique:T1190",
        kind="technique",
        external_id="T1190",
        name="Exploit Public-Facing Application",
        source_url="https://attack.mitre.org/techniques/T1190",
    )

    mock_get_node.return_value = node
    mock_neighbors.return_value = []

    mock_conn = MagicMock()
    mock_engine = MagicMock()
    mock_engine.connect.return_value.__enter__.return_value = mock_conn
    mock_get_engine.return_value = mock_engine

    result = runner.invoke(app, ["show", "technique:T1190"])
    assert result.exit_code == 0
    assert "technique:T1190" in result.output
    assert "edges:" not in result.output


@pytest.mark.parametrize(
    ("input_id", "expected_resolved"),
    [
        ("TA0001", "tactic:TA0001"),
        ("M1030", "mitigation:M1030"),
        ("G0016", "actor:G0016"),
        ("S0154", "software:S0154"),
        ("CVE-2021-44228", "cve:CVE-2021-44228"),
        ("unknown_id", "technique:unknown_id"),
    ],
)
@patch("threatlens.graph.store.get_node")
@patch("threatlens.graph.store.neighbors")
@patch("threatlens.graph.store.get_engine")
def test_show_command_prefix_resolution(
    mock_get_engine,
    mock_neighbors,
    mock_get_node,
    input_id,
    expected_resolved,
):
    mock_get_node.return_value = Node(
        id=expected_resolved,
        kind=expected_resolved.split(":")[0],
        external_id=input_id,
        name="Test Entity",
        source_url="https://example.com",
    )
    mock_neighbors.return_value = []

    mock_conn = MagicMock()
    mock_engine = MagicMock()
    mock_engine.connect.return_value.__enter__.return_value = mock_conn
    mock_get_engine.return_value = mock_engine

    result = runner.invoke(app, ["show", input_id])
    assert result.exit_code == 0
    mock_get_node.assert_called_once_with(mock_conn, expected_resolved)


@patch("threatlens.graph.store.get_node")
@patch("threatlens.graph.store.get_engine")
def test_show_command_missing_node(mock_get_engine, mock_get_node):
    mock_get_node.return_value = None

    mock_conn = MagicMock()
    mock_engine = MagicMock()
    mock_engine.connect.return_value.__enter__.return_value = mock_conn
    mock_get_engine.return_value = mock_engine

    result = runner.invoke(app, ["show", "T9999"])
    assert result.exit_code == 1
    assert "not found: technique:T9999" in result.output


def test_verbose_flag():
    result = runner.invoke(app, ["--verbose", "db", "--help"])
    assert result.exit_code == 0
