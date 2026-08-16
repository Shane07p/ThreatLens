import json
import sys
import types
from unittest.mock import MagicMock, patch

import pytest
from typer.testing import CliRunner

from threatlens.cli import app
from threatlens.models import Edge, Node

runner = CliRunner()


@pytest.fixture(autouse=True)
def _cli_needs_settings(configured_env: str) -> None:
    """Every CLI command loads Settings, so this module opts in to a DATABASE_URL.

    Scoped to this file rather than the whole suite: config's rejection of a missing
    DATABASE_URL has to stay observable somewhere.
    """


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


def test_version_command_plain():
    result = runner.invoke(app, ["version"])
    assert result.exit_code == 0
    assert "threatlens v0.1.0" in result.output


def test_version_command_json():
    result = runner.invoke(app, ["version", "--json"])
    assert result.exit_code == 0
    parsed = json.loads(result.output)
    assert parsed["version"] == "0.1.0"


def test_config_command_plain():
    result = runner.invoke(app, ["config"])
    assert result.exit_code == 0
    assert "ThreatLens Settings" in result.output
    assert "database_url" in result.output


def test_config_command_json():
    result = runner.invoke(app, ["config", "-j"])
    assert result.exit_code == 0
    parsed = json.loads(result.output)
    assert "database_url" in parsed
    assert "provider" in parsed


@patch("subprocess.run")
@patch("threatlens.graph.store.get_engine")
def test_doctor_command_success(mock_get_engine, mock_subprocess_run, tmp_path, monkeypatch):
    monkeypatch.setattr(
        "threatlens.cli._get_data_paths",
        lambda: (tmp_path / "raw", tmp_path / "manifest.json"),
    )
    mock_subprocess_run.return_value = MagicMock(return_code=0, returncode=0)

    mock_conn = MagicMock()
    mock_engine = MagicMock()
    mock_engine.connect.return_value.__enter__.return_value = mock_conn
    mock_get_engine.return_value = mock_engine

    result = runner.invoke(app, ["doctor"])
    assert result.exit_code == 0
    assert "ThreatLens Health Doctor" in result.output
    assert "Database Connection" in result.output


@patch("subprocess.run")
@patch("threatlens.graph.store.get_engine")
def test_doctor_command_json(mock_get_engine, mock_subprocess_run, tmp_path, monkeypatch):
    monkeypatch.setattr(
        "threatlens.cli._get_data_paths",
        lambda: (tmp_path / "raw", tmp_path / "manifest.json"),
    )
    mock_subprocess_run.return_value = MagicMock(returncode=0)

    mock_conn = MagicMock()
    mock_engine = MagicMock()
    mock_engine.connect.return_value.__enter__.return_value = mock_conn
    mock_get_engine.return_value = mock_engine

    result = runner.invoke(app, ["doctor", "--json"])
    assert result.exit_code == 0
    parsed = json.loads(result.output)
    assert parsed["status"] == "ok"
    assert len(parsed["checks"]) == 3


@patch("subprocess.run")
@patch("threatlens.graph.store.get_engine")
def test_doctor_command_failure(mock_get_engine, mock_subprocess_run, tmp_path, monkeypatch):
    monkeypatch.setattr(
        "threatlens.cli._get_data_paths",
        lambda: (tmp_path / "raw", tmp_path / "manifest.json"),
    )
    mock_get_engine.side_effect = RuntimeError("DB down")
    mock_subprocess_run.side_effect = RuntimeError("No docker")

    result = runner.invoke(app, ["doctor"])
    assert result.exit_code == 1
    assert "Remedy Suggestions" in result.output


def test_fetch_list_command_plain():
    result = runner.invoke(app, ["fetch", "list"])
    assert result.exit_code == 0
    assert "Available Data Sources" in result.output
    assert "attack" in result.output


def test_fetch_list_command_json():
    result = runner.invoke(app, ["fetch", "list", "--json"])
    assert result.exit_code == 0
    parsed = json.loads(result.output)
    assert isinstance(parsed, list)
    assert any(s["name"] == "attack" for s in parsed)


def test_fetch_option_list():
    result = runner.invoke(app, ["fetch", "--list"])
    assert result.exit_code == 0
    assert "Available Data Sources" in result.output


@patch("threatlens.graph.store.init_schema")
@patch("threatlens.graph.store.get_engine")
def test_db_init_command_success(mock_get_engine, mock_init_schema):
    result = runner.invoke(app, ["db", "init"])
    assert result.exit_code == 0
    assert "Schema applied successfully" in result.output
    mock_get_engine.assert_called_once()
    mock_init_schema.assert_called_once()


@patch("threatlens.graph.store.init_schema")
@patch("threatlens.graph.store.get_engine")
def test_db_init_command_failure(mock_get_engine, mock_init_schema):
    mock_init_schema.side_effect = RuntimeError("Database connection failed")
    result = runner.invoke(app, ["db", "init"])
    assert result.exit_code != 0
    assert "schema init failed" in result.output.lower() or "did you mean" in result.output.lower()


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
def test_fetch_attack_command_not_modified(mock_fetch_url, mock_update_manifest):
    mock_fetch_url.return_value = {
        "url": "https://example.com/attack.json",
        "sha256": "1234567890abcdef1234567890abcdef",
        "bytes": 1024,
        "not_modified": True,
    }
    result = runner.invoke(app, ["fetch", "attack"])
    assert result.exit_code == 0
    assert "Unchanged" in result.output
    mock_update_manifest.assert_not_called()


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
    assert "Download failed" in result.output or "file exists" in result.output


@patch("threatlens.ingest.fetch.update_manifest")
@patch("threatlens.ingest.fetch.fetch_url")
def test_fetch_mappings_command_success(mock_fetch_url, mock_update_manifest):
    mock_fetch_url.return_value = {
        "url": "https://raw.githubusercontent.com/center-for-threat-informed-defense/attack_to_cve/master/Att%26ckToCveMappings.csv",
        "sha256": "abcdef1234567890abcdef1234567890",
        "bytes": 2048,
    }
    result = runner.invoke(app, ["fetch", "mappings"])
    assert result.exit_code == 0
    assert "sha256=abcdef123456..." in result.output
    assert "2048 bytes" in result.output
    mock_fetch_url.assert_called_once()
    mock_update_manifest.assert_called_once()
    dest_arg = mock_fetch_url.call_args[0][1]
    assert dest_arg.name == "Att&ckToCveMappings.csv"


@patch("threatlens.ingest.fetch.update_manifest")
@patch("threatlens.ingest.fetch.fetch_url")
def test_fetch_mappings_command_not_modified(mock_fetch_url, mock_update_manifest):
    mock_fetch_url.return_value = {
        "url": "https://raw.githubusercontent.com/center-for-threat-informed-defense/attack_to_cve/master/Att%26ckToCveMappings.csv",
        "sha256": "abcdef1234567890abcdef1234567890",
        "bytes": 2048,
        "not_modified": True,
    }
    result = runner.invoke(app, ["fetch", "mappings"])
    assert result.exit_code == 0
    assert "Unchanged" in result.output
    mock_update_manifest.assert_not_called()


@patch("threatlens.ingest.fetch.update_manifest")
@patch("threatlens.ingest.fetch.fetch_url")
def test_fetch_mappings_command_with_force_flag(mock_fetch_url, mock_update_manifest):
    mock_fetch_url.return_value = {
        "url": "https://raw.githubusercontent.com/center-for-threat-informed-defense/attack_to_cve/master/Att%26ckToCveMappings.csv",
        "sha256": "abcdef1234567890abcdef1234567890",
        "bytes": 2048,
    }
    result = runner.invoke(app, ["fetch", "mappings", "--force"])
    assert result.exit_code == 0
    mock_fetch_url.assert_called_once()
    assert mock_fetch_url.call_args.kwargs.get("force") is True


@patch("threatlens.ingest.fetch.fetch_url")
def test_fetch_mappings_command_file_exists_error(mock_fetch_url):
    mock_fetch_url.side_effect = FileExistsError("file exists; pass --force")
    result = runner.invoke(app, ["fetch", "mappings"])
    assert result.exit_code == 1
    assert "Download failed" in result.output or "file exists" in result.output


@patch("threatlens.ingest.fetch.fetch_url")
def test_fetch_mappings_command_generic_error(mock_fetch_url):
    mock_fetch_url.side_effect = RuntimeError("Network error")
    result = runner.invoke(app, ["fetch", "mappings"])
    assert result.exit_code == 1
    assert "Download failed" in result.output


def test_ingest_attack_command_missing_snapshot(tmp_path, monkeypatch):
    monkeypatch.setattr(
        "threatlens.cli._get_data_paths",
        lambda: (tmp_path / "missing", tmp_path / "manifest.json"),
    )
    result = runner.invoke(app, ["ingest", "attack"])
    assert result.exit_code == 1
    assert "Snapshot missing" in result.output


def test_ingest_attack_command_parser_unavailable(tmp_path, monkeypatch):
    raw_dir = tmp_path / "data" / "raw"
    manifest = tmp_path / "data" / "manifest.json"
    dest = raw_dir / "enterprise-attack.json"
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text("{}")
    monkeypatch.setattr("threatlens.cli._get_data_paths", lambda: (raw_dir, manifest))
    monkeypatch.setitem(sys.modules, "threatlens.ingest.attack", None)

    result = runner.invoke(app, ["ingest", "attack"])
    assert result.exit_code == 1
    assert "parser unavailable" in result.output


def test_ingest_attack_command_success(tmp_path, monkeypatch):
    raw_dir = tmp_path / "data" / "raw"
    dest = raw_dir / "enterprise-attack.json"
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text("{}")
    manifest = tmp_path / "data" / "manifest.json"
    manifest.write_text('{"enterprise-attack.json": {"sha256": "abc123456"}}')

    monkeypatch.setattr("threatlens.cli._get_data_paths", lambda: (raw_dir, manifest))

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
    assert "Inserted 650 nodes, 1200 edges" in result.output


def test_ingest_attack_command_corrupted_manifest(tmp_path, monkeypatch):
    raw_dir = tmp_path / "data" / "raw"
    dest = raw_dir / "enterprise-attack.json"
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text("{}")
    manifest = tmp_path / "data" / "manifest.json"
    manifest.write_text("{corrupted json")

    monkeypatch.setattr("threatlens.cli._get_data_paths", lambda: (raw_dir, manifest))

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
    assert "Inserted 10 nodes, 5 edges" in result.output
    mock_ingest_attack.assert_called_once_with(dest, "", mock_conn)


@patch("threatlens.graph.store.edge_counts")
@patch("threatlens.graph.store.node_counts")
@patch("threatlens.graph.store.get_engine")
def test_stats_command_plain(mock_get_engine, mock_node_counts, mock_edge_counts):
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


@patch("threatlens.graph.store.edge_counts")
@patch("threatlens.graph.store.node_counts")
@patch("threatlens.graph.store.get_engine")
def test_stats_command_json(mock_get_engine, mock_node_counts, mock_edge_counts):
    mock_node_counts.return_value = {"technique": 650}
    mock_edge_counts.return_value = {"BELONGS_TO": 650}

    mock_conn = MagicMock()
    mock_engine = MagicMock()
    mock_engine.connect.return_value.__enter__.return_value = mock_conn
    mock_get_engine.return_value = mock_engine

    result = runner.invoke(app, ["stats", "--json"])
    assert result.exit_code == 0
    parsed = json.loads(result.output)
    assert parsed["nodes"]["technique"] == 650


@patch("threatlens.graph.store.get_node")
@patch("threatlens.graph.store.neighbors")
@patch("threatlens.graph.store.get_engine")
def test_show_command_existing_node_plain(mock_get_engine, mock_neighbors, mock_get_node):
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
    assert "T1190" in result.output
    assert "Exploit Public-Facing Application" in result.output


@patch("threatlens.graph.store.get_node")
@patch("threatlens.graph.store.neighbors")
@patch("threatlens.graph.store.get_engine")
def test_show_command_existing_node_json(mock_get_engine, mock_neighbors, mock_get_node):
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

    result = runner.invoke(app, ["show", "T1190", "--json"])
    assert result.exit_code == 0
    parsed = json.loads(result.output)
    assert parsed["id"] == "technique:T1190"


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
    assert "Not found: technique:T9999" in result.output


def test_verbose_flag():
    result = runner.invoke(app, ["--verbose", "db", "--help"])
    assert result.exit_code == 0


def test_ingest_attack_command_database_error(tmp_path, monkeypatch):
    raw_dir = tmp_path / "data" / "raw"
    dest = raw_dir / "enterprise-attack.json"
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text("{}")

    monkeypatch.setattr(
        "threatlens.cli._get_data_paths",
        lambda: (raw_dir, tmp_path / "manifest.json"),
    )

    mock_ingest_attack = MagicMock(side_effect=RuntimeError("DB write failure"))
    fake_module = types.ModuleType("threatlens.ingest.attack")
    fake_module.ingest_attack = mock_ingest_attack
    monkeypatch.setitem(sys.modules, "threatlens.ingest.attack", fake_module)

    mock_conn = MagicMock()
    mock_engine = MagicMock()
    mock_engine.begin.return_value.__enter__.return_value = mock_conn
    monkeypatch.setattr("threatlens.graph.store.get_engine", lambda: mock_engine)

    result = runner.invoke(app, ["ingest", "attack"])
    assert result.exit_code == 1
    assert "Ingestion failed" in result.output or "threatlens db init" in result.output


@patch("threatlens.graph.store.get_engine")
def test_show_command_database_error(mock_get_engine):
    mock_get_engine.side_effect = RuntimeError("DB connection error")

    result = runner.invoke(app, ["show", "T1190"])
    assert result.exit_code == 1
    assert "Database error" in result.output or "threatlens db init" in result.output
