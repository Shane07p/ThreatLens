"""Architectural boundary enforcement — run in CI to catch violations early.

config.py is the *only* module permitted to read os.environ, os.getenv, or
call load_dotenv. Any other module doing so means a second, uncontrolled,
untestable configuration path. These tests use AST inspection so they catch
violations even in code that's never imported during the test run.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

SRC_ROOT = Path(__file__).resolve().parent.parent.parent / "src" / "threatlens"

# The one allowed file
ALLOWED_ENV_MODULE = SRC_ROOT / "config.py"


def _python_files(root: Path) -> list[Path]:
    """All .py files under root, recursively."""
    return sorted(root.rglob("*.py"))


def _find_env_access(filepath: Path) -> list[tuple[int, str]]:
    """Return (line_number, description) for every os.environ / os.getenv / load_dotenv usage."""
    source = filepath.read_text(encoding="utf-8")
    tree = ast.parse(source, filename=str(filepath))
    violations: list[tuple[int, str]] = []

    for node in ast.walk(tree):
        # os.getenv("X") or os.environ (direct attribute access on 'os')
        if (
            isinstance(node, ast.Attribute)
            and isinstance(node.value, ast.Name)
            and node.value.id == "os"
            and node.attr in ("environ", "getenv")
        ):
            violations.append((node.lineno, f"os.{node.attr}"))

        # os.environ.get / os.environ.xxx (chained attribute)
        if (
            isinstance(node, ast.Attribute)
            and isinstance(node.value, ast.Attribute)
            and isinstance(node.value.value, ast.Name)
            and node.value.value.id == "os"
            and node.value.attr == "environ"
        ):
            violations.append((node.lineno, f"os.environ.{node.attr}"))

        # os.environ["X"] (subscript)
        if (
            isinstance(node, ast.Subscript)
            and isinstance(node.value, ast.Attribute)
            and isinstance(node.value.value, ast.Name)
            and node.value.value.id == "os"
            and node.value.attr == "environ"
        ):
            violations.append((node.lineno, "os.environ[...]"))

        # load_dotenv() call
        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Name) and node.func.id == "load_dotenv":
                violations.append((node.lineno, "load_dotenv()"))
            if isinstance(node.func, ast.Attribute) and node.func.attr == "load_dotenv":
                violations.append((node.lineno, "*.load_dotenv()"))

    return violations


class TestConfigIsOnlyEnvReader:
    """No module other than config.py may read the environment directly."""

    @pytest.mark.parametrize(
        "filepath",
        [f for f in _python_files(SRC_ROOT) if f != ALLOWED_ENV_MODULE],
        ids=lambda p: str(p.relative_to(SRC_ROOT)),
    )
    def test_no_env_access_outside_config(self, filepath: Path):
        violations = _find_env_access(filepath)
        if violations:
            detail = "\n".join(f"  line {ln}: {desc}" for ln, desc in violations)
            pytest.fail(
                f"{filepath.relative_to(SRC_ROOT)} reads the environment directly:\n{detail}\n"
                f"Move env reads to config.py and pass Settings to the caller."
            )


class TestConfigModuleDoesAccessEnv:
    """Sanity check: config.py SHOULD contain env reads — otherwise our detector is broken."""

    def test_config_py_has_env_access(self):
        violations = _find_env_access(ALLOWED_ENV_MODULE)
        assert len(violations) > 0, (
            "config.py has no detected os.environ/os.getenv/load_dotenv calls — "
            "either config.py was gutted or the detector is broken."
        )


class TestNoHardcodedSecretsInSource:
    """Scan source for patterns that look like accidentally committed secrets."""

    SUSPECT_PATTERNS = [
        "sk-ant-",  # Anthropic API key prefix
        "sk-proj-",  # OpenAI API key prefix
        "AKIA",  # AWS access key prefix
        "ghp_",  # GitHub personal access token
        "gho_",  # GitHub OAuth token
    ]

    @pytest.mark.parametrize(
        "filepath",
        _python_files(SRC_ROOT),
        ids=lambda p: str(p.relative_to(SRC_ROOT)),
    )
    @pytest.mark.security
    def test_no_hardcoded_secrets(self, filepath: Path):
        content = filepath.read_text(encoding="utf-8")
        for pattern in self.SUSPECT_PATTERNS:
            assert pattern not in content, (
                f"{filepath.relative_to(SRC_ROOT)} contains suspect pattern '{pattern}' — "
                f"this looks like an accidentally committed secret."
            )


class TestSchemaFileExists:
    """schema.sql must be packaged with the wheel — without it init_schema() dies at import."""

    def test_schema_sql_exists(self):
        schema = SRC_ROOT / "graph" / "schema.sql"
        assert schema.exists(), "schema.sql is missing — init_schema() will fail at runtime"

    def test_schema_sql_is_not_empty(self):
        schema = SRC_ROOT / "graph" / "schema.sql"
        content = schema.read_text(encoding="utf-8").strip()
        assert len(content) > 100, "schema.sql looks suspiciously short"

    def test_schema_creates_all_required_tables(self):
        schema = SRC_ROOT / "graph" / "schema.sql"
        content = schema.read_text(encoding="utf-8").lower()
        for table in ("nodes", "edges", "ingest_runs", "node_chunks"):
            assert "create table" in content and table in content, (
                f"schema.sql does not create the '{table}' table"
            )

    def test_schema_enables_pgvector(self):
        schema = SRC_ROOT / "graph" / "schema.sql"
        content = schema.read_text(encoding="utf-8").lower()
        assert "create extension" in content and "vector" in content
