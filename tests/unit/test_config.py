"""Exhaustive tests for threatlens.config.

config.py is the single gateway to the environment. Every field, every default,
every override path, and every edge case in env-var parsing is tested here so that
a refactor that accidentally drops a knob or changes a fallback is caught before merge.
"""

from __future__ import annotations

from dataclasses import FrozenInstanceError
from pathlib import Path

import pytest

from threatlens.config import Settings, _int_env, get_settings

# ── Settings dataclass contract ─────────────────────────────────────────────


class TestSettingsDefaults:
    """Every default is part of the public API — changing one is a breaking change."""

    def test_database_url_is_required(self):
        with pytest.raises(TypeError):
            Settings()  # database_url has no default

    def test_nvd_api_key_defaults_to_none(self):
        s = Settings(database_url="postgresql://localhost/db")
        assert s.nvd_api_key is None

    def test_provider_defaults_to_anthropic(self):
        s = Settings(database_url="postgresql://localhost/db")
        assert s.provider == "anthropic"

    def test_model_defaults_to_claude_opus_5(self):
        s = Settings(database_url="postgresql://localhost/db")
        assert s.model == "claude-opus-5"

    def test_data_raw_dir_defaults_to_data_raw(self):
        s = Settings(database_url="postgresql://localhost/db")
        assert s.data_raw_dir == Path("data/raw")

    def test_manifest_path_defaults_to_data_manifest_json(self):
        s = Settings(database_url="postgresql://localhost/db")
        assert s.manifest_path == Path("data/manifest.json")

    @pytest.mark.parametrize(
        "field, expected",
        [
            ("max_depth", 3),
            ("node_budget", 200),
            ("min_shared_actors", 3),
            ("rrf_k", 60),
            ("rerank_candidates", 50),
            ("evidence_top_n", 12),
            ("max_agent_steps", 8),
        ],
    )
    def test_retrieval_knob_defaults(self, field, expected):
        s = Settings(database_url="postgresql://localhost/db")
        assert getattr(s, field) == expected


class TestSettingsFrozen:
    """Settings is frozen — accidental mutation would silently break config consumers."""

    def _make(self) -> Settings:
        return Settings(database_url="postgresql://localhost/db")

    def test_cannot_mutate_database_url(self):
        with pytest.raises(FrozenInstanceError):
            self._make().database_url = "sqlite:///nope"

    def test_cannot_mutate_provider(self):
        with pytest.raises(FrozenInstanceError):
            self._make().provider = "openai"

    def test_cannot_mutate_max_depth(self):
        with pytest.raises(FrozenInstanceError):
            self._make().max_depth = 99

    def test_cannot_mutate_data_raw_dir(self):
        with pytest.raises(FrozenInstanceError):
            self._make().data_raw_dir = Path("/tmp")

    def test_cannot_add_new_attributes(self):
        with pytest.raises(FrozenInstanceError):
            self._make().new_field = "surprise"


class TestSettingsEquality:
    """Two Settings with identical fields must compare equal — test fixtures depend on it."""

    def test_identical_settings_are_equal(self):
        a = Settings(database_url="postgresql://localhost/db")
        b = Settings(database_url="postgresql://localhost/db")
        assert a == b

    def test_different_database_url_breaks_equality(self):
        a = Settings(database_url="postgresql://a/db")
        b = Settings(database_url="postgresql://b/db")
        assert a != b

    def test_different_knob_breaks_equality(self):
        a = Settings(database_url="postgresql://localhost/db", max_depth=3)
        b = Settings(database_url="postgresql://localhost/db", max_depth=5)
        assert a != b


# ── _int_env helper ─────────────────────────────────────────────────────────


class TestIntEnv:
    """_int_env silently converts env vars to ints; bad input must not corrupt config."""

    def test_returns_default_when_env_var_absent(self, monkeypatch):
        monkeypatch.delenv("THREATLENS_PHANTOM_KNOB", raising=False)
        assert _int_env("THREATLENS_PHANTOM_KNOB", 42) == 42

    def test_returns_parsed_int_when_env_var_present(self, monkeypatch):
        monkeypatch.setenv("THREATLENS_PHANTOM_KNOB", "99")
        assert _int_env("THREATLENS_PHANTOM_KNOB", 42) == 99

    def test_returns_default_when_env_var_is_empty_string(self, monkeypatch):
        monkeypatch.setenv("THREATLENS_PHANTOM_KNOB", "")
        assert _int_env("THREATLENS_PHANTOM_KNOB", 42) == 42

    def test_raises_on_non_numeric_string(self, monkeypatch):
        monkeypatch.setenv("THREATLENS_PHANTOM_KNOB", "not_a_number")
        with pytest.raises(ValueError):
            _int_env("THREATLENS_PHANTOM_KNOB", 42)

    def test_accepts_negative_values(self, monkeypatch):
        monkeypatch.setenv("THREATLENS_PHANTOM_KNOB", "-1")
        assert _int_env("THREATLENS_PHANTOM_KNOB", 42) == -1

    def test_accepts_zero(self, monkeypatch):
        monkeypatch.setenv("THREATLENS_PHANTOM_KNOB", "0")
        assert _int_env("THREATLENS_PHANTOM_KNOB", 42) == 0

    def test_rejects_float_string(self, monkeypatch):
        monkeypatch.setenv("THREATLENS_PHANTOM_KNOB", "3.14")
        with pytest.raises(ValueError):
            _int_env("THREATLENS_PHANTOM_KNOB", 42)

    def test_strips_whitespace_before_parsing(self, monkeypatch):
        """Trailing newlines from shell expansions are common."""
        monkeypatch.setenv("THREATLENS_PHANTOM_KNOB", "  7  ")
        # int(" 7 ") works in Python — this documents the behavior
        assert _int_env("THREATLENS_PHANTOM_KNOB", 42) == 7


# ── get_settings() — the cached factory ─────────────────────────────────────


class TestGetSettings:
    """get_settings() reads the env exactly once; tests must clear the cache."""

    @pytest.fixture(autouse=True)
    def _clear_cache(self):
        get_settings.cache_clear()
        yield
        get_settings.cache_clear()

    def _stub_dotenv(self, monkeypatch):
        """Prevent load_dotenv from reading a real .env file in the repo."""
        monkeypatch.setattr("threatlens.config.load_dotenv", lambda *a, **kw: None)

    # --- DATABASE_URL is required, with no fallback -------------------------

    def test_database_url_from_env(self, monkeypatch):
        self._stub_dotenv(monkeypatch)
        monkeypatch.setenv("DATABASE_URL", "postgresql://custom/db")
        monkeypatch.delenv("THREATLENS_TEST_DSN", raising=False)
        assert get_settings().database_url == "postgresql://custom/db"

    def test_missing_database_url_raises(self, monkeypatch):
        """No default. A plausible-looking fallback would let the CLI run against a
        database nobody chose, writing a real graph somewhere unintended."""
        self._stub_dotenv(monkeypatch)
        monkeypatch.delenv("DATABASE_URL", raising=False)
        monkeypatch.delenv("THREATLENS_TEST_DSN", raising=False)
        with pytest.raises(RuntimeError, match="DATABASE_URL"):
            get_settings()

    def test_test_dsn_is_not_used_as_a_fallback(self, monkeypatch):
        """The sharpest version of the same bug: falling back to THREATLENS_TEST_DSN
        means `threatlens ingest` writes the production graph into the test database,
        with no error and no warning. CI and .env.example both set that variable."""
        self._stub_dotenv(monkeypatch)
        monkeypatch.delenv("DATABASE_URL", raising=False)
        monkeypatch.setenv("THREATLENS_TEST_DSN", "postgresql://test/db")
        with pytest.raises(RuntimeError, match="DATABASE_URL"):
            get_settings()

    def test_error_message_says_how_to_fix_it(self, monkeypatch):
        """A config error should tell you the next action, not just what is missing."""
        self._stub_dotenv(monkeypatch)
        monkeypatch.delenv("DATABASE_URL", raising=False)
        with pytest.raises(RuntimeError, match=r"\.env"):
            get_settings()

    # --- NVD API key --------------------------------------------------------

    def test_nvd_api_key_none_when_absent(self, monkeypatch):
        self._stub_dotenv(monkeypatch)
        monkeypatch.setenv("DATABASE_URL", "postgresql://localhost/db")
        monkeypatch.delenv("NVD_API_KEY", raising=False)
        assert get_settings().nvd_api_key is None

    def test_nvd_api_key_none_when_empty_string(self, monkeypatch):
        """Docker Compose and .env.example both leave NVD_API_KEY= empty."""
        self._stub_dotenv(monkeypatch)
        monkeypatch.setenv("DATABASE_URL", "postgresql://localhost/db")
        monkeypatch.setenv("NVD_API_KEY", "")
        assert get_settings().nvd_api_key is None

    def test_nvd_api_key_populated(self, monkeypatch):
        self._stub_dotenv(monkeypatch)
        monkeypatch.setenv("DATABASE_URL", "postgresql://localhost/db")
        monkeypatch.setenv("NVD_API_KEY", "abc-123-key")
        assert get_settings().nvd_api_key == "abc-123-key"

    # --- LLM provider / model -----------------------------------------------

    def test_provider_override(self, monkeypatch):
        self._stub_dotenv(monkeypatch)
        monkeypatch.setenv("DATABASE_URL", "postgresql://localhost/db")
        monkeypatch.setenv("THREATLENS_PROVIDER", "openai")
        assert get_settings().provider == "openai"

    def test_model_override(self, monkeypatch):
        self._stub_dotenv(monkeypatch)
        monkeypatch.setenv("DATABASE_URL", "postgresql://localhost/db")
        monkeypatch.setenv("THREATLENS_MODEL", "gpt-4o")
        assert get_settings().model == "gpt-4o"

    # --- data paths ---------------------------------------------------------

    def test_data_raw_dir_override(self, monkeypatch):
        self._stub_dotenv(monkeypatch)
        monkeypatch.setenv("DATABASE_URL", "postgresql://localhost/db")
        monkeypatch.setenv("THREATLENS_DATA_RAW", "/opt/data/raw")
        assert get_settings().data_raw_dir == Path("/opt/data/raw")

    def test_manifest_path_override(self, monkeypatch):
        self._stub_dotenv(monkeypatch)
        monkeypatch.setenv("DATABASE_URL", "postgresql://localhost/db")
        monkeypatch.setenv("THREATLENS_MANIFEST", "/opt/data/manifest.json")
        assert get_settings().manifest_path == Path("/opt/data/manifest.json")

    # --- retrieval knobs from env -------------------------------------------

    @pytest.mark.parametrize(
        "env_var, field, value",
        [
            ("THREATLENS_MAX_DEPTH", "max_depth", "10"),
            ("THREATLENS_NODE_BUDGET", "node_budget", "500"),
            ("THREATLENS_MIN_SHARED_ACTORS", "min_shared_actors", "1"),
            ("THREATLENS_RRF_K", "rrf_k", "100"),
            ("THREATLENS_RERANK_CANDIDATES", "rerank_candidates", "25"),
            ("THREATLENS_EVIDENCE_TOP_N", "evidence_top_n", "20"),
            ("THREATLENS_MAX_AGENT_STEPS", "max_agent_steps", "15"),
        ],
    )
    def test_retrieval_knob_env_override(self, monkeypatch, env_var, field, value):
        self._stub_dotenv(monkeypatch)
        monkeypatch.setenv("DATABASE_URL", "postgresql://localhost/db")
        monkeypatch.setenv(env_var, value)
        assert getattr(get_settings(), field) == int(value)

    # --- caching behavior ---------------------------------------------------

    def test_get_settings_is_cached(self, monkeypatch):
        """Calling get_settings twice without cache_clear returns the same object."""
        self._stub_dotenv(monkeypatch)
        monkeypatch.setenv("DATABASE_URL", "postgresql://localhost/db")
        first = get_settings()
        second = get_settings()
        assert first is second

    def test_cache_clear_yields_fresh_instance(self, monkeypatch):
        self._stub_dotenv(monkeypatch)
        monkeypatch.setenv("DATABASE_URL", "postgresql://first/db")
        first = get_settings()
        get_settings.cache_clear()
        monkeypatch.setenv("DATABASE_URL", "postgresql://second/db")
        second = get_settings()
        assert first.database_url != second.database_url

    # --- all env vars at once -----------------------------------------------

    def test_all_overrides_applied_simultaneously(self, monkeypatch):
        """Regression guard: one env var reading another's slot would be invisible."""
        self._stub_dotenv(monkeypatch)
        monkeypatch.setenv("DATABASE_URL", "postgresql://all/db")
        monkeypatch.setenv("NVD_API_KEY", "all-key")
        monkeypatch.setenv("THREATLENS_PROVIDER", "gemini")
        monkeypatch.setenv("THREATLENS_MODEL", "gemini-2.0-flash")
        monkeypatch.setenv("THREATLENS_DATA_RAW", "/all/raw")
        monkeypatch.setenv("THREATLENS_MANIFEST", "/all/manifest.json")
        monkeypatch.setenv("THREATLENS_MAX_DEPTH", "7")
        monkeypatch.setenv("THREATLENS_NODE_BUDGET", "1000")
        monkeypatch.setenv("THREATLENS_MIN_SHARED_ACTORS", "5")
        monkeypatch.setenv("THREATLENS_RRF_K", "120")
        monkeypatch.setenv("THREATLENS_RERANK_CANDIDATES", "75")
        monkeypatch.setenv("THREATLENS_EVIDENCE_TOP_N", "30")
        monkeypatch.setenv("THREATLENS_MAX_AGENT_STEPS", "20")

        s = get_settings()
        assert s.database_url == "postgresql://all/db"
        assert s.nvd_api_key == "all-key"
        assert s.provider == "gemini"
        assert s.model == "gemini-2.0-flash"
        assert s.data_raw_dir == Path("/all/raw")
        assert s.manifest_path == Path("/all/manifest.json")
        assert s.max_depth == 7
        assert s.node_budget == 1000
        assert s.min_shared_actors == 5
        assert s.rrf_k == 120
        assert s.rerank_candidates == 75
        assert s.evidence_top_n == 30
        assert s.max_agent_steps == 20
