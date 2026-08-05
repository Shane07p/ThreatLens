from pathlib import Path

import pytest

from threatlens.config import Settings, get_settings


def test_settings_default_data_paths():
    s = Settings(database_url="postgresql://localhost/db")
    assert s.data_raw_dir == Path("data/raw")
    assert s.manifest_path == Path("data/manifest.json")


def test_get_settings_env_overrides_data_paths(monkeypatch):
    get_settings.cache_clear()
    monkeypatch.setenv("DATABASE_URL", "postgresql://localhost/test_db")
    monkeypatch.setenv("THREATLENS_DATA_RAW", "custom/data/raw")
    monkeypatch.setenv("THREATLENS_MANIFEST", "custom/manifest.json")

    s = get_settings()
    assert s.data_raw_dir == Path("custom/data/raw")
    assert s.manifest_path == Path("custom/manifest.json")
    get_settings.cache_clear()


def test_get_settings_missing_database_url_raises_runtime_error(monkeypatch):
    get_settings.cache_clear()
    monkeypatch.setattr("threatlens.config.load_dotenv", lambda *a, **kw: None)
    monkeypatch.delenv("DATABASE_URL", raising=False)

    with pytest.raises(RuntimeError, match="DATABASE_URL is not set"):
        get_settings()
    get_settings.cache_clear()
