"""The only module that reads os.environ. Everything else takes Settings."""

from __future__ import annotations

import os
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

from dotenv import load_dotenv


@dataclass(frozen=True)
class Settings:
    database_url: str
    nvd_api_key: str | None = None
    provider: str = "anthropic"
    model: str = "claude-opus-5"
    data_raw_dir: Path = Path("data/raw")
    manifest_path: Path = Path("data/manifest.json")
    # retrieval knobs — recorded in eval run metadata so a number stays reproducible
    max_depth: int = 3
    node_budget: int = 200
    min_shared_actors: int = 3
    rrf_k: int = 60
    rerank_candidates: int = 50
    evidence_top_n: int = 12
    max_agent_steps: int = 8


def _int_env(name: str, default: int) -> int:
    raw = os.getenv(name)
    return int(raw) if raw else default


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    load_dotenv()
    database_url = os.getenv("DATABASE_URL")
    if not database_url:
        raise RuntimeError("DATABASE_URL is not set. Copy .env.example to .env.")
    return Settings(
        database_url=database_url,
        nvd_api_key=os.getenv("NVD_API_KEY") or None,
        provider=os.getenv("THREATLENS_PROVIDER", "anthropic"),
        model=os.getenv("THREATLENS_MODEL", "claude-opus-5"),
        data_raw_dir=Path(os.getenv("THREATLENS_DATA_RAW", "data/raw")),
        manifest_path=Path(os.getenv("THREATLENS_MANIFEST", "data/manifest.json")),
        max_depth=_int_env("THREATLENS_MAX_DEPTH", 3),
        node_budget=_int_env("THREATLENS_NODE_BUDGET", 200),
        min_shared_actors=_int_env("THREATLENS_MIN_SHARED_ACTORS", 3),
        rrf_k=_int_env("THREATLENS_RRF_K", 60),
        rerank_candidates=_int_env("THREATLENS_RERANK_CANDIDATES", 50),
        evidence_top_n=_int_env("THREATLENS_EVIDENCE_TOP_N", 12),
        max_agent_steps=_int_env("THREATLENS_MAX_AGENT_STEPS", 8),
    )
