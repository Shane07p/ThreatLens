# Setup

## Prereqs

- Python 3.12 (pinned in `.python-version`)
- `uv`
- Docker (for Postgres + pgvector)

## 1. Environment

```bash
uv sync
```

Dependencies are added with `uv add`, never `pip install`. The spec docs say
`pip install X --break-system-packages`; that flag exists to override an
externally-managed system Python and is wrong here — see [decisions.md](decisions.md) D1.

Phase-by-phase dependency adds:

```bash
# phase 1
uv add stix2 psycopg[binary] sqlalchemy typer python-dotenv
# phase 2
uv add httpx tenacity
# phase 3
uv add sentence-transformers pgvector
# phase 4
uv add rank-bm25
# phase 6
uv add langchain langgraph langchain-anthropic
# dev, any time
uv add --dev pytest pytest-timeout ruff
```

## 2. Database

`docker-compose.yml`:

```yaml
services:
  db:
    image: pgvector/pgvector:pg16
    environment:
      POSTGRES_USER: threatlens
      POSTGRES_PASSWORD: threatlens
      POSTGRES_DB: threatlens
    ports: ["5432:5432"]
    volumes: ["pgdata:/var/lib/postgresql/data"]
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U threatlens"]
      interval: 5s
      retries: 10
volumes:
  pgdata:
```

```bash
docker compose up -d db
uv run threatlens db init      # runs graph/schema.sql
```

`schema.sql` starts with `CREATE EXTENSION IF NOT EXISTS vector;` — the pgvector image ships
the extension but does not enable it in your database.

## 3. Secrets

`.env` (gitignored):

```
DATABASE_URL=postgresql+psycopg://threatlens:threatlens@localhost:5432/threatlens
THREATLENS_TEST_DSN=postgresql+psycopg://threatlens:threatlens@localhost:5432/threatlens_test
NVD_API_KEY=

# LLM provider — anthropic | openai | gemini | groq | deepseek | qwen | kimi
THREATLENS_PROVIDER=anthropic
THREATLENS_MODEL=claude-opus-5

# Only the key for the provider in use is required
ANTHROPIC_API_KEY=
OPENAI_API_KEY=
GEMINI_API_KEY=
GROQ_API_KEY=
DEEPSEEK_API_KEY=
QWEN_API_KEY=
KIMI_API_KEY=
```

- NVD key: https://nvd.nist.gov/developers/request-an-api-key — free, arrives by email,
  single-use reveal link. Raises the limit from 5 req/30s to 50 req/30s.
- `ANTHROPIC_API_KEY` is only needed from Phase 6 onward, plus `-m eval` tests.

`config.py` reads these once via `python-dotenv` and exposes a frozen settings object.
Nothing else in the codebase reads `os.environ`.

## 4. Fetch snapshots

```bash
uv run threatlens fetch attack      # ATT&CK STIX bundle
uv run threatlens fetch mappings    # CVE→ATT&CK KEV dataset
uv run threatlens fetch nvd         # scoped CVE pull (see data-sources.md)
```

Each writes to `data/raw/` and updates `data/manifest.json` with url, sha256, and timestamp.

## 5. Build the graph

```bash
uv run threatlens ingest attack
uv run threatlens ingest cves
uv run threatlens ingest mappings
uv run threatlens ingest chains     # derive CHAINS_TO
uv run threatlens embed             # phase 3+
```

Sanity check before trusting anything:

```bash
uv run threatlens stats             # node/edge counts by kind
uv run threatlens show T1190        # one technique, its tactic, mitigations, actors
```

## 6. Model weights

First run of `threatlens embed` downloads `BAAI/bge-small-en-v1.5` (~130 MB) to the
HuggingFace cache; the reranker `BAAI/bge-reranker-base` (~1.1 GB) downloads on first
rerank. Both are CPU-only and MIT/Apache licensed. Cache lives outside the repo
(`~/.cache/huggingface`) — do not vendor weights into `data/`.

## Troubleshooting

| Symptom | Cause |
|---|---|
| `type "vector" does not exist` | `CREATE EXTENSION vector` not run in *this* database |
| NVD 403 / 503 storms | Missing or wrong `apiKey` header; back off, the limiter is per-key |
| Mappings CSV 404 | The `&` in `Att&ckToCveMappings.csv` must stay URL-encoded as `%26` |
| Embeddings all identical | Stub encoder from tests leaked into a real run — check `config.py` |
| 400 from Anthropic API | You passed `temperature` / `top_p` / `budget_tokens`. Remove them. |
