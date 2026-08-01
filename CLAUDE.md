# CLAUDE.md — ThreatLens

Guidance for Claude Code working in this repository.

## What this project is

ThreatLens is an **agentic GraphRAG threat-intelligence tool**. Given a security finding
(a CVE, an ATT&CK technique, a plain-English question), it traverses a knowledge graph of
threat intelligence — CVE → technique → tactic → chained techniques → mitigations → threat
actors — and returns a grounded, cited answer.

**Graph retrieval is the product.** The answer is a *path through linked knowledge*, not a
set of similar text chunks. Naive vector RAG is the baseline we measure against, not the
architecture.

Two source documents define the project; treat them as the spec of record:
- `threat_intel_graphrag_spec (1).md` — full project spec
- `threatlens_phase1-3_data_sources_guide.md` — exact data sources for phases 1–3

Working docs live in `.claude/` — start at `.claude/README.md`.

**These are local-only and untracked** (see `.gitignore`). They exist on disk but are not
published to GitHub, so links to them will not resolve there.

## Non-goals (do not build these)

- Not a scanner or detector. It does not scan systems or monitor networks.
- Not a SOC platform.
- No live API calls at query time — all data is a local snapshot.
- No fine-tuning, no GPU, no Pinecone/Weaviate, no CrewAI/AutoGen.

## Stack

| Layer | Choice |
|---|---|
| Language | Python 3.12, `uv` for env + packages |
| Graph + vectors | PostgreSQL 16 + `pgvector` (single store, recursive CTEs for traversal) |
| ATT&CK parsing | `stix2` |
| HTTP | `httpx` |
| Embeddings | `sentence-transformers` → `BAAI/bge-small-en-v1.5` (384-dim) |
| Lexical | `rank-bm25` |
| Reranker | `BAAI/bge-reranker-base` |
| LLM | `anthropic` SDK, model `claude-opus-5` |
| CLI | `typer` |
| Tests | `pytest` |

## Commands

```bash
uv sync                      # install deps
uv add <package>             # add a dependency (NEVER pip install)
docker compose up -d db      # Postgres + pgvector
uv run threatlens --help     # CLI
uv run pytest -m "not slow and not eval"   # fast test suite
uv run pytest                # everything except eval
uv run pytest -m eval        # eval harness (costs LLM tokens)
uv run ruff check . && uv run ruff format .
```

## Rules

1. **`uv add`, never `pip install`.** The source docs say
   `pip install X --break-system-packages`; that is wrong for this project — see
   [.claude/decisions.md](.claude/decisions.md) D1.
2. **Never touch the held-out eval set outside the eval harness.** It is frozen in Phase 2
   and committed. Regenerating it invalidates every number in the ablation table.
3. **Snapshots, not live APIs.** Ingestion writes to `data/` (gitignored). Query-time code
   must never call NVD, GitHub, or MITRE.
4. **Every generated claim carries a citation** to a node id. Ungrounded output is a bug.
5. **Secrets in `.env`** (`NVD_API_KEY`, `ANTHROPIC_API_KEY`), read via `config.py`. Never
   hardcode, never commit.
6. **Claude API:** `claude-opus-5`, `thinking={"type": "adaptive"}`. Do **not** pass
   `temperature`, `top_p`, `top_k`, or `budget_tokens` — they return 400 on this model.
7. **Tests before implementation** for retrieval and ingestion logic. See
   [.claude/testing.md](.claude/testing.md).
8. Record any deviation from the spec in [.claude/decisions.md](.claude/decisions.md).

## Layout

```
src/threatlens/
├── cli.py            # typer entrypoint
├── config.py         # env + settings
├── ingest/           # attack.py, nvd.py, mappings.py, chains.py
├── graph/            # schema.sql, store.py, traverse.py
├── retrieval/        # embed.py, vector.py, bm25.py, fusion.py, rerank.py, pipeline.py
├── agent/            # loop.py, tools.py, prompts.py
├── report/           # markdown.py
└── eval/             # harness.py, metrics.py, configs.py
tests/                # unit/, integration/, eval/, fixtures/
data/                 # snapshots (gitignored) + data/eval/holdout.jsonl (committed)
```

## Current state

Phase 0. Only the `uv init` scaffold exists. Next: [.claude/phase-1-attack-ingestion.md](.claude/phase-1-attack-ingestion.md).
