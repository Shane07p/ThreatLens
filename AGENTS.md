# AGENTS.md — ThreatLens

Instructions for AI coding agents working in this repository. Humans should start at
[README.md](README.md) and [CONTRIBUTING.md](CONTRIBUTING.md).

This file is deliberately short: it is loaded into every agent session, and a long file
costs context and lowers adherence. Each rule names the doc that explains it — read those
on demand, not up front. Directories with their own rules carry a nested `AGENTS.md`
([tests/](tests/AGENTS.md), [ingest/](src/threatlens/ingest/AGENTS.md),
[graph/](src/threatlens/graph/AGENTS.md), [retrieval/](src/threatlens/retrieval/AGENTS.md));
the one closest to the file you are editing adds to this one.

## What this is

A GraphRAG threat-intelligence CLI. Given a CVE, an ATT&CK technique, or a question, it walks
a knowledge graph — CVE → technique → tactic → mitigation, with actors and chained
techniques — and returns an answer where every claim cites a node.

**Graph retrieval is the product.** Naive vector RAG is the baseline it is measured against.
The deliverable that matters is the ablation table, configs A–E, each differing from the
last by exactly one component ([docs/design/evaluation.md](docs/design/evaluation.md)).

Not a scanner, detector, or SOC platform. No live API calls at query time. No GPU, no
fine-tuning, no hosted vector database.

## Commands

```bash
uv sync --all-groups                      # install everything, including dev tools
docker compose up -d db                   # Postgres 16 + pgvector, plus a test database
uv run threatlens --help                  # the CLI

uv run pytest -m "not db and not eval"    # unit tests: no database, no network, seconds
uv run pytest -m "not eval"               # what CI runs; needs THREATLENS_TEST_DSN set
uv run ruff check . && uv run ruff format . && uv run mypy
uv run pre-commit run --all-files         # every local check in one go
```

Integration tests read `THREATLENS_TEST_DSN` from `.env` (see `.env.example`). `-m eval`
calls a paid LLM API and never runs in CI.

## Where things are

| Path | What |
|---|---|
| `src/threatlens/` | `cli.py` (Typer), `config.py` (the only env reader), `models.py` (`Node`, `Edge`, `Graph`) |
| `src/threatlens/ingest/` | fetch snapshots, parse STIX / NVD / mappings, write via `graph/` |
| `src/threatlens/graph/` | `schema.sql`, `store.py` (all SQL), `traverse.py` (multi-hop) |
| `src/threatlens/retrieval/`, `eval/` | embeddings and ranking; metrics |
| `tests/unit/`, `tests/integration/` | no-DB tests; Postgres tests marked `db` |
| `docs/` | [design](docs/design/), [phases](docs/phases/phases.md), [conventions](docs/conventions/), [spec](docs/spec.md) |

[ARCHITECTURE.md](ARCHITECTURE.md) is the code map: what each module owns and must not do.

## Hard rules

CI or review rejects a change that breaks one of these.

| Rule | Why |
|---|---|
| `uv add`, never `pip install` | `uv.lock` is what CI installs; anything else drifts |
| No `os.environ` outside `config.py` | one place to read, change, and test settings |
| No SQL outside `graph/`; never f-string SQL | a schema change has one home; injection-safe by construction |
| `ingest/ graph/ retrieval/ eval/ report/` never import LangChain or LangGraph | configs A–D must stay deterministic; only `llm/` and `agent/` may |
| Missing value is `None`, never a plausible default | a fabricated `0.0` severity reads as "no risk" |
| Every write is an upsert; re-running changes no counts | ingestion must be idempotent |
| Every generated claim cites a node id; the model never writes URLs | ungrounded output is a bug |
| Never read or regenerate `data/eval/holdout.jsonl` outside `eval/` | regenerating it invalidates every published number |
| Snapshots only — query-time code never calls NVD, MITRE, or GitHub | results must be reproducible offline |
| No secrets in code, tests, or commits; `.env` only | the repository is public — a pushed secret is compromised |
| No AI attribution in commits, PRs, or tags | commits are authored by the maintainers |
| No phase numbers, task ids, or decision ids in code comments | they rot and mean nothing to a reader |

Details: [docs/conventions/code.md](docs/conventions/code.md),
[docs/conventions/workflow.md](docs/conventions/workflow.md).

## How to work

These counter the ways coding agents most often go wrong — making an assumption and running
with it, hiding confusion, over-building, and editing code they were not asked to touch.

1. **State assumptions before acting on them.** When two readings of a request lead to
   different work, ask. When the code and a doc disagree, say so instead of picking one
   silently.
2. **Push back when a request conflicts with these rules or the design docs.** Say it once,
   in a sentence, then follow the decision.
3. **Build the simplest thing that works.** No speculative options, layers, or error
   handling for cases that cannot happen. If a change came out at 500 lines, check whether
   100 would do. A defensive branch that can never execute is dead code that reads like a
   guard.
4. **Make surgical changes.** Touch only what the task needs. Do not reformat, rename, or
   delete comments or code you do not understand. Remove dead code you created; flag dead
   code you found.
5. **Define done as something you can run.** For parsers, traversal, and ranking, write the
   test first and watch it fail for the reason you expect. Reproduce a bug as a failing test
   before fixing it.
6. **Check that new tests can fail.** Break the implementation once and confirm a test goes
   red. Mutation has already exposed two tests here that passed no matter what the code did.
7. **Prove claims with output.** "Tests pass" means you ran them in this session. Report
   failures with the output, not a summary of it.

## Before you call something done

- [ ] `uv run ruff check .`, `uv run ruff format --check .`, `uv run mypy` are clean
- [ ] `uv run pytest -m "not eval"` is green against a real Postgres
- [ ] New behaviour has a test that failed before the change
- [ ] Docs changed if commands, layout, or behaviour changed
- [ ] A deviation from the spec or design is recorded in [docs/design/decisions.md](docs/design/decisions.md)
- [ ] Nothing from `data/raw/`, no `.env`, no keys, no AI co-author lines

## Agent tool notes

- **Claude Code** reads this file natively from v2.1.277. **Do not commit a `CLAUDE.md` or
  `CLAUDE.local.md`** — if either exists, Claude Code reads it *instead of* this file. Keep
  personal instructions in `~/.claude/CLAUDE.md`, which does not have that effect.
  Claude-only settings and hooks live in `.claude/settings.json`.
- **Antigravity** (successor to Gemini CLI, retired June 2026), **Codex**, **Copilot**, and
  **Cursor** read `AGENTS.md` directly. No `GEMINI.md` or `.cursorrules` is needed, and adding
  one creates a second copy of these rules that will drift from this one.
