# ThreatLens

A Graph-RAG threat-intelligence agent. Give it a security finding — a CVE, an ATT&CK
technique, a plain-English question — and it traces the whole picture: what the attack is,
how it's exploited, what an attacker does next, who uses it, and how to defend. Every claim
carries a citation.

> **Status: in development.** The ATT&CK graph (MITRE ATT&CK Enterprise **v19.2**, sha256
> `dc1639caa550…`, pinned in [data/manifest.json](data/manifest.json)), traversal, and CVE
> ingestion are built; retrieval and evaluation are in progress. No results to report yet —
> this README will carry the ablation table when there is one. Current status:
> [docs/phases/phases.md](docs/phases/phases.md).

## The idea

Answering *"here's a CVE — how bad is it, how would an attacker actually use it, and what do
I do?"* means cross-referencing several separate knowledge bases: the CVE record, the MITRE
ATT&CK framework, the mappings between them, threat-actor reporting, and mitigation
catalogs. That stitching is slow, needs expertise, and is easy to get wrong under alert
pressure.

ThreatLens models that world as a **knowledge graph** — CVEs, techniques, tactics,
mitigations, threat actors, all linked — and answers questions by **traversing** it:

```
CVE ──ENABLES──▶ Technique ──BELONGS_TO──▶ Tactic
                 Technique ──CHAINS_TO───▶ Technique
                 Technique ──MITIGATED_BY▶ Mitigation
                 Technique ◀────USES───── ThreatActor
```

The answer is a *path through linked knowledge*, not a set of similar text chunks — which
is exactly where flat vector RAG underperforms. Graph retrieval is the engine, not a
feature.

## Planned interface

```bash
threatlens ask "CVE-2021-44228 showed up in our environment. How would an attacker
                exploit it, what would they likely do next, and how do I defend?"
threatlens ask "..." --report finding.md    # shareable Markdown artifact
threatlens path CVE-2021-44228              # traversal only, no LLM
```

## Stack

Python 3.12 · PostgreSQL + pgvector · MITRE ATT&CK (STIX 2.1) · NVD · CVE→ATT&CK Mappings
Explorer · `bge-small-en-v1.5` embeddings · BM25 + RRF + cross-encoder reranking ·
LangChain/LangGraph for the agent layer only · Typer

## Setup

> Commands beyond `db init` land as their phases are implemented. See
> [docs/phases/phases.md](docs/phases/phases.md) for current status. To contribute, read
> [CONTRIBUTING.md](CONTRIBUTING.md).

### 1. Prerequisites

| Tool | Why |
|---|---|
| **Python 3.12** | pinned in `.python-version` |
| **[uv](https://docs.astral.sh/uv/)** | environment and dependency management |
| **Docker** | runs Postgres 16 + pgvector |

### 2. Install

```bash
git clone https://github.com/Shane07p/ThreatLens.git
cd ThreatLens

uv sync --all-groups           # preferred
# pip install -r requirements.txt   # if you'd rather not use uv
```

`uv add <package>` to add a dependency — never `pip install` into the project
environment, or `uv.lock` and CI drift apart.

### 3. Configure

```bash
cp .env.example .env
```

Fill in:

| Variable | Required | Notes |
|---|---|---|
| `DATABASE_URL` | yes | pre-filled for the Docker container |
| `NVD_API_KEY` | recommended | free, by email — [request one](https://nvd.nist.gov/developers/request-an-api-key). Raises the rate limit from 5 req/30s to 50. |
| `THREATLENS_PROVIDER` | yes | `anthropic` \| `openai` \| `gemini` \| `groq` \| `deepseek` \| `qwen` \| `kimi` |
| `<PROVIDER>_API_KEY` | phase 6+ | only the one for the provider you selected |

`.env` is gitignored. Never commit real keys — the repository is public, so a key
in any commit is compromised the moment it is pushed.

### 4. Database

```bash
docker compose up -d db        # Postgres 16 + pgvector, plus a test database
uv run threatlens db init      # apply the schema
```

### 5. Verify

```bash
uv run pytest -m "not eval"    # unit + integration; no API calls, no cost
```

Green means the environment is correct. This is the same command CI runs.

### 6. Build the graph

```bash
uv run threatlens fetch attack     # MITRE ATT&CK STIX bundle
uv run threatlens fetch mappings   # CVE→ATT&CK mappings
uv run threatlens fetch nvd        # CVE records (scoped, not all 250k)

uv run threatlens ingest attack
uv run threatlens ingest cves
uv run threatlens ingest mappings
uv run threatlens ingest chains    # derive CHAINS_TO edges
uv run threatlens embed            # embed node text

uv run threatlens stats            # node/edge counts — sanity-check before trusting anything
uv run threatlens show T1190       # one technique, end to end
```

Snapshots land in `data/` (gitignored) and are recorded in `data/manifest.json`
with URL, sha256, and version. **Pin them.** If the ATT&CK snapshot changes
mid-project, every measured number becomes incomparable.

First run of `embed` downloads `bge-small-en-v1.5` (~130 MB); the reranker
(~1.1 GB) downloads on first use. Both are CPU-only — no GPU anywhere.

### Troubleshooting

| Symptom | Cause |
|---|---|
| `type "vector" does not exist` | `CREATE EXTENSION vector` not run in *this* database |
| NVD 403 / 503 storms | missing or wrong `apiKey` header — the limiter is per key |
| Mappings CSV 404 | the `&` in `Att&ckToCveMappings.csv` must stay URL-encoded as `%26` |
| 400 from the Anthropic API | `temperature` / `top_p` / `budget_tokens` were passed — remove them |
| CI red on formatting | run `uv run ruff format .` and commit |

Deeper notes on data sources, provider selection, and the graph schema are in
[docs/](docs/README.md); the build plan is in [docs/phases/phases.md](docs/phases/phases.md).

## Evaluation

The point of the project. The CVE→ATT&CK Mappings Explorer provides labelled ground truth;
20% is held out and frozen before any retrieval code is written. Each retrieval component is
measured independently:

| # | Configuration | recall@1 | recall@5 | MRR | Groundedness |
|---|---|---|---|---|---|
| A | Vector search only (naive RAG baseline) | — | — | — | — |
| B | + BM25 hybrid (RRF) | — | — | — | — |
| C | + graph traversal (GraphRAG) | — | — | — | — |
| D | + cross-encoder reranking | — | — | — | — |
| E | + agentic re-query (full system) | — | — | — | — |

Numbers land as the phases complete. Empty cells are honest; guessed cells would not be.

## Scope

**Is:** a comprehension and research tool over known threat intelligence.
**Is not:** a scanner, a detector, a network monitor, or a SOC platform. A clean answer does
not mean "you are safe."

This is an active research area — CyKG-RAG, the IEEE GraphRAG-CTI dataset, and Minerva cover
similar ground. No novelty is claimed for the approach; the goal is a well-built,
well-evaluated, usable implementation.

## Documentation

- [ARCHITECTURE.md](ARCHITECTURE.md) — the code map: what each module owns and must not do
- [docs/](docs/README.md) — graph schema, data sources, retrieval design, evaluation
  protocol, conventions, and the eight-phase build plan
- [docs/design/decisions.md](docs/design/decisions.md) — every deviation from the source
  spec, with reasons
- [CONTRIBUTING.md](CONTRIBUTING.md) · [CONTRIBUTORS.md](CONTRIBUTORS.md) ·
  [SECURITY.md](SECURITY.md) · [AGENTS.md](AGENTS.md) for AI coding agents

## Attribution

MITRE ATT&CK® is a registered trademark of The MITRE Corporation. Data from MITRE ATT&CK,
the NIST National Vulnerability Database, and the Center for Threat-Informed Defense
Mappings Explorer, used under their respective terms.
