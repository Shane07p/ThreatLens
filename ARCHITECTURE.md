# Architecture

A map of the code as it exists today: what each module is for, where to start reading, and
what it must never do. The *target* design — including the parts not built yet — is in
[docs/design/architecture.md](docs/design/architecture.md).

Names below are meant to be searched for (`rg parse_bundle`), not clicked. Links to line
numbers rot; symbol names mostly do not.

## Bird's-eye view

```
 offline, run once                                    query time
 ─────────────────                                    ──────────
 MITRE ATT&CK STIX ─┐                                 threatlens show / path
 NVD CVE records  ──┼─ ingest/ ─▶ Postgres + pgvector ─▶ graph/traverse.py
 CVE→ATT&CK maps  ──┘   fetch,     nodes, edges,        retrieval/ (embeddings, ranking)
 CISA KEV catalog       parse,     node_chunks          eval/ (metrics)
                        write      ingest_runs
```

Ingestion pulls pinned snapshots into `data/raw/`, parses them into frozen `Node` and `Edge`
values, and upserts them. Query-time code reads only from Postgres. A node id is
`{kind}:{external_id}` — `technique:T1190`, `cve:CVE-2021-44228` — so ids are deterministic
and every re-ingest updates rows rather than adding new ones.

## Code map

### `models.py`
`Node`, `Edge`, `Graph` — frozen dataclasses, the contract every module exchanges. Plus
`NODE_KINDS` and `EDGE_KINDS`. Nothing crosses a module boundary as a bare dict.

### `config.py`
`get_settings()` is the **only** reader of environment variables. It raises if
`DATABASE_URL` is unset rather than falling back to a default, because a plausible fallback
once meant production ingestion could silently write into the test database.

### `cli.py`
Typer app, entry point `threatlens`. Command groups: `db`, `fetch`, `ingest`, plus `stats`,
`show`, `path`, `embed`, `doctor`, `config`. Commands should stay thin: resolve paths, call
one function in `ingest/`, `graph/` or `retrieval/`, print the result. Logic that grows here
belongs in a module where it can be tested without a terminal.

### `ingest/` — snapshots in, graph out
| Module | Entry points | Notes |
|---|---|---|
| `fetch.py` | `fetch_url`, `fetch_scoped_nvd`, `TokenBucket` | Only network code in the project. Pins sha256 in `data/manifest.json`. |
| `attack.py` | `parse_bundle` (pure), `ingest_attack` | STIX 2.1 → techniques, tactics, mitigations, actors, software. |
| `nvd.py` | `parse_cve_record` (pure), `ingest_cves`, `load_kev_ids` | CVSS v3.1, falling back to v4.0, then `None`. |
| `mappings.py` | `parse_mappings_csv` (pure), `partition_edges`, `ingest_mappings` | `ENABLES` edges, primary 1.0 / secondary 0.5. |

**Invariant:** parsers are pure; writes go through `graph/store.py`; every skip is counted,
and out-of-scope is never counted as loss.

### `graph/` — the only home of SQL
| Module | Entry points | Notes |
|---|---|---|
| `schema.sql` | applied by `init_schema` | Idempotent DDL. `edges` keyed on `(src, dst, kind)`. |
| `store.py` | `upsert_nodes`, `upsert_edges`, `get_node`, `neighbors`, `record_ingest_run` | Every write is an upsert. |
| `traverse.py` | `traverse`, `chains`, `Hop` | Recursive CTE over simple paths up to `max_depth`; returns the cheapest route per node. `node_budget` caps the rows returned, not the work done to find them. |

**Invariant:** no SQL anywhere else; no string-built SQL here.

### `retrieval/` — what the ablation table measures
`embed.py`: `chunk_text`, `embed_nodes`, the `Encoder` protocol, `StubEncoder` for tests,
`load_encoder` as the only place real weights load. Vector search, BM25, fusion, and
reranking are planned.

**Invariant:** no LangChain or LangGraph imports. **Known violation:** `embed_nodes` writes
`node_chunks`, though retrieval is meant to be read-only. It belongs in `ingest/`.

### `eval/`
`metrics.py`: `recall_at_k`, `mrr`, `path_correct`, `citation_coverage` — pure functions over
`(predicted, gold)`. The harness, the config matrix, and the frozen holdout are planned.

## Cross-cutting concerns

- **Provenance.** Every ingest writes an `ingest_runs` row with source, version and sha256,
  and every fetch writes a `data/manifest.json` entry. A number that cannot be traced to its
  snapshot cannot be published.
- **Errors.** Ingestion is tolerant: it logs, skips, and counts. Query time is strict: an
  id that does not resolve fails loudly (`threatlens show` exits 1), and a dangling edge is a
  bug in our code, not a data problem. `traverse` itself returns nothing for an unknown
  anchor, so callers check with `get_node` first.
- **Logging.** `logging`, never `print`, outside `cli.py`'s user-facing output.
- **Testing.** Unit tests never touch the network, a database, or model weights —
  `conftest.py` blocks sockets. Integration tests run against real pgvector, in CI too.
- **Determinism.** Configs A–D are LLM-free and must produce identical output for identical
  input. Only the planned agent loop (config E) is allowed to vary.

## Not built yet

`llm/` (provider seam over LangChain `init_chat_model`), `agent/` (LangGraph loop),
`report/` (Markdown rendering), the eval harness, and the frozen holdout. Status lives in
[docs/phases/phases.md](docs/phases/phases.md).
