# Architecture

## Shape

```
                    ┌──────────────────────────────────────────┐
  snapshots         │  Postgres 16 + pgvector                  │
  (data/, offline)  │                                          │
  ┌──────────────┐  │   nodes ── embedding vector(384)         │
  │ ATT&CK STIX  │─▶│   node_chunks ── embedding vector(384)   │
  │ NVD CVEs     │─▶│   edges  ── weighted, typed              │
  │ CVE→ATT&CK   │─▶│                                          │
  └──────────────┘  └──────────────────────────────────────────┘
      ingest/                     │  graph/store.py
                                  ▼
                       ┌──────────────────────┐
                       │ retrieval/pipeline   │
                       │ 1 anchor resolve     │
                       │ 2 graph traverse     │◀── the core
                       │ 3 hybrid retrieve    │
                       │ 4 RRF + rerank       │
                       └──────────┬───────────┘
                                  ▼
                       ┌──────────────────────┐
                       │ agent/loop.py        │  Claude decides:
                       │ tools = retrieval fns│  "traverse further, or answer?"
                       └──────────┬───────────┘
                                  ▼
                   cli.py  ──▶  report/markdown.py
```

Ingestion is **offline and one-shot**. Query time touches nothing but Postgres and the
Anthropic API.

## Module boundaries

| Module | Owns | Must not |
|---|---|---|
| `ingest/` | Network I/O, parsing, writing nodes/edges | Be imported by query-time code |
| `graph/` | SQL, schema, traversal CTEs | Know about embeddings or LLMs |
| `retrieval/` | Ranking, fusion, embeddings | Write to the database |
| `llm/` | Provider protocol + vendor adapters | Know about the graph, retrieval, or prompts |
| `agent/` | Tool definitions, the loop, prompts | Contain SQL, ranking logic, or a vendor SDK import |
| `report/` | Markdown rendering | Call the LLM or the DB |
| `eval/` | Harness, metrics, config matrix | Be imported by `retrieval/` or `agent/` |

`retrieval/` is pure read. If a retrieval function needs to write, that is a design error —
move it to `ingest/`.

## Data flow at query time

1. `cli.ask(question)` → `agent.loop.run(question)`
2. Agent calls tool `resolve_anchor(text)` → `retrieval.pipeline.resolve` → node ids
3. Agent calls tool `traverse(node_id, depth, edge_kinds)` → `graph.traverse` → subgraph
4. Agent calls tool `retrieve_text(node_ids, query)` → hybrid + RRF + rerank → evidence
5. Agent decides: enough evidence → generate; not enough → back to step 3
6. Generation emits claims each tagged with a node id
7. `report.markdown` renders the answer + attack path + citation table

## Key design constraints

**One store, not two.** Postgres holds the graph *and* the vectors. A single query can
filter by graph structure and then rank by cosine similarity. Neo4j would split this into
two systems and two round trips — see [decisions.md](decisions.md) D2.

**The subgraph is bounded.** Traversal always has a depth cap and a node budget. An
unbounded traversal from a hub technique returns most of ATT&CK and blows the context
window. Defaults live in `config.py`.

**Chunk-level embeddings, node-level scores.** `bge-small` truncates at 512 tokens; several
technique descriptions exceed that. Text is chunked into `node_chunks`; a node's similarity
is the max over its chunks. See [decisions.md](decisions.md) D6.

**The agent drives retrieval, not generation shape.** The LLM chooses *what to retrieve
next*. It does not get to invent facts — the generation step is constrained to the evidence
set assembled by the tools.
