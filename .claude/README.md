# ThreatLens working docs

Index of the docs in this folder.

> `CLAUDE.md` at the repo root is the short version of the working rules, but it is
> **local-only and not tracked in git** — it will not appear in a fresh clone.

## Reference

| Doc | What's in it |
|---|---|
| [architecture.md](architecture.md) | System shape, module boundaries, data flow |
| [graph-schema.md](graph-schema.md) | Node/edge model, SQL DDL, traversal queries |
| [data-sources.md](data-sources.md) | Every source, exact URL, what to pull, what to skip |
| [retrieval.md](retrieval.md) | The 6-stage pipeline, fusion, reranking, agent loop |
| [evaluation.md](evaluation.md) | Metrics, the ablation table, holdout protocol |
| [testing.md](testing.md) | Test strategy, layout, markers, fixtures, CI gates |
| [setup.md](setup.md) | Local environment, Postgres, env vars, API keys |
| [conventions.md](conventions.md) | Code style, naming, error handling, logging |
| [decisions.md](decisions.md) | Deviations from the two spec docs, with reasons |

## Phases

Build order. Each phase doc has: goal, steps, deliverable, done-when, and the tests that
must pass before moving on.

| Phase | Doc | Deliverable |
|---|---|---|
| 1 | [phase-1-attack-ingestion.md](phase-1-attack-ingestion.md) | ATT&CK graph in Postgres. No AI. |
| 2 | [phase-2-cve-bridge.md](phase-2-cve-bridge.md) | CVEs + `ENABLES` edges + **frozen holdout** |
| 3 | [phase-3-baseline.md](phase-3-baseline.md) | Naive vector RAG + **row A of the ablation table** |
| 4 | [phase-4-graph-retrieval.md](phase-4-graph-retrieval.md) | Traversal + hybrid + RRF + reranker |
| 5 | [phase-5-evaluation.md](phase-5-evaluation.md) | Full eval harness, rows A–D |
| 6 | [phase-6-agent.md](phase-6-agent.md) | Agentic re-query loop, grounded generation, row E |
| 7 | [phase-7-cli-report.md](phase-7-cli-report.md) | CLI polish, Markdown report, subgraph viz |
| 8 | [phase-8-release.md](phase-8-release.md) | README, related work, honest limitations |

See [phases.md](phases.md) for the master plan, the cut list, and what changed from the
original 8-week sequence.

## Reading order for a new session

1. [conventions.md](conventions.md) and [setup.md](setup.md) — the working rules
2. [phases.md](phases.md) — find the current phase
3. That phase's doc
4. [decisions.md](decisions.md) if anything looks like it contradicts the spec
