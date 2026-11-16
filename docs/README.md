# ThreatLens documentation

Everything here is plain Markdown so that people and coding agents read the same source.
Agents get a short summary of the rules in [AGENTS.md](../AGENTS.md) and read these files on
demand rather than loading all of them into every session.

| Folder | Holds | Changes when |
|---|---|---|
| [design/](design/) | How the system works and why | the design changes |
| [phases/](phases/phases.md) | The build plan, one doc per phase, with done-when checklists | a phase starts or finishes |
| [conventions/](conventions/) | How we write code, tests, and commits | a rule is added or retired |
| [spec.md](spec.md) | The original spec of record | never — deviations go in [decisions.md](design/decisions.md) |
| [superpowers/](superpowers/) | Dated implementation plans from Phase 1 | never — historical record |

## Design

| Doc | What's in it |
|---|---|
| [architecture.md](design/architecture.md) | The target system shape, including parts not built yet. For the code as it is today, see [ARCHITECTURE.md](../ARCHITECTURE.md) |
| [graph-schema.md](design/graph-schema.md) | Node and edge model, DDL, traversal SQL, STIX gotchas |
| [data-sources.md](design/data-sources.md) | Every upstream source, its exact URL, what to pull and skip |
| [retrieval.md](design/retrieval.md) | The retrieval pipeline: anchors, traversal, hybrid search, fusion, reranking |
| [evaluation.md](design/evaluation.md) | Metrics, the ablation table, the holdout protocol |
| [decisions.md](design/decisions.md) | Every deviation from the spec, with the evidence behind it |

## Conventions

| Doc | What's in it |
|---|---|
| [code.md](conventions/code.md) | Simplicity, module boundaries, naming, errors, comments, docstrings |
| [testing.md](conventions/testing.md) | Test layers, markers, how to add tests, what not to test |
| [workflow.md](conventions/workflow.md) | Git, branching, repository visibility, CI, data, secrets, working style |
| [setup.md](conventions/setup.md) | Local environment, Postgres, environment variables, model weights |

## Phases

| Phase | Deliverable |
|---|---|
| [1](phases/phase-1-attack-ingestion.md) | ATT&CK graph in Postgres. No AI. |
| [2](phases/phase-2-cve-bridge.md) | CVEs, `ENABLES` edges, and the **frozen holdout** |
| [3](phases/phase-3-baseline.md) | Naive vector RAG and **row A of the ablation table** |
| [4](phases/phase-4-graph-retrieval.md) | Traversal, hybrid retrieval, RRF, reranking |
| [5](phases/phase-5-evaluation.md) | Full evaluation harness, rows A–D |
| [6](phases/phase-6-agent.md) | Agentic re-query loop, grounded generation, row E |
| [7](phases/phase-7-cli-report.md) | CLI polish and the Markdown report |
| [8](phases/phase-8-release.md) | Release: README, related work, honest limitations |

[phases.md](phases/phases.md) holds the master plan, the cut list, and current status.

## Reading order for someone new

1. [README.md](../README.md), then [ARCHITECTURE.md](../ARCHITECTURE.md)
2. [conventions/code.md](conventions/code.md) and [conventions/testing.md](conventions/testing.md)
3. [phases.md](phases/phases.md) to find the current phase, then that phase's doc
4. [decisions.md](design/decisions.md) whenever something seems to contradict the spec

## Keeping these docs useful

- Update the doc in the same pull request as the change it describes. A doc that lags the
  code is worse than no doc, because it is believed.
- Record *why*, with the evidence: the measured number, the failing test, the upstream
  change. A rule without a reason gets worked around.
- Prefer names over line links. `traverse()` survives a refactor; `traverse.py#L42` does not.
