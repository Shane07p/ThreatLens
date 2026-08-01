# ThreatLens

A Graph-RAG threat-intelligence agent. Give it a security finding — a CVE, an ATT&CK
technique, a plain-English question — and it traces the whole picture: what the attack is,
how it's exploited, what an attacker does next, who uses it, and how to defend. Every claim
carries a citation.

> **Status: in development.** The knowledge graph, retrieval pipeline, and evaluation
> harness are being built in phases. No results to report yet — this README will carry the
> ablation table when there is one.

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
Explorer · `bge-small-en-v1.5` embeddings · BM25 + RRF + cross-encoder reranking · Anthropic
SDK · Typer

## Quick start

Needs Python 3.12, [uv](https://docs.astral.sh/uv/), and Docker.

```bash
git clone https://github.com/Shane07p/ThreatLens.git
cd ThreatLens

uv sync --all-groups           # or: pip install -r requirements.txt
cp .env.example .env           # then fill in NVD_API_KEY and one LLM provider key

docker compose up -d db        # Postgres 16 + pgvector
uv run threatlens db init      # create the schema

uv run pytest -m "not eval"    # verify the setup
```

Then fetch the data snapshots and build the graph:

```bash
uv run threatlens fetch attack     # MITRE ATT&CK STIX bundle
uv run threatlens fetch mappings   # CVE→ATT&CK mappings
uv run threatlens fetch nvd        # CVE records (scoped, not the full NVD)

uv run threatlens ingest attack
uv run threatlens ingest cves
uv run threatlens ingest mappings
uv run threatlens stats            # sanity-check the graph
```

Full setup notes — API keys, provider selection, troubleshooting — are in
[.claude/setup.md](.claude/setup.md). The build plan is in
[.claude/phases.md](.claude/phases.md).

> Commands beyond `db init` land as their phases are implemented. See
> [.claude/phases.md](.claude/phases.md) for current status.

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

- [.claude/](.claude/) — architecture, graph schema, data sources, retrieval design,
  evaluation protocol, testing strategy, and the eight-phase build plan
- [.claude/decisions.md](.claude/decisions.md) — every  deviation from the source spec, with reasons

## Attribution

MITRE ATT&CK® is a registered trademark of The MITRE Corporation. Data from MITRE ATT&CK,
the NIST National Vulnerability Database, and the Center for Threat-Informed Defense
Mappings Explorer, used under their respective terms.
