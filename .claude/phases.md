# Phase plan

Eight phases, mapped from the spec's 8-week sequence, with the phase-1–3 data guide folded
in. One phase per doc. Status here is the source of truth.

| # | Phase | Deliverable | Status |
|---|---|---|---|
| 1 | [ATT&CK ingestion](phase-1-attack-ingestion.md) | ATT&CK graph in Postgres, verified by hand. No AI. | not started |
| 2 | [CVE bridge](phase-2-cve-bridge.md) | CVEs + `ENABLES` edges + **frozen holdout** + metric definitions | not started |
| 3 | [Naive baseline](phase-3-baseline.md) | Vector-only RAG + **row A measured** | not started |
| 4 | [Graph retrieval](phase-4-graph-retrieval.md) | Traversal + hybrid + RRF + reranker | not started |
| 5 | [Evaluation](phase-5-evaluation.md) | Full harness, rows A–D, ablation table | not started |
| 6 | [Agent](phase-6-agent.md) | Agentic re-query loop, grounded generation, row E | not started |
| 7 | [CLI + report](phase-7-cli-report.md) | `threatlens ask`, Markdown report, subgraph viz | not started |
| 8 | [Release](phase-8-release.md) | README with the table, demo, related work, limitations | not started |

Update the status column as phases land. A phase is only "done" when its done-when list is
fully checked and its tests pass.

## What changed from the original 8-week sequence

Five substantive changes. Full reasoning in [decisions.md](decisions.md).

1. **Holdout split moves earlier — into Phase 2, before any retrieval code.** The data guide
   already says this; the spec's week-5 placement conflicts with it. Earlier wins: the split
   cannot be influenced by anything you learn while building the retriever. (D4)

2. **Metric definitions land in Phase 2, a minimal harness in Phase 3.** The baseline number
   must come out of the same code path as rows C–E. Measuring row A with throwaway code and
   comparing it to harness output in week 5 is not a comparison. (D4)

3. **NVD ingestion is scoped, not exhaustive.** Only mapped CVEs + KEV + an optional recent
   window. Pulling all 250k CVEs makes the naive-RAG baseline look bad for the wrong reason
   and slows every config equally. (D3)

4. **`CHAINS_TO` gets a concrete, defensible definition in Phase 4** — actor co-occurrence
   with a ≥3 support threshold and kill-chain direction — rather than being left as
   "techniques commonly used together." (D5)

5. **Four data-parsing corrections are baked into Phase 1** rather than discovered at
   runtime: ATT&CK ids live in `external_references`; technique→tactic comes from
   `kill_chain_phases`, not a relationship object; revoked/deprecated objects must be
   filtered; the collection version must be recorded. Following the guide literally produces
   a graph with zero tactic edges. (D7–D10)

Plus one environment change throughout: `uv add`, never
`pip install --break-system-packages`. (D1)

## Protect vs cut

**Protect — this is the project:**
- Graph traversal / multi-hop retrieval (Phase 4)
- The eval ablation table (Phase 5)

Everything else is negotiable. These two are what make it deep, retrieval-first, and
credible.

**Cut in this order if time runs short:**
1. Web UI (already out of scope for v1)
2. Attack-path visualization (Phase 7)
3. Sigma / D3FEND enrichment (v1.5)
4. Agentic loop (Phase 6) — degrade to a fixed traversal pipeline; row E becomes "not run"
5. Second data source

Even the minimal version — graph + traversal retrieval + eval table — is a strong, honest
project. A finished Phase 5 with no Phase 6 beats a half-built agent with no numbers.

## Working rhythm

Each phase doc ends with a **done-when** checklist and the tests that must pass. Do not
start the next phase with a red suite; the phases compound, and a wrong edge in Phase 1
becomes a wrong ablation table in Phase 5.
