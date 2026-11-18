# Evaluation

The credibility core. The headline claim the project exists to support:

> *"Naive vector RAG retrieved the correct technique X% of the time; adding graph traversal
> and reranking took it to Y%."*

Without a measured X and Y this is a demo, not a project.

## Ground truth

The CVE→ATT&CK mappings dataset provides labelled `CVE → technique(s)` links. Split
**80 / 20** at the end of Phase 2, before any retrieval code exists.

`data/eval/holdout.jsonl`, one line per CVE:

```json
{"cve": "CVE-2021-44228", "techniques": ["T1190", "T1059"], "primary": ["T1190"], "split": "holdout"}
```

Rules, non-negotiable:
1. Split with a **fixed seed**, write the file, commit it. Never regenerate.
2. Holdout CVEs still exist as nodes; only their `ENABLES` edges are excluded from the graph
   under `--eval-mode`. Leaving them in is label leakage — the traversal would read the
   answer straight off the edge it is being scored on.
3. Nothing outside `src/threatlens/eval/` may open this file. Enforced by a test.
4. `dev.jsonl` (the 80%) is the only set used for tuning.

Ground truth is every technique in any of the four mapping columns (decisions.md D21):
**822 CVEs and 1,682 CVE→technique pairs**, so the holdout is about **164 CVEs**. Each
holdout technique keeps the column it came from, so every number can also be reported on
the impact-only subset (373 CVEs) as a robustness check. Small either way. **Report n and a
95% Wilson interval on every accuracy number.** A 6-point gap on n=164 may not be a gap.

## Two tasks, two tables

The evaluation measures two different things, and they are never mixed in one table
(decisions.md D22).

**Table 1 — link prediction.** Given a held-out CVE's description, rank the ATT&CK
techniques it enables. Under `--eval-mode` the CVE's `ENABLES` edges are gone, so no
configuration can read the answer off the graph; graph configurations may only use the
graph to expand and re-rank candidates the text retrieval proposed. Scored with `recall@k`
and `mrr` against the holdout labels. This table carries the headline number.

**Table 2 — answering over known links.** Given a question about a CVE whose links are in
the graph, return the chain (technique → tactic → mitigation, and the actors that use the
technique) with citations. Scored with `path_correct` and `groundedness`. This measures
whether the answer is complete and checkable, not whether a missing link can be guessed.

Held constant across every row of a table: the query text and the anchor-resolution step.
A row changes exactly one component, so a gap can be attributed to that component alone.
Both a naive vector baseline and a strong technique-filtered one are reported, so the graph
is compared with the best text-only system, not only the weakest.

## Metrics

| Metric | Definition | Where |
|---|---|---|
| `recall@k` | fraction of holdout CVEs whose correct technique appears in top-k retrieved (k = 1, 3, 5) | `eval/metrics.py` |
| `mrr` | mean reciprocal rank of the first correct technique | `eval/metrics.py` |
| `path_correct` | did the returned path traverse the true CVE→technique→tactic chain | `eval/metrics.py` |
| `groundedness` | fraction of generated claims with a resolvable citation. Target: 1.0 | `eval/metrics.py` |
| `latency_p50/p95` | wall clock, seconds, per query | harness |
| `tokens_in/out` | per query, from `response.usage` | harness |

Retrieval metrics are **deterministic** — no LLM in the loop. Only groundedness and answer
quality need a model, which is why they run under a separate `-m eval` marker.

## The ablation table

Configs are defined once in `eval/configs.py` and share the same pipeline entry point, so
every row differs by exactly one component. The table below is laid out for Table 1; Table
2 uses the same rows with its own metrics:

| # | Configuration | recall@1 | recall@5 | MRR | path_correct | groundedness | p50 latency |
|---|---|---|---|---|---|---|---|
| A | Vector search only (naive RAG baseline) | | | — | — | | |
| B | + BM25 hybrid (RRF) | | | | — | | |
| C | + graph traversal (GraphRAG) | | | | | | |
| D | + cross-encoder reranking | | | | | | |
| E | + agentic re-query (full system) | | | | | | |

Fill with real measured numbers. An empty cell is honest; a guessed cell is fraud.

**One LLM provider per table.** Configs A–D are LLM-free; any row that uses an LLM uses the
same provider and model as every other row in that table. Mixing providers across rows
confounds the comparison. Provider is a separate axis — compare providers by running the
whole table again.

**Row A must be measured in Phase 3, not Phase 5.** It is the number everything else is
compared against, and it must be produced by the same harness that produces C, D, E or the
comparison is meaningless. This is why the metric definitions and holdout format land in
Phase 2 and a minimal runner lands in Phase 3 — see [decisions.md](decisions.md) D4.

## Running it

```bash
uv run threatlens eval --config A          # one row
uv run threatlens eval --all               # all rows → eval_results/<timestamp>.json
uv run threatlens eval --all --md          # also emit the markdown table for the README
```

Each run writes: git sha, config values from `config.py`, ATT&CK version, mappings snapshot
date, per-query results, and the aggregate table. A number without that metadata cannot be
put in a README.

## Groundedness

Two layers, cheap first:

1. **Structural (free, deterministic):** every citation marker in the answer resolves to a
   node id in the evidence set. Runs in the fast test suite.
2. **Semantic (LLM, `-m eval`):** does the cited node actually support the claim? A judge
   prompt over a sample of ~50 answers. Optionally RAGAS faithfulness for a second opinion.

Layer 1 must be 1.0 always. Layer 2 is reported as a percentage with the sample size.

## Honest reporting

State in the README:
- The dataset size and the holdout size.
- That `CHAINS_TO` is a co-occurrence heuristic, not observed attack sequences.
- That the mappings dataset covers CISA KEV CVEs, so results generalize to
  *known-exploited* vulnerabilities, not all CVEs.
- Which ATT&CK version and mappings snapshot the numbers were produced against.
- Related work by name — CyKG-RAG, the IEEE GraphRAG-CTI dataset, Minerva — and what is
  ours (a well-built, well-evaluated, usable tool) versus prior art (the general approach).
