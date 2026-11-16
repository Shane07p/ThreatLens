# Phase 5 — Evaluation

**Status:** not started
**Goal:** the ablation table, filled with real measured numbers.

This is when the project stops being a toy. Protect this phase; cut Phase 6 before cutting
this.

Protocol and metric definitions are in [evaluation.md](../design/evaluation.md); this doc is the build
order.

## Steps

1. **Complete the harness** — `eval/harness.py`. Phase 3 shipped a minimal version for row
   A; extend it to run every config in `eval/configs.py` over the holdout and emit one
   result JSON per run.

   Every run records: git sha, every value from `config.py`, ATT&CK version, mappings
   snapshot date, per-query results (predicted ranking, gold, latency, tool calls, tokens),
   and the aggregate table. A number without that metadata cannot go in a README.

2. **Metrics.** Already defined in Phase 2. Now wire `path_correct` — did the returned path
   actually traverse `cve → technique → tactic`, not just surface the right node? Node
   recall alone does not demonstrate multi-hop retrieval; the path does.

3. **Confidence intervals.** ~160 holdout CVEs is small. Report a 95% Wilson interval on
   every proportion. A 6-point gap at n=160 may not be a gap, and claiming it is will not
   survive scrutiny.

4. **Run the matrix.**
   ```bash
   uv run threatlens eval --all --eval-mode --md
   ```
   Fill rows A–D in [evaluation.md](../design/evaluation.md). Row E waits for Phase 6.

5. **Read the failures.** Sample 20 queries where config D missed and classify:
   - anchor resolution failed (no entry node found)
   - traversal reached the technique but ranking buried it
   - the gold technique is genuinely absent from the subgraph
   - the mapping label is arguable

   That classification is worth more in the README than another point of recall — it shows
   you understand your own system's failure modes.

6. **Latency + cost.** Report p50/p95 per config and where time goes (embed / SQL / rerank).
   If the reranker is 80% of latency, say so.

7. **Groundedness, layer 1.** Structural citation checking is deterministic and free — run
   it on every config that generates text. It must be 1.0.

## Expected shape

The headline claim is `A → D`. If C (graph traversal) does not beat B (hybrid, no graph),
stop and investigate before proceeding:
- Is the holdout `ENABLES` edge actually excluded under `--eval-mode`? (If not, C is
  inflated.)
- Is anchor resolution finding the CVE node at all? (If not, C degenerates to B.)
- Is `node_budget` truncating before the gold technique is reached?

An honest negative result is publishable. A result you cannot explain is not.

## Tests that must pass

- Harness produces identical output on two runs of the same config (retrieval is
  deterministic; assert it)
- Every config emits a metrics dict with no `None`s
- Holdout checksum test still passes
- `test_holdout_only_read_by_eval_module` still passes

```bash
uv run pytest -m "not eval"
```

## Done when

- [ ] All configs A–D measured over the full holdout
- [ ] Rows A–D of the ablation table filled with real numbers, n, and CIs
- [ ] `path_correct` implemented and reported for C and D
- [ ] Latency p50/p95 and component breakdown recorded
- [ ] Structural groundedness = 1.0
- [ ] 20-query failure analysis written up
- [ ] Result JSONs committed under `eval_results/`
- [ ] Reruns are reproducible from the recorded metadata

## Next

[Phase 6 — Agent](phase-6-agent.md)
