# Phase 4 — Graph retrieval

**Status:** not started
**Goal:** the real retriever. Traversal + hybrid + RRF + cross-encoder rerank.

This is the deep core of the project. Protect it; cut other things first.

Design detail lives in [retrieval.md](../design/retrieval.md); this doc is the build order.

## Steps

1. **Deps.** `uv add rank-bm25`

2. **`CHAINS_TO` derivation** — `ingest/chains.py`. Actor co-occurrence, ≥3 shared actors,
   directed by kill-chain phase order, weight = normalized shared-actor count. SQL is in
   [graph-schema.md](../design/graph-schema.md); reasoning in [decisions.md](../design/decisions.md) D5.

   Build `tactic_order` (14 shortnames → index) as a static table. A technique in multiple
   tactics takes its lowest index.

   Then look at the output. Spot-check 10 pairs — do they read like plausible attack
   progressions? If most are noise, the threshold is too low.

3. **Anchor resolution** — `retrieval/pipeline.resolve`. Regex for `CVE-…`, `T####`,
   `M####`, `G####`; exact name match; vector fallback with a similarity floor. Zero anchors
   is a legitimate result.

4. **Traversal** — `graph/traverse.py`, the recursive CTE from
   [graph-schema.md](../design/graph-schema.md).
   - Cycle guard is mandatory (`NOT dst = ANY(path)`). Without it the query never returns.
   - `max_depth=3`, `node_budget=200`, both from `config.py`.
   - Direction-aware: `USES` is walked backwards from technique to actor, so the API takes
     `(kind, direction)` pairs.
   - Return nodes, the edges among them, **and the shortest path from each node to an
     anchor**. The path is evidence, not debug output.

5. **Hybrid retrieval scoped to the subgraph** — dense over `node_chunks` restricted to
   subgraph node ids, plus BM25 over the same restricted set. Build the BM25 index once at
   startup and cache it; rebuilding per query is the obvious performance trap.

6. **RRF fusion** — `1/(k + rank)`, k=60, over *ranks* not scores. Dense cosine and BM25
   scores are not comparable; normalizing them is a silent-bug factory.

7. **Cross-encoder rerank** — `BAAI/bge-reranker-base` over the top ~50 fused candidates,
   keep top 12. Cache by `(query, node_id)`. This is the slowest CPU component in the
   system — measure its share of p50 latency and report it.

8. **Configs B, C, D** in `eval/configs.py`, each differing from the previous by exactly one
   component:

   | Config | Anchor | Traversal | Dense | BM25 | RRF | Rerank |
   |---|---|---|---|---|---|---|
   | A | vector only | — | ✅ | — | — | — |
   | B | vector only | — | ✅ | ✅ | ✅ | — |
   | C | regex + vector | ✅ | ✅ | ✅ | ✅ | — |
   | D | regex + vector | ✅ | ✅ | ✅ | ✅ | ✅ |

   One variable per row, or the table proves nothing.

## Tests that must pass

- `test_chains_derivation.py` — threshold, direction, no self-loops
- `test_fusion.py` — RRF table-driven, deterministic tie-breaks
- `test_traversal.py` — terminates on a cycle (with `pytest.mark.timeout(10)`), honours
  depth and budget, returns the expected `cve → technique → tactic` path
- rerank ordering test — assert relative order, never float values
- `test_pipeline_end_to_end.py` — each config runs on the mini fixture graph

```bash
uv run pytest -m "not eval"
```

## Done when

- [ ] `CHAINS_TO` edges exist, spot-checked, threshold documented
- [ ] Traversal is bounded, cycle-safe, direction-aware, and returns paths
- [ ] BM25 index built once and cached
- [ ] RRF operates on ranks with k=60
- [ ] Reranker runs on CPU within an acceptable latency budget
- [ ] Configs B, C, D all execute end to end
- [ ] `uv run pytest -m "not eval"` is green

## Next

[Phase 5 — Evaluation](phase-5-evaluation.md)
