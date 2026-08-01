# Phase 3 — Naive vector RAG baseline

**Status:** not started
**Goal:** the number every later claim is measured against.

This phase deliberately builds the weaker system. **Row A of the ablation table is the
deliverable** — not the code.

## Steps

1. **Deps.** `uv add sentence-transformers pgvector`

2. **Embed.** `BAAI/bge-small-en-v1.5`, 384 dims, CPU, MIT licensed, ~33M params.

   Chunk before embedding — the model truncates at 512 tokens and several technique
   descriptions exceed it ([decisions.md](decisions.md) D6). Write chunks to `node_chunks`,
   embed each, index with HNSW cosine.

   ```python
   from sentence_transformers import SentenceTransformer
   model = SentenceTransformer("BAAI/bge-small-en-v1.5")
   emb = model.encode(chunk_text)     # (384,)
   ```

   Embed the text for every node kind: techniques, CVEs, mitigations, actors, software.
   Batch the encode calls; one call per chunk is an hour instead of minutes.

3. **Bare top-k search.** `retrieval/vector.py`:
   ```sql
   SELECT node_id, 1 - (embedding <=> %(q)s) AS sim
   FROM node_chunks ORDER BY embedding <=> %(q)s LIMIT %(k)s;
   ```
   Aggregate to node level by max similarity. **No graph traversal. No BM25. No reranking.**
   That is the point — this row is the strawman, and it must be a fair strawman.

4. **Minimal harness.** `eval/harness.py` + `eval/configs.py` with config `A` only. It uses
   the metric functions written in Phase 2 and emits the same result JSON that Phase 5 will
   emit for configs B–E. Same code path, or the comparison is meaningless
   ([decisions.md](decisions.md) D4).

5. **Measure row A against the holdout, and record it.**
   ```bash
   uv run threatlens eval --config A --eval-mode
   ```
   Writes `eval_results/<timestamp>.json` with git sha, config values, ATT&CK version,
   mappings snapshot date, per-query results, and aggregates. Paste the aggregates into
   [evaluation.md](evaluation.md) row A.

6. **Optional but useful:** wire the top-k results straight into a single LLM call for a
   qualitative answer. Not required for the number, and it costs tokens — the retrieval
   metrics are LLM-free by design.

## What "correct" means for row A

The query is the CVE description (not the CVE id — matching an id string is not retrieval).
A hit is: the gold technique appears in the top-k *technique* nodes returned. Non-technique
nodes are not filtered out of the ranking; filtering them would quietly make the baseline
stronger than naive RAG actually is.

## Expected outcome

Row A should look mediocre. That is the finding, not a bug — the published result this
project cites (CyKG-RAG) is precisely that flat vector RAG cannot represent structure. If
row A comes out very high, check for leakage first: is the holdout `ENABLES` edge excluded,
and is the CVE description accidentally quoting the technique name verbatim?

## Tests that must pass

- `tests/integration/test_vector_search.py` — planted nearest neighbour is returned
- chunking: a >512-token description produces >1 chunk, and its tail text is retrievable
- `tests/unit/` metric tests still green
- embedding is deterministic for the same input (same model, same text → same vector)

```bash
uv run pytest -m "not eval"
```

## Done when

- [ ] Every node with text has ≥1 embedded chunk
- [ ] HNSW index exists and is used (check `EXPLAIN`)
- [ ] `threatlens eval --config A --eval-mode` runs end to end on the full holdout
- [ ] Row A of the ablation table in [evaluation.md](evaluation.md) is filled with real
      numbers **and** n + confidence interval
- [ ] The result JSON records git sha, config, and data versions
- [ ] `uv run pytest -m "not eval"` is green

## Do not

Do not tune the baseline to look better. Do not tune it to look worse. Whatever it scores is
the number.

## Next

[Phase 4 — Graph retrieval](phase-4-graph-retrieval.md)
