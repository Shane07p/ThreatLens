# AGENTS.md — src/threatlens/retrieval/

Adds to the root [AGENTS.md](../../../AGENTS.md). Background:
[docs/design/retrieval.md](../../../docs/design/retrieval.md) and
[docs/design/evaluation.md](../../../docs/design/evaluation.md).

Everything here is what the ablation table measures, so it is hand-written on purpose.

## Rules

- **No LangChain or LangGraph imports.** A library's fusion or retriever would make the table
  measure that library instead of this design. `TestNoLangchainImport` enforces it.
- **One component per configuration.** Configs A–D each differ from the previous one by
  exactly one change, or the table proves nothing.
- **Keep the baseline fair.** Config A queries with the CVE *description*, never its id, and
  does not filter non-technique nodes out of the ranking. A weakened strawman inflates every
  later row.
- **Fuse ranks, not scores.** RRF is `1 / (k + rank)` with `k = 60`. Dense cosine and BM25
  scores are not comparable, and normalising them to look comparable hides bugs.
- **Build indexes once.** Rebuilding BM25 or reloading model weights per query is the obvious
  performance trap.
- **Retrieval reads, it does not write.** `embed.py` currently writes `node_chunks` from
  this directory, which breaks that rule. It belongs in `ingest/`; until it moves, do not
  add a second writer here.

## Testing

Unit tests use `StubEncoder` and never load real weights. Nearest-neighbour tests need
hand-written vectors — the stub's vectors all lie in the positive orthant, so they cannot
discriminate a nearest neighbour.
