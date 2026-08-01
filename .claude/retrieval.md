# Retrieval pipeline

Six stages. Stage 2 is the differentiator — it is the thing naive vector RAG cannot do.

## Stage 1 — Anchor resolution

Find the entry node(s) for a question.

- Regex first: `CVE-\d{4}-\d{4,}` → `cve:<id>`; `T\d{4}(\.\d{3})?` → `technique:<id>`;
  `M\d{4}` → mitigation; `G\d{4}` → actor.
- Exact name match on `nodes.name` (case-folded).
- Fallback: vector search over `node_chunks`, top-k, keep nodes above a similarity floor.

Return up to `MAX_ANCHORS` (default 3). Zero anchors is a real outcome — say
"no matching entity" rather than hallucinating one.

## Stage 2 — Graph traversal (the core)

`graph/traverse.py`, backed by the recursive CTE in [graph-schema.md](graph-schema.md).

Default expansion from a CVE anchor:

```
cve --ENABLES--> technique --BELONGS_TO--> tactic
                 technique --MITIGATED_BY--> mitigation
                 technique <--USES-- actor
                 technique --CHAINS_TO--> technique  (depth-limited)
```

Bounded by `max_depth=3` and `node_budget=200`. The traversal is direction-aware: `USES` is
traversed backwards from a technique to reach actors, so the traversal API takes
`(kind, direction)` pairs, not bare kind strings.

Output: a subgraph — node ids, the edges between them, and the shortest path from each node
back to an anchor. **The path is part of the evidence**, not a debugging artifact — it is
what the answer's "attack path" section renders and what multi-hop correctness is scored on.

## Stage 3 — Hybrid text retrieval

For nodes in the subgraph, retrieve supporting text.

- **Dense:** `bge-small-en-v1.5`, cosine over `node_chunks`, restricted to subgraph node ids.
  Node score = max over its chunks.
- **Lexical:** `rank-bm25` over the same restricted set. The index is built once at startup
  from the node/chunk corpus and cached — rebuilding per query is the obvious performance
  trap.

Both are scoped to the subgraph. That scoping is *why* graph retrieval helps: it removes
lexically-similar-but-structurally-irrelevant nodes from contention before ranking.

## Stage 4 — Fusion + reranking

**Reciprocal Rank Fusion** over the dense and lexical rankings:

```
RRF(d) = Σ_r  1 / (k + rank_r(d))       k = 60
```

RRF over ranks, not scores — dense cosine and BM25 scores are not comparable and
normalizing them is a source of silent bugs.

Then **cross-encoder rerank** the top ~50 fused candidates with `bge-reranker-base`, keep
top-N (default 12) as the evidence set. The reranker is the slowest CPU component; cap the
candidate count and cache by `(query, node_id)`.

## Stage 5 — Agentic loop

`agent/loop.py`. Claude drives what to retrieve next.

Tools exposed to the model:

| Tool | Input | Returns |
|---|---|---|
| `resolve_anchor` | free text | candidate node ids + names + kinds |
| `traverse` | node_id, edge kinds, depth | subgraph nodes + edges + paths |
| `retrieve_text` | node_ids, query | ranked evidence passages with node ids |
| `get_node` | node_id | full record + source_url |

The loop talks to `llm.Provider`, never to a vendor SDK (see
[decisions.md](decisions.md) D14):

```python
provider = llm.registry.get(settings.provider)      # anthropic | openai | gemini | groq | ...
resp = provider.complete(messages=messages, tools=TOOLS)
# resp: .text, .tool_calls, .usage, .stop_reason  — normalized across providers
```

Rules:
- Cap iterations (`MAX_AGENT_STEPS`, default 8). An uncapped loop is a billing incident.
- Append the full assistant turn back to `messages`, not just the text — dropping tool-call
  blocks breaks the conversation on every provider.
- Return all tool results for one assistant turn in a **single** user message.
- Handle a refusal stop reason before reading content. On Anthropic this is a normal HTTP
  200, not an exception; this is a security-adjacent domain and it will happen.

Provider-specific detail lives inside the adapter:

| Adapter | Specifics it absorbs |
|---|---|
| `AnthropicProvider` | `thinking={"type": "adaptive"}`, `output_config={"effort": "high"}`, `max_tokens=16000`. Never `temperature`/`top_p`/`top_k`/`budget_tokens` — 400 on `claude-opus-5`. |
| `OpenAICompatProvider` | `base_url` per vendor (OpenAI, Groq, DeepSeek, Qwen, Kimi); `tools` in OpenAI function-call schema |
| `GeminiProvider` | `functionDeclarations`, `parts`-shaped messages |

The manual loop is preferred over any SDK's built-in tool runner because the eval harness
needs to count and log every retrieval call — and because a vendor runner would only work
for one provider.

## Stage 6 — Grounded generation

Every claim carries a node id. The generation prompt states: answer only from the evidence
set; if the evidence does not support a claim, say so.

Post-check before returning (in `agent/loop.py`, not the prompt):
- Every citation marker resolves to a node id in the evidence set → else drop the sentence
  and log it.
- Citation coverage is computed and returned with the answer; the eval harness asserts it
  is 1.0.

## Config knobs

All in `config.py`, all overridable by env, all recorded in the eval run metadata:

```python
MAX_ANCHORS = 3
MAX_DEPTH = 3
NODE_BUDGET = 200
MIN_SHARED_ACTORS = 3       # CHAINS_TO support threshold
RRF_K = 60
RERANK_CANDIDATES = 50
EVIDENCE_TOP_N = 12
MAX_AGENT_STEPS = 8
```

Changing one of these invalidates the ablation table. Re-run the harness, don't hand-edit
the numbers.
