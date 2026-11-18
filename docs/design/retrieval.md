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

`graph/traverse.py`, a budget-bounded level-by-level walk described in
[graph-schema.md](graph-schema.md).

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

`agent/graph.py`, a LangGraph `StateGraph`. The model drives what to retrieve next.

**Stages 1–4 above are configs A–D and must not import LangChain or LangGraph.** They are
deterministic and LLM-free, and they carry the headline claim. Only this stage — config E —
is a graph. See [decisions.md](decisions.md) D16.

Tools exposed to the model:

| Tool | Input | Returns |
|---|---|---|
| `resolve_anchor` | free text | candidate node ids + names + kinds |
| `traverse` | node_id, edge kinds, depth | subgraph nodes + edges + paths |
| `retrieve_text` | node_ids, query | ranked evidence passages with node ids |
| `get_node` | node_id | full record + source_url |

Tool descriptions state **when** to call, not just what the tool does — prescriptive
descriptions measurably improve triggering.

```python
from langchain.chat_models import init_chat_model
from langgraph.graph import StateGraph
from langgraph.prebuilt import ToolNode, tools_condition
from langgraph.checkpoint.sqlite import SqliteSaver

model = init_chat_model(settings.model, model_provider=settings.provider).bind_tools(TOOLS)

graph = StateGraph(AgentState)          # messages + tool_calls + evidence accumulators
graph.add_node("agent", call_model)
graph.add_node("tools", ToolNode(TOOLS))
graph.add_conditional_edges("agent", tools_condition)
graph.add_edge("tools", "agent")
app = graph.compile(checkpointer=SqliteSaver.from_conn_string("data/agent.db"))
```

Rules:
- Cap iterations — `app.invoke(..., {"recursion_limit": MAX_AGENT_STEPS})`, default 8. An
  uncapped graph is a billing incident.
- **Checkpointing is the reason this is a graph.** An eval sweep over ~160 holdout CVEs that
  dies at #140 resumes rather than restarting.
- Tool-call counts come from graph state, not from wrapping an SDK — the eval table reports
  them per config.
- Handle a refusal stop reason before reading content. On Anthropic this is a normal HTTP
  200, not an exception; this is a security-adjacent domain and it will happen.

Provider selection is a config change, not a code change — `init_chat_model` normalizes
messages and tool-calling across Anthropic, OpenAI, Gemini, Groq, and DeepSeek; Qwen and Kimi
go through `ChatOpenAI` with a `base_url`.

**Anthropic caveat:** verify the installed `langchain-anthropic` actually surfaces
`thinking={"type": "adaptive"}` and `output_config={"effort": "high"}`. If they are only
reachable through blind `model_kwargs`, use the `anthropic` SDK directly for that provider —
the `Provider` seam in `llm/` exists so that swap costs nothing in `agent/`. Never pass
`temperature`, `top_p`, `top_k`, or `budget_tokens`; all return 400 on `claude-opus-5`.

## Stage 6 — Grounded generation

Every claim carries a node id. The generation prompt states: answer only from the evidence
set; if the evidence does not support a claim, say so.

Post-check before returning (in `agent/graph.py`, not the prompt):
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
