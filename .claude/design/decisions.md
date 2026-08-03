# Decisions

Deviations from [threat_intel_graphrag_spec (1).md](../../threat_intel_graphrag_spec%20(1).md),
with reasons. Append, don't rewrite.

Several entries below also correct the original phase 1-3 data sources guide. That guide has
been folded into [data-sources.md](data-sources.md) — which carries the corrections rather
than the mistakes — and removed from the repository. Its content lives on there; the
decisions here record what was wrong with it and why.

---

### D1 — `uv add`, not `pip install --break-system-packages`

**Spec says:** `pip install stix2 --break-system-packages`, same for
`sentence-transformers`.

**We do:** `uv add stix2`.

**Why:** the repo is already a `uv` project (`pyproject.toml`, `.python-version` = 3.12).
`--break-system-packages` exists to override PEP 668 protection on an externally-managed
system Python — installing into the OS interpreter, unpinned, invisible to `pyproject.toml`.
That defeats reproducibility, which is the one thing an eval-driven project cannot lose.

---

### D2 — PostgreSQL + pgvector, not Neo4j

**Spec says:** either; Postgres recommended.

**We do:** Postgres, decided.

**Why:** graph filter *then* vector rank is one query in one system. Neo4j splits graph and
vectors across two stores and two round trips, and the retrieval pipeline restricts vector
search to subgraph node ids on every query — cheap in SQL, awkward across a boundary.
Recursive CTEs cover the traversal depth this project needs (≤3 hops).

---

### D3 — Scope the NVD pull; do not paginate the whole database

**Guide says:** paginate `resultsPerPage=2000`, incrementing `startIndex` until
`totalResults`.

**We do:** pull only (a) CVEs referenced by the mappings dataset, (b) the CISA KEV catalog,
(c) optionally a recent date window.

**Why:** the full NVD is 250k+ records. CVEs with no `ENABLES` edge are unreachable by
traversal and can never appear in an answer — they inflate the vector index, slow the
baseline, and make the naive-RAG row of the ablation table *look worse for the wrong
reason*. Comparing configs requires the same corpus with the same signal-to-noise.

---

### D4 — Metric definitions land in Phase 2; a minimal runner lands in Phase 3

**Spec says:** eval harness in week 5; week 3 says "measure the baseline and keep the
number."

**We do:** freeze the holdout format and write `eval/metrics.py` in Phase 2; ship a minimal
`eval/harness.py` in Phase 3 that produces row A.

**Why:** a baseline measured by ad-hoc code in week 3 and compared against harness output in
week 5 is not a comparison. Row A must come out of the same code path as rows C–E or the
headline claim is unsupported.

---

### D5 — `CHAINS_TO` defined narrowly, by actor co-occurrence

**Spec says:** "derived: techniques commonly used together / in sequence" — flagged as the
fuzziest edge.

**We do:** A→B if ≥3 distinct actors are documented using both, directed by kill-chain phase
order, weight = shared-actor count normalized.

**Why:** it is derivable from data already in the graph (`USES` edges), the threshold is a
single tunable, and it is honestly describable as co-occurrence rather than observed
sequence. The README says so explicitly. Overclaiming here is the cheapest way to lose
credibility with anyone who knows the data.

---

### D6 — Chunk long node text; embed chunks, score nodes

**Guide says:** "embed every node's description text."

**We do:** chunk to ≤512 tokens into `node_chunks`, embed chunks, node score = max over
chunks.

**Why:** `bge-small-en-v1.5` truncates at 512 tokens. Several ATT&CK technique descriptions
exceed that, so naive embedding silently drops the tail of exactly the longest, most
detailed descriptions — a quiet recall loss that would be attributed to the retrieval
strategy instead of the encoder.

---

### D7 — ATT&CK ids come from `external_references`

**Guide implies:** objects carry their ATT&CK id.

**Reality:** `T1190` lives in `external_references[]` where `source_name == "mitre-attack"`,
field `external_id`. The same entry's `url` is the citation target. Without this the
mappings dataset (keyed on `T####`) cannot join to the STIX objects at all.

---

### D8 — `BELONGS_TO` comes from `kill_chain_phases`, not a relationship object

**Guide says:** technique→tactic comes from `relationship` objects.

**Reality:** there is no `relationship` linking `attack-pattern` to `x-mitre-tactic`. The
link is `attack-pattern.kill_chain_phases[].phase_name` (where
`kill_chain_name == "mitre-attack"`) matched against `x-mitre-tactic.x_mitre_shortname`.
Following the guide literally yields zero tactic edges and a graph that cannot answer "what
tactic is this."

---

### D9 — Filter `revoked` and `x_mitre_deprecated`

**Guide says:** loop all objects, branch by `type`.

**We do:** skip `revoked: true` and `x_mitre_deprecated: true`, and drop edges referencing
skipped objects.

**Why:** retired techniques are still in the bundle. They will never be correct answers
against current ground truth, but they will compete in vector search and depress recall.

---

### D10 — Record the ATT&CK version from `x-mitre-collection`

The bundle contains an `x-mitre-collection` object carrying `x_mitre_version`. Read it, store
it in `ingest_runs`, cite it in the README. "Built against ATT&CK v19.1" is a reproducibility
claim; "built against ATT&CK" is not.

---

### D11 — Manual agent loop, not the SDK tool runner  *(SUPERSEDED by D16)*

**Spec says:** "the raw agentic loop (~15 lines)".

**We do:** manual loop in `agent/loop.py`.

**Why:** the eval harness needs to count and log every retrieval call per query (tool-call
count is a reported metric, and row E's cost story depends on it). The SDK tool runner is a
fine default elsewhere; here the instrumentation is the point. Iterations are capped at
`MAX_AGENT_STEPS`.

---

### D12 — Model config is fixed and constrained

`claude-opus-5`, `thinking={"type": "adaptive"}`, `output_config={"effort": "high"}`.
No `temperature`, `top_p`, `top_k`, or `budget_tokens` — all return **400** on this model.
`stop_reason == "refusal"` is a normal HTTP 200 and must be handled before reading
`content`; this is a security-adjacent domain and it will happen.

---

### D13 — Holdout is committed; raw snapshots are not

`data/eval/holdout.jsonl` and `data/manifest.json` are in git. `data/raw/` is not.

**Why:** the holdout is small, is public data, and is the only way someone else can check
the ablation table. The snapshots are large and reconstructible from the manifest's URLs and
checksums.

---

### D14 — Multi-provider LLM support behind one protocol  *(adapter design SUPERSEDED by D16)*

**Spec says:** "Anthropic SDK (or any LLM SDK) native tool-use."

**We do:** an `llm/` package with a `Provider` protocol and three adapters covering seven
providers — Claude, OpenAI, Gemini, Groq, DeepSeek, Qwen, Kimi.

**Why three, not seven:** OpenAI, Groq, DeepSeek, Qwen (DashScope compat endpoint), and Kimi
(Moonshot) all speak the OpenAI wire format. One `OpenAICompatProvider` parameterized by
`base_url` covers all five. Anthropic and Gemini have genuinely different message and
tool schemas and get their own adapters.

**Consequences to respect:**
- No vendor SDK may be imported outside `llm/`. The moment `agent/loop.py` imports
  `anthropic` directly, the abstraction is dead and swapping providers becomes a rewrite.
- Tool-calling fidelity varies a lot across these models, and the agentic loop (Phase 6)
  depends on it. Every provider must pass a shared tool-use conformance test before being
  listed as supported. A provider that cannot reliably emit tool calls is a provider the
  agent cannot use, regardless of how good its prose is.
- **Provider is an evaluation axis, not an ablation row.** Rows A–E must all run on the same
  provider or the comparison is confounded. To compare providers, run the whole table again
  and report it as a separate result.
- Cost and latency differ by more than an order of magnitude across these. Report which
  provider produced any published number.

---

### D16 — LangChain for providers, LangGraph for the agent loop

**Spec says:** "The raw agentic loop (~15 lines); tools = graph queries + retrieval. Add
LangGraph only if you later want checkpointed multi-step runs." Supersedes D11.

**We do:** `init_chat_model` + `bind_tools` for provider normalization, and LangGraph for
the Phase 6 agent loop.

**Why LangChain over hand-written adapters:** `init_chat_model` normalizes messages and
tool-calling across Anthropic, OpenAI, Gemini, Groq, and DeepSeek natively; Qwen and Kimi go
through `ChatOpenAI` with a custom `base_url`. That deletes roughly 250 lines of adapter
code we would otherwise own and maintain.

**Why LangGraph:** checkpointing is the real argument. An eval sweep over ~160 holdout CVEs
that dies at #140 currently restarts from zero; a checkpointer resumes it. Explicit graph
state also beats a hand-rolled loop once retry, re-query, and step-budget logic land.

**The line that must hold — LangGraph is Phase 6 only:**

| Config | Path | Framework |
|---|---|---|
| A–D | `retrieval/pipeline.py` | **None.** Plain Python, deterministic, LLM-free. |
| E | `agent/graph.py` | LangGraph |

Configs A–D produce the retrieval metrics the headline claim rests on. They must be exactly
reproducible, so they do not import LangChain or LangGraph at all. Routing them through an
agent framework would add a dependency and a nondeterminism surface to precisely the rows
that need neither.

**Consequences to respect:**
- The `Provider` seam stays (~20 lines). LangChain must never be load-bearing — if
  `langchain-anthropic` lags on a parameter we need, we drop to the raw SDK for that
  provider without touching `agent/`.
- **Verify adaptive thinking and `output_config.effort` are actually surfaced** by the
  installed `langchain-anthropic` before relying on it. These are recent Anthropic
  parameters; if they are only reachable via blind `model_kwargs`, that is worse than
  calling the SDK directly, because a 400 then returns through two layers.
- Token accounting per provider still has to be verified. The eval table reports tokens and
  cost per config, and a field LangChain does not normalize becomes a silently blank column.
- Tool-call counts come from LangGraph state, not from wrapping the SDK.

---

### D15 — CI gates on lint + `not eval`; never on the LLM suite

GitHub Actions runs `ruff check`, `ruff format --check`, and `pytest -m "not eval"` against a
`pgvector/pgvector:pg16` service container.

**Why exclude `eval`:** those tests call a paid API and are non-deterministic. A pipeline that
goes red because a model phrased something differently — or because someone's key ran out —
teaches the team to ignore the pipeline. Eval runs are deliberate and manual.
