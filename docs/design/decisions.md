# Decisions

Deviations from [spec.md](../spec.md),
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
Traversal over the edge table covers the depth this project needs (≤3 hops); D20
explains why it is a level-by-level walk rather than one recursive CTE.

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

---

### D17 — The traversal cycle guard is a cost bound, not a termination bound

*Superseded in part by D20: the walk is no longer a recursive CTE. The reasoning about
what the guard bounds still explains why the old query blew up.*

[graph-schema.md](graph-schema.md) says of `NOT e.dst = ANY(w.path)`: *"Cycle guard is not
optional — without this it never terminates."* That reasoning is wrong, and the correction
matters because it changes what has to be tested.

`max_depth` already bounds the recursion; a cyclic graph terminates without the guard. And a
route that revisits a node always costs more than the route that reached it first, so
`DISTINCT ON (id) ... ORDER BY cost` discards the revisiting row regardless. Removing the
guard leaves **every assertion about results passing** — proven by mutation: deleting it and
re-running the traversal suite was green.

What it actually bounds is the size of the intermediate `walk` relation. Six fully-connected
nodes at `max_depth=10` is `6 × 5^10` rows — tens of millions out of thirty edges. With the
guard a path cannot repeat a node, so nothing beyond six hops survives.

**Consequences:**
- The guard stays, for the reason above rather than the one originally written down.
- The test that protects it asserts *time*, not results: a dense cycle under
  `pytest.mark.timeout`. A results-based cycle test passes either way and proves nothing.
- `CHAINS_TO` is derived from actor co-occurrence and is symmetric before kill-chain
  ordering is applied, so dense cycles are the ordinary shape here, not a corner case.

### D18 — Tactic order is read from the matrix object, never hard-coded

[graph-schema.md](graph-schema.md) specifies `tactic_order` as *"a static map of the 14
Enterprise tactic shortnames to their kill-chain index"*. Written as a literal, that map is
already wrong: v19.2 renamed TA0005 Defense Evasion to **Stealth** and split **TA0112 Defense
Impairment** out of it, so the enterprise matrix has fifteen tactics, not fourteen.

Nothing on an `x-mitre-tactic` object records its position. The `x-mitre-matrix` object
carries `tactic_refs` in kill-chain order — reconnaissance first, impact last — and that is
the only place the sequence appears.

**Consequences:**
- The parser reads the order off the matrix and stores it as `attrs.order` on each tactic
  node, so chain derivation reads the graph rather than re-parsing the bundle.
- A tactic absent from the matrix gets `order: None`, not a sentinel index. A fabricated `0`
  would read as "first" and chain that technique to everything downstream of it.
- The real-bundle test asserts the orders form a dense `0..n-1` range and that
  reconnaissance is first, rather than pinning a count that moves every release.

### D19 — CHAINS_TO saturates at a fixed count, and min_shared_actors=3 stands

The derivation SQL in [graph-schema.md](graph-schema.md) normalizes weight as
`count(*) / max_shared`. Taking `max_shared` from the run's own maximum scores the single
strongest pair 1.0 however thin its evidence, and shifts every weight in the graph whenever
one new pair appears. Weight is therefore `LEAST(shared / 10, 1.0)` against a fixed
saturation constant.

On v19.2 the threshold of 3 yields **9,555 chains**, more than every ingested edge kind
combined. Spot-checked as the phase doc requires:

*Strongest edges* read as textbook intrusion sequences — Spearphishing Attachment → Malicious
File (75 shared actors), PowerShell → Ingress Tool Transfer (58), Windows Command Shell →
Ingress Tool Transfer (53), Registry Run Keys → Ingress Tool Transfer (45).

*At the threshold*, where a third of the edges sit, a random ten was roughly seven plausible
(Phishing for Information → Exploit Public-Facing Application; Local Account → Data Encrypted
for Impact) to three weak (Code Repositories → Proxy; Windows Command Shell → Fast Flux DNS).
Mixed, but not noise-dominated, so the threshold stays.

**Consequences:**
- These edges are inferred, not published. They say enough documented actors use both
  techniques in kill-chain order — **not** that anyone observed A followed by B. Anywhere
  they are surfaced must say so; describing them as attack-path data is overclaiming.
- The shared-actor count is stored on each edge so any single chain can be challenged.
- The derivation replaces rather than merges: a chain whose evidence weakened must vanish,
  because nothing in the graph would mark it stale.
- Density has a latency cost. Traversing `CHAINS_TO` from one technique measures 19 ms at
  depth 1, 34 ms at depth 2 and **494 ms at depth 3** — roughly 15× per level. The
  `max_depth=3` default is now load-bearing for latency as well as for semantics.
  (D20 removed that cost: depth 3 now runs at a 29 ms p95.)

---

### D20 — Traversal walks one level at a time and prunes to the budget

**Spec says:** recursive SQL CTEs for traversal.

**We do:** one indexed query per depth for the arcs leaving the frontier, with Python keeping
the cheapest route to each node and carrying only the cheapest `node_budget` routes into the
next level (#44).

**Why:** the recursive CTE enumerated every simple path up to `max_depth`, then
deduplicated, sorted and applied `LIMIT`. `node_budget` capped the output, not the work.
Postgres allows no aggregation, `DISTINCT ON` or `LIMIT` inside the recursive term, so the
budget could not be enforced inside the CTE. Measured on the real graph, 60 seed techniques
walking `CHAINS_TO` with a budget of 200:

| Depth | CTE p95 | CTE max | Level walk p95 | Level walk max |
|---|---|---|---|---|
| 3 | 188 ms | 306 ms | 29 ms | 30 ms |
| 4 | 3,898 ms | 4,993 ms | 36 ms | 39 ms |

**Why the pruning cannot change the answer:** every step costs `1 / max(weight, 0.01)`,
which is positive. If a route is dropped at some level, at least `node_budget` other nodes
were already reached more cheaply. Anything the dropped route leads to costs more than all
of them, so it could never make the final cut. A property test compares the walk against an
unpruned brute-force enumeration on random small graphs, with weights whose inverses are
exact so that ties are real ties.

**Consequences:**
- A walk is `max_depth + 2` round trips instead of one. Locally that is under a millisecond
  each, far less than what the CTE spent enumerating paths.
- Among equally cheap routes the shortest is reported. The CTE reported an arbitrary one:
  119 nodes across 240 sampled walks had a different `depth` for that reason alone.
- Costs are computed in Python from the weights as Postgres sends them (`0.3`, not float4's
  `0.30000001`). They differ from the CTE's in the seventh significant digit, and one
  real-graph walk broke a tie at the budget boundary differently: the CTE ranked two
  cost-5.0 routes apart by that rounding noise, while the walk treats them as a tie and
  breaks it by id.
- No statement timeout was added. Each level queries at most `node_budget` frontier ids
  through the `(src, kind)` and `(dst, kind)` indexes, so no single statement can run away.
  A timeout would only guard against a misconfigured `node_budget`.
- Nothing about how the results are used changes. `traverse` keeps its signature, and the
  CLI, `chains()` and every existing assertion are untouched.
