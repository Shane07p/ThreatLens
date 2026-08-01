# ThreatLens — A Graph-RAG Threat Intelligence Agent
### Complete Project Specification

*An agentic GraphRAG system that takes a security finding (a CVE, an attack technique, an alert) and traces it across the web of threat-intelligence knowledge — what it is, how it's exploited, what an attacker does next, who uses it, and how to defend — returning a grounded, cited answer in seconds instead of an hour of manual cross-referencing.*

> **Name is a placeholder.** "ThreatLens" is just a working title; rename freely.

---

## 1. What the project is (in one paragraph)

Security analysts constantly face the question: *"here's a CVE / technique / alert — what is it, how bad is it, how would an attacker actually use it, and what do I do?"* Answering it well means cross-referencing several separate knowledge bases (the CVE database, the MITRE ATT&CK framework, the mappings between them, threat-actor reports, mitigation catalogs) and manually stitching the pieces into one picture. That stitching is slow, requires expertise, and is easy to get wrong under alert pressure. **ThreatLens automates the stitching.** It models the threat-intelligence world as a *knowledge graph* (CVEs, attack techniques, tactics, mitigations, threat actors, all linked), and answers plain-English questions by *traversing that graph* — retrieving the connected subgraph relevant to the question and explaining it with a citation on every claim. The core technical work is **graph retrieval** (GraphRAG), which is exactly where naive vector-search RAG fails, because the answer is a *path through connected knowledge*, not a set of similar text chunks.

---

## 2. Why this project (the reasoning behind it)

- **Retrieval is genuinely the point.** The value is in *traversing linked knowledge*, not in classifying or solving. Strip the retrieval out and there is no product. This is deliberately unlike a "classifier with RAG bolted on" — here the graph retrieval *is* the engine.
- **Naive vector RAG provably underperforms here.** Published research (CyKG-RAG, 2026) states plainly that flat vector RAG *"does not allow to consider pivotal aspects such as network structure, threat attack patterns"* — the answer is structural. That's the whole reason to build graph retrieval, and it's a real, citable justification for the architecture.
- **It plays to a graph-algorithms strength** (multi-hop traversal, weighted paths) while still being a full, honest RAG + agents project — not pure graph algorithms.
- **The data is abundant, free, structured, and relationship-rich** (see §4). No data wall, no scraping-that-violates-ToS, no paywall.
- **There's a built-in ground-truth source for evaluation** (the CVE→ATT&CK Mappings Explorer provides labeled links), which makes a rigorous eval harness possible — the single thing that separates a real project from a demo.

**Honest positioning:** this is an *active research area* (CyKG-RAG, the IEEE GraphRAG-CTI dataset, Minerva, and others exist). The goal is **not novelty** — it's a genuinely well-built, well-evaluated, usable tool that is *better on execution* than academic prototypes. The differentiator is craft and evaluation, not invention. State this honestly in the README.

---

## 3. What it does — from the user's perspective

**User:** a security analyst, a security student, or a developer wearing the security hat.

**Example interaction:**

> **User:** "CVE-2024-1234 showed up in our environment. How would an attacker exploit it, what would they likely do next, and how do I defend against it?"
>
> **ThreatLens:**
> This CVE enables **Exploit Public-Facing Application (T1190)**, an *Initial Access* technique. From here, attackers commonly chain to **Command and Scripting Interpreter (T1059)** for execution, then **Valid Accounts (T1078)** for persistence. Threat groups **APT29** and **FIN7** are documented using this pattern.
>
> **Defense:** apply the vendor patch (primary). Since patching often lags, add compensating controls — network segmentation (**M1030**) and the detection rule below for the exploitation pattern.
>
> *[every claim links to its source: the CVE record, the ATT&CK technique page, the threat-actor entry, the mitigation]*

**The key move:** it didn't just *look up* the CVE. It **traced the connections** — CVE → technique → tactic → next-technique → threat-actor → mitigation — and assembled the whole picture, with citations. That traversal across linked knowledge is the thing that's slow and error-prone to do by hand, and it's exactly what the tool automates.

**Interface:** command-line first (`threatlens ask "..."`), with a Markdown report as the shareable artifact. A simple web UI is optional/later.

---

## 4. Where the data comes from (all free, all confirmed current)

This is the project's biggest practical advantage. Every source below is free, public, and machine-readable.

| Source | What it gives you | Access | Notes |
|---|---|---|---|
| **MITRE ATT&CK** | Techniques, tactics, mitigations, detections, threat-actor→technique mappings | STIX 2.1 JSON on GitHub (`mitre-attack/attack-stix-data`) or the official TAXII 2.1 API (`attack-taxii.mitre.org`) | Latest is Enterprise v19.1 (May 2026). Parse with the `stix2` Python library. This is the backbone of the graph. |
| **CVE / NVD** | Vulnerability records: descriptions, severity (CVSS), affected products | NVD REST API (free; request an API key for higher rate limits) | The "findings" users ask about. |
| **CVE→ATT&CK Mappings Explorer** | Pre-built links from CVEs to the ATT&CK techniques they enable (primary + secondary impact) | Center for Threat-Informed Defense (public) | **Critical: this is your labeled ground truth for evaluation.** It's also the edge that connects the CVE world to the ATT&CK world. |
| **D3FEND** | Defensive techniques mapped to offensive ones | Public ontology (MITRE) | Optional enrichment for the "how to defend" side. |
| **Sigma rules** | Detection rules mapped to ATT&CK techniques | Public `SigmaHQ` GitHub repo | Optional: lets the tool output concrete detection rules. |
| **Pre-built Neo4j graph (optional shortcut)** | 1,427 nodes / 2,543 relationships of ATT&CK + APT data | IEEE DataPort ("MITRE ATT&CK Dataset for KG-Enhanced RAG") | Useful to *see the graph shape* before building your own ingestion. |

**Recommended starting subset:** MITRE ATT&CK Enterprise (STIX) + NVD (CVE records) + the CVE→ATT&CK mappings. That trio alone supports the whole core experience and the eval harness. Add D3FEND / Sigma later as enrichment.

**Ingestion note:** download the STIX JSON once and build your own graph in your database (don't depend on live API calls at query time). This keeps queries fast and the system reproducible.

---

## 5. The knowledge graph — schema

**Nodes:**
- `CVE` — a vulnerability (id, description, CVSS score, affected products)
- `Technique` — an ATT&CK technique (e.g., T1190), with its text description
- `Tactic` — an ATT&CK tactic (e.g., Initial Access, the attacker's goal)
- `Mitigation` — an ATT&CK mitigation (e.g., M1030)
- `ThreatActor` / `Group` — a documented adversary (e.g., APT29)
- `Detection` — a detection method / Sigma rule (optional)
- `Software` / `Tool` — malware or tools used by actors (optional)

**Edges:**
- `CVE —ENABLES→ Technique` (from the Mappings Explorer — the bridge between the two worlds)
- `Technique —BELONGS_TO→ Tactic`
- `Technique —MITIGATED_BY→ Mitigation`
- `Technique —DETECTED_BY→ Detection`
- `ThreatActor —USES→ Technique`
- `Technique —CHAINS_TO→ Technique` (derived: techniques commonly used together / in sequence)
- `ThreatActor —USES→ Software`

The `CHAINS_TO` edge is the most interesting one to build well — it's what lets the tool answer "what would an attacker do *next*," which is the multi-hop reasoning that shows off graph retrieval.

---

## 6. The retrieval pipeline — where the real engineering lives

This is checkpoint 3 ("RAG is about implementation; many techniques") — and this domain rewards real technique because naive RAG demonstrably fails.

**Stage 1 — Entry-point resolution.** Parse the user's question to find the anchor node(s): a CVE id, a technique name, a tactic, or free-text that must be *semantically* matched to a node. (Hybrid: exact-match on ids + vector search on descriptions.)

**Stage 2 — Graph traversal (the core, GraphRAG).** From the anchor, traverse the graph to collect the relevant connected subgraph: CVE → technique → tactic → chained techniques → mitigations → actors. This is bounded, weighted multi-hop traversal — your graph-algorithms strength. **This is the stage naive vector RAG cannot do**, because the answer is a path, not a similarity ranking.

**Stage 3 — Semantic retrieval over node text.** For the nodes in the subgraph, retrieve their descriptions and any linked prose (technique write-ups, threat reports) using **hybrid search** (BM25 + dense embeddings) so the explanation is grounded in real text.

**Stage 4 — Fusion + reranking.** Fuse the graph-derived context and the semantically-retrieved text (Reciprocal Rank Fusion), then rerank with a cross-encoder so the most relevant evidence leads.

**Stage 5 — Agentic loop.** The LLM decides whether it has enough to answer or needs to traverse further ("I have the technique; now fetch its mitigations and the actors who use it"). It re-queries the graph until the evidence is sufficient and self-consistent, then generates the answer. This is genuine agentic behavior — the model drives *what to retrieve next*, which it can't know in advance.

**Stage 6 — Grounded generation.** Produce the answer with a citation on every claim, linking back to the specific node/source. Nothing ungrounded.

**Techniques you'll implement (and learn):** GraphRAG / knowledge-graph traversal, hybrid retrieval (BM25 + dense), Reciprocal Rank Fusion, cross-encoder reranking, multi-hop retrieval, query decomposition, agentic re-querying, and groundedness/faithfulness evaluation. This is a *real* RAG curriculum, not toy RAG.

---

## 7. Tech stack

| Layer | Choice | Why |
|---|---|---|
| Language | **Python 3.12** | Required for the RAG/embedding ecosystem; use `uv` for env + packages. |
| Graph + vector store | **PostgreSQL + `pgvector`** (recommended) *or* **Neo4j** | Postgres holds the graph (via tables + recursive CTEs) and the embeddings in one place, so graph-filter-then-vector-search is one query. Neo4j is an option if you specifically want to learn a graph DB and lean on Cypher — but it splits graph and vectors into two systems. Start with Postgres unless graph-DB skills are a goal. |
| Graph traversal | Recursive SQL CTEs (Postgres) or Cypher (Neo4j) | The multi-hop core. |
| Data parsing | **`stix2`** (ATT&CK), `httpx` (NVD API), `json` | `stix2` is MITRE's own library for the ATT&CK data. |
| Embeddings | **`sentence-transformers`** → `BAAI/bge-small-en-v1.5` | CPU-friendly; embeds node descriptions. |
| Lexical search | **`rank-bm25`** | The lexical half of hybrid retrieval. |
| Reranker | **`BAAI/bge-reranker-base`** | Cross-encoder; runs on CPU. |
| Agent loop | **Anthropic SDK** (or any LLM SDK) native tool-use | The raw agentic loop (~15 lines); tools = graph queries + retrieval. Add **LangGraph** only if you later want checkpointed multi-step runs. |
| CLI | **Typer** | The v1 interface. FastAPI only if you add a web UI later. |
| Eval | **`pytest`** + a custom harness; optional **RAGAS** | For the ablation table and faithfulness scoring. |

**Deliberately NOT needed:** no Pinecone/Weaviate (pgvector suffices at this scale), no fine-tuning, no GPU, no CrewAI/AutoGen. Keep the stack boring so the retrieval can be interesting.

---

## 8. Features

**Core (v1 — build these):**
1. **Ingestion** — pull ATT&CK STIX + NVD CVEs + CVE→ATT&CK mappings into the graph store.
2. **CVE lookup + explanation** — given a CVE, explain what it is and what technique(s) it enables.
3. **Multi-hop traversal** — CVE → technique → tactic → chained techniques → mitigations → actors.
4. **Plain-English Q&A** — ask a question, get a traversal-grounded answer with citations.
5. **Grounded, cited output** — every claim links to its source node.
6. **Markdown report** — a shareable file summarizing the finding, the attack path, the actors, and the defenses.
7. **Eval harness** — the ablation table (see §9).

**Enrichment (v1.5 — if time allows):**
8. Detection-rule output (Sigma) for a technique.
9. D3FEND defensive-technique mapping.
10. "Attack path" visualization (render the retrieved subgraph).

**Later (v2):**
11. Ingest a log/alert (not just a CVE) as the entry point.
12. MCP server, so a coding/security agent can call ThreatLens as a tool.
13. Web UI.

**Explicit non-goals (do NOT build):** it does **not** detect attacks or scan systems (it's a comprehension/research tool, not a scanner); it does **not** do live network monitoring; it does **not** try to be a full SOC platform. Keep the scope to "explain and connect known threat intelligence."

---

## 9. Evaluation — the credibility core

This is the single most important part, and the thing most projects skip. **Build the ablation table** — it's what turns "I built a thing" into "I built a thing and here's proof it works."

**Ground truth:** the CVE→ATT&CK Mappings Explorer gives labeled CVE→technique links. Hold out a set of these and measure whether the system retrieves the correct technique(s) for a given CVE.

**The ablation table** (fill with your real measured numbers):

| Configuration | Retrieval accuracy (correct technique) | Multi-hop answer quality | Groundedness |
|---|---|---|---|
| A. Vector search only (naive RAG baseline) | ~? | ~? | ~? |
| B. + BM25 hybrid | ~? | ~? | ~? |
| C. + graph traversal (GraphRAG) | ~? | ~? | ~? |
| D. + reranking | ~? | ~? | ~? |
| E. + agentic re-query (full) | ~? | ~? | ~? |

**The headline claim you're aiming for:** *"naive vector RAG retrieved the correct technique X% of the time; adding graph traversal and reranking took it to Y%"* — mirroring the published finding that flat RAG underperforms in this domain. That sentence is your project's entire credibility.

**Other metrics:** groundedness/faithfulness (does every claim have a supporting citation? — RAGAS or a custom check), multi-hop correctness (did it find the right *path*, not just the right node), and answer latency.

---

## 10. 8-week build sequence (solo, alongside coursework)

| Week | Deliverable |
|---|---|
| 1 | Ingest ATT&CK STIX (techniques, tactics, mitigations, actors) into the graph store. **No AI yet.** Verify the graph by hand. |
| 2 | Ingest NVD CVEs + the CVE→ATT&CK mappings. Now the two worlds are connected. Build basic traversal queries (CVE → technique → tactic → mitigation). |
| 3 | Naive RAG baseline: embed node descriptions, vector search, generate. **Measure how it does and keep the number** — it's your ablation baseline. |
| 4 | The real retriever: graph traversal + hybrid (BM25 + dense) + RRF + reranker. |
| 5 | **Eval harness.** Hold out CVE→technique labels; measure retrieval accuracy across configs. Build the ablation table. This is when it stops being a toy. |
| 6 | Agentic loop: the LLM drives multi-hop re-querying; grounded, cited generation. |
| 7 | CLI polish + Markdown report + (if time) attack-path visualization. |
| 8 | README with the ablation table, a demo on a real CVE, honest "related work" section citing CyKG-RAG etc., and honest limitations. |

**Weeks 3–5 double as your RAG course** — you'll build embeddings, retrieval metrics, and ranking right as your ML course covers the theory.

---

## 11. The deep core to protect vs. what to cut

- **Protect (the impressive, differentiating core):** the **graph traversal / multi-hop retrieval**, and the **eval ablation table**. These are what make it deep, retrieval-first, and credible — and where your graph strength shows.
- **Cut first if time runs short, in order:** web UI → attack-path visualization → Sigma/D3FEND enrichment → agentic loop (degrade to a fixed traversal pipeline) → second data source. Even the minimal version (graph + traversal retrieval + eval table) is a strong, honest project.

---

## 12. Honest risks & cautions

- **It's an active research area** — you are not first. Position on execution and evaluation, cite related work (CyKG-RAG, the IEEE GraphRAG-CTI dataset, Minerva) by name, and be honest about what's yours (a well-built, well-evaluated, usable tool) vs. what's prior art (the general approach).
- **Scope creep** is the main threat — "all of threat intelligence" is infinite. Anchor v1 firmly on **CVE→ATT&CK multi-hop Q&A**. Everything else is enrichment.
- **It's a comprehension tool, not a detector** — be honest in the pitch. The benefit is *speed and thoroughness on known intelligence* (research cites ~45% triage-time reduction for tools of this shape), not novel detection. Don't imply a green answer means "you're safe."
- **Data freshness** — download snapshots; don't depend on live API calls at query time. Note in the README which ATT&CK/NVD version you built against.
- **The `CHAINS_TO` edge is the fuzziest to build** — "what technique comes next" isn't always cleanly in the data. Scope it carefully (e.g., derive from threat-actor co-occurrence) rather than overclaiming precision.

---

## 13. One-line summaries (for different audiences)

- **User / general:** "Give it a CVE or an alert, and it instantly traces the whole picture — what the attack is, how it's exploited, what comes next, who does it, and how to stop it — in seconds instead of an hour of manual cross-referencing."
- **Technical peer:** "A GraphRAG threat-intelligence agent: it answers analyst questions by multi-hop traversal over the ATT&CK/CVE knowledge graph, with hybrid retrieval, reranking, an agentic re-query loop, and an ablation-based eval."
- **RAG-learning context:** "An agentic GraphRAG project where graph traversal is the core retrieval mechanism — chosen specifically because naive vector RAG provably underperforms on structurally-linked threat knowledge."
