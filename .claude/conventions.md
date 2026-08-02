# Conventions

## Python

- Python 3.12, `ruff` for lint and format (line length 100).
- Type hints on every public function. `from __future__ import annotations` not needed on 3.12.
- Dataclasses (frozen) for records crossing module boundaries: `Node`, `Edge`, `Evidence`,
  `Subgraph`, `EvalResult`. Not dicts — a typo'd dict key surfaces three modules later.
- No `os.environ` outside `config.py`.
- No SQL outside `graph/`.
- No `print`. Use `logging`; the CLI configures handlers.

## Naming

| Thing | Convention | Example |
|---|---|---|
| Node id | `{kind}:{external_id}` | `technique:T1190` |
| Edge kind | SCREAMING_SNAKE, verb from src to dst | `MITIGATED_BY` |
| Node kind | lowercase singular | `technique`, `cve` |
| Config constant | SCREAMING_SNAKE in `config.py` | `NODE_BUDGET` |
| Eval config | single letter matching the ablation row | `A`, `B`, `C`, `D`, `E` |

## Errors

- Ingestion is **tolerant and loud**: a malformed record is logged with its id and skipped;
  the run reports `n skipped` at the end. It does not abort a 30-minute ingest over one bad
  row.
- Query time is **strict**: an unresolvable node id, a dangling edge, or a citation that
  does not resolve raises. These are bugs, not data problems.
- Never swallow an exception to keep a number in the ablation table. A crashed config is a
  blank cell.

## Logging

```python
log.info("ingest.attack", extra={"nodes": 1200, "edges": 15000, "skipped": 3})
```

One structured event per meaningful step. Retrieval logs every stage's candidate count at
DEBUG — the fastest way to find out why a config regressed is to see where the candidate set
collapsed.

## SQL

- Parameterized queries only. No f-string SQL, including in ingestion scripts.
- Bulk insert with `execute_values` / `COPY`, not row-by-row. 15k edges one at a time is
  minutes; batched is seconds.
- Every write path is an upsert on the primary key so re-running ingestion is safe.

## Citations

A citation is `[^node_id]` in generated text, resolved to `nodes.source_url` at render time.
The model never writes URLs — it writes node ids, and `report/markdown.py` resolves them.
That way a hallucinated URL is structurally impossible.

## LLM providers

`llm/registry.py` wraps `init_chat_model` behind a thin `Provider` seam. Swapping Claude for
Groq is a config change, not a code change.

```python
from langchain.chat_models import init_chat_model

model = init_chat_model(settings.model, model_provider=settings.provider)
```

Covers Anthropic, OpenAI, Gemini, Groq, and DeepSeek natively; Qwen and Kimi go through
`ChatOpenAI` with a `base_url`.

**Keep the seam thin — LangChain must never be load-bearing.** If a wrapper lags on a
parameter we need, we drop to that vendor's SDK inside `llm/` without touching `agent/`.

Anthropic, fixed:

```python
model="claude-opus-5"
max_tokens=16000               # 64000 if streaming
thinking={"type": "adaptive"}
output_config={"effort": "high"}
```

Verify `langchain-anthropic` actually surfaces `thinking` and `output_config.effort` before
relying on it — if they only go through blind `model_kwargs`, use the SDK directly. Never
pass `temperature`, `top_p`, `top_k`, or `budget_tokens`; all return 400 on this model. Check
the stop reason before reading content — a refusal arrives as a normal HTTP 200.

## Framework boundary

| Layer | May import LangChain / LangGraph |
|---|---|
| `ingest/`, `graph/`, `retrieval/`, `report/` | **No** |
| `eval/` | No — it calls configs A–D directly |
| `llm/`, `agent/` | Yes |

Configs A–D are deterministic and LLM-free and produce the numbers the project's claim rests
on. Only config E, the agent loop, is a graph. See [decisions.md](decisions.md) D16.

## Commits

Conventional Commits, phase-scoped:

```
feat(ingest): parse ATT&CK kill_chain_phases into BELONGS_TO edges
fix(traverse): guard against cycles via MITIGATED_BY
test(eval): pin holdout checksum
docs(phase-3): record baseline recall@1
```

**Never add `Co-Authored-By: Claude`, `Generated with Claude Code`, or any other
Claude/Anthropic attribution** to a commit message, PR description, or tag. Commits are
authored by the repository owner alone. No exceptions, and this does not need re-asking.

## Docs

When a phase completes, update its doc's status line and append measured numbers to
[evaluation.md](evaluation.md). A finished phase with an empty table row is not finished.
