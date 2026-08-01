# Phase 6 — Agentic loop and grounded generation

**Status:** not started
**Goal:** the LLM decides what to retrieve next, then answers with a citation on every
claim. Row E of the ablation table.

First cuttable phase if time runs short — degrade to the fixed Phase 4 pipeline and mark row
E "not run." Say so honestly rather than shipping a half-working agent.

## Steps

1. **Deps.** `uv add anthropic openai google-genai`
   (`openai` covers OpenAI, Groq, DeepSeek, Qwen, and Kimi via `base_url` — see
   [decisions.md](decisions.md) D14.)

1a. **Provider layer first** — `llm/base.py` defines the `Provider` protocol and a
   normalized `Response` (`text`, `tool_calls`, `usage`, `stop_reason`); `llm/registry.py`
   maps `THREATLENS_PROVIDER` to an adapter. Build `AnthropicProvider` first, get the loop
   working, then add `OpenAICompatProvider` and `GeminiProvider` against the same
   conformance test. **No vendor SDK import escapes `llm/`.**

2. **Tools** — `agent/tools.py`. Thin wrappers over Phase 4 functions:

   | Tool | Input | Returns |
   |---|---|---|
   | `resolve_anchor` | free text | candidate node ids, names, kinds |
   | `traverse` | node_id, edge kinds, depth | subgraph nodes + edges + paths |
   | `retrieve_text` | node_ids, query | ranked evidence passages tagged with node ids |
   | `get_node` | node_id | full record + `source_url` |

   Tool descriptions must say **when** to call, not just what the tool does — prescriptive
   descriptions measurably improve tool triggering.

3. **The loop** — `agent/loop.py`, manual, written against `llm.Provider`
   ([decisions.md](decisions.md) D11 — the harness needs to count every retrieval call, and
   a vendor tool runner would only work for one provider).

   ```python
   provider = llm.registry.get(settings.provider)
   resp = provider.complete(messages=messages, tools=TOOLS)
   ```

   Non-negotiable details:
   - Check the refusal stop reason **before** reading content. On Anthropic a refusal is a
     normal HTTP 200 with `stop_details`, not an exception. Security-adjacent domain; it
     will happen.
   - Append the full assistant turn back to `messages`, not just the text — dropping
     tool-call blocks breaks the turn on every provider.
   - All tool results for one assistant turn go back in a **single** user message. Splitting
     them trains the model out of parallel tool calls.
   - Cap iterations at `MAX_AGENT_STEPS` (default 8). An uncapped loop is a billing incident.
   - Log every tool call with its arguments and result size, plus the provider and model id.
     Tool-call count is a reported metric and it varies by provider.
   - Anthropic specifics (`thinking`, `effort`, no `temperature`/`top_p`/`top_k`/
     `budget_tokens` — all 400 on `claude-opus-5`) live in the adapter, not here.

4. **Grounded generation** — `agent/prompts.py`. The system prompt states: answer only from
   the assembled evidence; cite every claim by node id as `[^node_id]`; if the evidence does
   not support a claim, say so rather than filling the gap.

   The model writes **node ids, never URLs** ([conventions.md](conventions.md)). URLs are
   resolved at render time, which makes a hallucinated link structurally impossible.

5. **Post-check, in code not in the prompt.** Before returning:
   - every citation marker resolves to a node id in the evidence set
   - unresolvable citations → drop the sentence, log it, decrement coverage
   - return coverage alongside the answer

6. **Config E** in `eval/configs.py`: config D plus the agentic loop. Measure over the
   holdout, fill row E.

7. **Cost accounting.** Row E adds tokens and latency. Report tokens in/out per query and
   tool calls per query, and state whether the accuracy gain justifies them. "The agent
   helped by 2 points and tripled cost" is a legitimate, interesting finding.

## Tests that must pass

Marked `eval`, skipped without `ANTHROPIC_API_KEY`:
- loop terminates within `MAX_AGENT_STEPS` on a normal question
- a refusal response is handled without an exception
- structural groundedness = 1.0 on 5 real questions
- ablation smoke: config E runs on 10 holdout CVEs with no `None` metrics

```bash
uv run pytest -m "not eval"     # must stay green
uv run pytest -m eval           # run manually
```

CI never gates on `-m eval` — non-deterministic and it costs money.

## Done when

- [ ] Four tools implemented with prescriptive descriptions
- [ ] Loop caps iterations and logs every tool call
- [ ] Refusal path handled and tested
- [ ] Generation emits node-id citations; renderer resolves them to URLs
- [ ] Post-check enforces citation resolvability; coverage returned with the answer
- [ ] Config E measured; row E filled with numbers, tokens, and tool-call counts
- [ ] `-m eval` suite passes locally

## Next

[Phase 7 — CLI and report](phase-7-cli-report.md)
