# Code rules

How code and comments are written here. Where a rule has a reason, the reason is given —
a rule nobody understands is a rule that gets worked around.

---

## Language and tooling

Python 3.12, `ruff` for lint and format, line length 100.

```bash
uv run ruff check . && uv run ruff format .
```

**Type hints on every public function.** They are the cheapest documentation available.

**Frozen dataclasses for anything crossing a module boundary.** `Node`, `Edge`, `Graph`,
`Settings`. Not dicts — a typo'd key surfaces three modules away, and immutability means a
value cannot be changed behind its owner's back.

**Single responsibility per module.** If a file has grown to where you scroll to find
things, it is doing too much. Files that change together live together.

---

## Dependencies

**`uv add`, never `pip install`.** Dependencies belong in `pyproject.toml` and `uv.lock`.
The source documents say `pip install X --break-system-packages`; that flag exists to
override PEP 668 protection on a system Python and installs unpinned, invisible to the
project. Reproducibility is the one thing an eval-driven project cannot lose.

**Prefer a well-maintained library over writing our own — except where the component is
being measured.**

| Layer | Library | Why |
|---|---|---|
| LLM access | LangChain `init_chat_model` | One interface across providers; deletes ~250 lines of adapters |
| Agent loop | LangGraph | Checkpointing: a long eval sweep that dies partway resumes instead of restarting |
| Text splitting | LangChain splitters, inside `ingest/` only | Better than hand-rolled, and differentiates no configuration |
| Retrieval ranking | **ours** | See below |
| Graph traversal | **ours** | Nothing does bounded, weighted, direction-aware multi-hop over a Postgres edge table |

Retrieval ranking stays hand-written because the ablation table is the point of the project.
Each configuration must differ from the previous one by exactly one component. Using a
library's fusion means measuring that library's weighting, and the claim degrades from
*"we implemented RRF and measured its contribution"* to *"we called something and the number
went up"* — which is unanswerable when someone asks what `k` was.

RRF is five lines of arithmetic. Taking a dependency to avoid that is the wrong trade.

---

## Boundaries

Not suggestions. Each one has cost a project somewhere.

| Rule | Reason |
|---|---|
| No `os.environ` outside `config.py` | One place to look, one place to change, one place to test |
| No SQL outside `graph/` | A schema change has exactly one home |
| No f-string SQL, ever | Parameterized queries only, including in throwaway scripts |
| Retrieval never writes | If it needs to write, it belongs in `ingest/` |
| `ingest/`, `graph/`, `retrieval/`, `eval/` never import LangChain or LangGraph | Those paths must stay deterministic and reproducible |
| No vendor SDK outside `llm/` | Swapping a provider stays a config change |

---

## Naming

| Thing | Convention | Example |
|---|---|---|
| Node id | `{kind}:{external_id}` | `technique:T1190` |
| Edge kind | SCREAMING_SNAKE, reads src → dst | `MITIGATED_BY` |
| Node kind | lowercase singular | `technique` |
| Config constant | SCREAMING_SNAKE in `config.py` | `NODE_BUDGET` |
| Private helper | leading underscore | `_attack_ref` |
| Test | named after the behavior | `test_revoked_objects_are_skipped` |

---

## Errors

**Tolerant on the way in, strict on the way out.**

Ingestion logs a malformed record with its id, skips it, and **counts it**. A thirty-minute
ingest must not die on one bad row, but the loss has to be visible — a silent skip is
indistinguishable from a bug.

Query time raises. An unresolvable id, a dangling edge, or a citation that does not resolve
is a bug in our code, not a data problem.

**Never swallow an exception to keep a number in a results table.** A crashed configuration
is a blank cell, and a blank cell is honest.

**`logging`, never `print`.** One structured event per meaningful step. Debug-level for
per-stage candidate counts — the fastest way to find why a configuration regressed is seeing
where the candidate set collapsed.

---

## Comments

**Never reference internal phase numbers, task ids, or decision ids in code.** No "Phase 3",
no "Task 0", no "D8", no "Track B". They mean nothing to someone reading the file, they rot
the moment the plan changes, and they push the actual explanation into a document the reader
does not have open.

```python
# Bad
# D8 — BELONGS_TO comes from kill_chain_phases

# Good
# STIX has no relationship object for technique -> tactic. It models it as a
# "kill chain phase" on the technique, naming the tactic by shortname.
```

**Comments explain why, not what.** The code already says what.

```python
# Bad — restates the line below it
# increment skipped
skipped += 1

# Good — explains a decision the reader cannot infer
# One end was filtered out, so the edge goes with it. An edge to a node that
# does not exist breaks traversal.
skipped += 1
```

**Write down the trap you just fell into.** If something took twenty minutes to work out,
the next person deserves the answer rather than the same twenty minutes. Nearly every long
comment in this codebase exists because something failed silently once.

**Document deliberate non-behavior.** When the code does *not* do something obvious — does
not deduplicate, does not truncate, does not validate — say so, so the next person knows it
was a decision rather than an oversight.

**Do not comment the obvious.** No `# imports`, no `# constructor`, no comment restating a
parameter name.

---

## Docstrings

**Every public function's docstring answers three questions:** what it does, how you use it,
and what it depends on or raises. For anything non-obvious, say why it exists at all.

```python
def _attack_ref(obj: dict) -> tuple[str, str] | None:
    """Pull the ATT&CK id and its documentation URL out of a STIX object.

    The id (T1190, M1030) is not a top-level field — it sits in external_references
    alongside references to CAPEC and others, so source_name has to be checked.
    Objects also carry a STIX uuid, but nothing outside the bundle uses it: the CVE
    mappings, the website, and every analyst all speak T####.

    Returns (external_id, url), or None when the object has no ATT&CK identity.
    """
```

**A module docstring says what the module is for and what it must not do.** The constraints
are as useful as the purpose:

```python
"""Parse an ATT&CK STIX 2.1 bundle into nodes and edges.

Pure: no database, no network. Feed it a file path, get a Graph back.
"""
```

**Multi-value returns get their fields named** in the docstring. A bare
`tuple[dict, dict, dict, int]` is unreadable at the call site.

---

## Citations

A citation is a node id, written as `[^node_id]`, resolved to `nodes.source_url` at render
time. **The model never writes URLs** — it writes ids, and the renderer resolves them. That
makes a hallucinated link structurally impossible rather than merely unlikely.
