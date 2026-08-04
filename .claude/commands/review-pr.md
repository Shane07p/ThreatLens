---
description: Review a ThreatLens pull request or branch against the project rules
---

Review the pull request or branch given in `$ARGUMENTS` (a PR number, a branch name, or
nothing — in which case review the current branch against `main`).

## 1. Get the code

```bash
gh pr checkout $ARGUMENTS        # if a PR number was given
# or
git fetch origin && git diff origin/main...HEAD
```

Read the **whole diff** before commenting on any part of it. A change that looks wrong in
isolation is often correct in context, and the reverse.

## 2. Run the checks before reading the code

```bash
uv run ruff check .
uv run ruff format --check .
uv run pytest -m "not eval"
```

Report what actually happened. If tests fail, quote the output rather than summarizing it.
If the DB tests skip because there is no `THREATLENS_TEST_DSN`, say so — a skipped test is
not a passing test, and CI will run it even though you could not.

## 3. Project-specific checks

These are the ones a generic review misses. Each maps to a rule in `.claude/rules/`.

**Boundaries** — grep for these; they are hard rules, not preferences:
- `os.environ` anywhere outside `src/threatlens/config.py`
- SQL outside `src/threatlens/graph/`
- f-string or `%`-formatted SQL anywhere, including scripts and tests
- `import langchain` / `langgraph` inside `ingest/`, `graph/`, `retrieval/`, `report/`, `eval/`
- a vendor SDK (`anthropic`, `openai`, `google.genai`) outside `llm/`
- writes from anything under `retrieval/`

**Data honesty**
- a missing value defaulting to `0.0`, `""`, or `"unknown"` where `None` is correct —
  a fabricated CVSS score reads as "no risk" in an answer someone may act on
- a skipped or dropped record that is not counted and surfaced
- something out of scope being counted as an error, or an error being counted as out of scope

**Ingestion**
- a write path that is not an upsert on the primary key
- row-by-row inserts where a batch belongs
- an ingest that aborts on one bad record instead of logging, counting, and continuing

**Comments and docstrings**
- phase numbers, task ids, decision ids (`D8`, `Phase 3`, `Track B`) in code or comments
- comments restating what the line below does instead of why it exists
- a public function whose docstring does not say what it does, how to use it, and what it
  raises or depends on
- deliberate non-behavior that is not documented as deliberate

**Tests**
- a new parser or ranking function with no robustness cases — empty, missing field,
  duplicate, oversized, unicode, hostile, self-referential
- assertions on incidental values (row counts, float scores) rather than properties
- a golden file regenerated in the same commit as a parser change, with no evidence
  a human read the diff
- network, database, or model weights touched in a test not marked `db`, `slow`, or `eval`
- a test that cannot fail

**Dependencies**
- `pip install` in any instruction, script, or doc
- a new dependency added without `uv add`, or `uv.lock` not updated alongside `pyproject.toml`
- a library taken on to avoid writing something the project is measuring — RRF, fusion,
  traversal, and reranking stay ours

**Simplification** — per the simplify-first rule:
- a function doing two jobs that would read better as two
- a wide return tuple (`tuple[dict, dict, dict, int]`) that should be a dataclass or fewer values
- error handling for a case that cannot occur
- code built for a requirement nobody asked for

## 4. Report

Order findings by severity, worst first. For each one give the file and line, what is
wrong, and the concrete fix.

Separate clearly:
- **Blocking** — breaks a hard rule, fails a test, or is incorrect
- **Worth fixing** — works, but will cause trouble later
- **Optional** — style or taste; say so plainly so it can be ignored without guilt

Do not pad the review. If the diff is clean, say it is clean and stop — a review that
invents findings to look thorough trains people to ignore reviews.

State explicitly what you could **not** verify: tests that skipped, behavior that needs a
database, anything depending on a snapshot not present locally.
