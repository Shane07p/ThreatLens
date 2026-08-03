# Testing

Test-first for ingestion parsers, traversal, and ranking. Those three are where silent
wrongness lives: a parser that drops 15% of edges and a reranker that inverts its sort both
produce plausible output and a garbage ablation table.

Code and comment rules are in [coderule.md](coderule.md); git, CI, and data rules are in
[otherrule.md](otherrule.md).

## Rules

**Testing is the priority, not an afterthought.** A parser that silently drops fifteen
percent of the edges produces a graph that looks entirely reasonable and numbers that are
worthless. The assertion is what makes a dropped edge a decision rather than an accident.

**Tests come first for parsers and ranking.** Those are the places failure is silent and
plausible. Structural code — wiring, CLI, rendering — can be tested after.

**Test three layers, not one.** Most suites only ever cover the first:

1. **Correctness** — the right answer on well-formed input.
2. **Robustness** — malformed, missing, duplicated, self-referential, hostile input. Real
   data is not clean, and one bad upstream release should not take down an ingest.
3. **Invariants** — properties that must hold for *any* input. No dangling edges. Ids that
   round-trip. Parsing that is deterministic across runs.

**Cases worth writing every time:**

- empty input, and input missing a field you assumed was always present
- duplicates, and two records claiming the same identity
- unicode, very long values, and text shaped like SQL injection
- something that should be *ignored*, asserted as distinct from something that was *lost*
- scale — an input several times larger than production
- determinism — the same input twice must give byte-identical output

**Name the test after the behavior, not the function.**
`test_revoked_objects_are_skipped`, not `test_parse_bundle_2`. The name is what a failing
build shows you first.

**Give a test a docstring when the reason it exists is not obvious from its name** —
especially a test guarding a bug that already happened once.

**Assert the property, not the incidental value.** Assert ordering, not float scores.
Assert the shape of a path, not a row count that will drift with the next data release.

**Never touch the network, a database, or model weights in a unit test.** `conftest.py`
blocks sockets for anything not marked `db` or `eval`. A suite that fails when GitHub is
slow gets disabled by the team within a week.

**Golden files are generated once and read by a human before being committed.** A golden
file produced by a buggy parser locks the bug in permanently, and every later phase inherits
it. Update one deliberately, never to make a red test go green.

**Do not test:** exact LLM wording, exact reranker floats, third-party parsing already
covered by its own library, or a live external API.

## Layout

```
tests/
├── conftest.py               # shared fixtures, network kill-switch
├── unit/                     # no DB, no network, no model weights. milliseconds.
│   ├── test_stix_parse.py
│   ├── test_mappings_parse.py
│   ├── test_nvd_parse.py
│   ├── test_chains_derivation.py
│   ├── test_fusion.py        # RRF math
│   ├── test_citations.py     # citation extraction + resolution
│   └── test_config.py
├── integration/              # real Postgres+pgvector, real SQL. seconds.
│   ├── test_schema.py
│   ├── test_upsert_idempotent.py
│   ├── test_traversal.py
│   ├── test_vector_search.py
│   └── test_pipeline_end_to_end.py
├── eval/                     # needs ANTHROPIC_API_KEY. costs money. never in CI gate.
│   ├── test_agent_loop.py
│   ├── test_groundedness.py
│   └── test_ablation_smoke.py
└── fixtures/
    ├── mini-attack-bundle.json    # ~20 objects, hand-checked
    ├── mini-mappings.csv          # ~10 rows incl. one secondary-impact row
    ├── nvd-sample.json            # 3 CVE records incl. one with no CVSS v3
    └── expected_graph.json        # the exact nodes/edges mini-bundle must produce
```

## Markers

`pyproject.toml`:

```toml
[tool.pytest.ini_options]
markers = [
    "slow: needs model weights or a large corpus",
    "db: needs Postgres",
    "eval: calls the Anthropic API, costs tokens",
]
addopts = "-q --strict-markers"
```

| Command | Runs | When |
|---|---|---|
| `uv run pytest -m "not slow and not eval and not db"` | unit only | every save |
| `uv run pytest -m "not eval"` | unit + integration | before commit, and in CI |
| `uv run pytest -m eval` | LLM tests | manually, before tagging a release |

**CI gates on `-m "not eval"` only.** An LLM call is non-deterministic and costs money; a
red build caused by model drift teaches everyone to ignore the build.

## CI

`.github/workflows/ci.yml`, on every push to `main`, every PR, and manual dispatch:

| Job | Steps |
|---|---|
| `lint` | `uv sync --all-groups` → `ruff check .` → `ruff format --check .` |
| `test` | same sync → `pytest -m "not eval" --timeout=120` against a `pgvector/pgvector:pg16` service container |

The test job sets `THREATLENS_TEST_DSN` to the service container and enables the `vector`
extension before running. Concurrency is capped per ref so a rapid second push cancels the
first run.

`uv.lock` is committed — CI installs from it, so a transitive dependency releasing a broken
version cannot turn the build red on its own.

Run the same thing locally before pushing:

```bash
uv run ruff check . && uv run ruff format --check . && uv run pytest -m "not eval"
```

## Provider conformance

Every LLM provider must pass one shared suite before being listed as supported. Same tests,
parameterized over the registry:

```python
@pytest.mark.eval
@pytest.mark.parametrize("provider_name", ["anthropic", "openai", "gemini", "groq",
                                           "deepseek", "qwen", "kimi"])
def test_provider_emits_structured_tool_call(provider_name): ...
```

What it asserts, per provider:
- a single-tool prompt produces a **structured** tool call, not prose describing one
- arguments parse as JSON and match the declared schema
- a multi-tool turn round-trips: tool results go back, the model continues
- `usage` is populated (token accounting feeds the cost column of the eval table)
- a refusal surfaces as a stop reason, not an exception

Providers are skipped individually when their key is absent, so a contributor with one key
can still run the suite. A provider that cannot hold a tool-calling loop is not supported by
the agent, however good its prose is — record that outcome in
[decisions.md](../design/decisions.md) rather than working around it.

## Unit tests

No network, no DB, no model weights. `conftest.py` enforces it:

```python
@pytest.fixture(autouse=True)
def _no_network(monkeypatch, request):
    if "db" in request.keywords or "eval" in request.keywords:
        return
    def _blocked(*a, **kw):
        raise RuntimeError("network call in a unit test")
    monkeypatch.setattr("socket.socket.connect", _blocked)
```

Embeddings are stubbed in unit tests — a deterministic fake encoder returning a fixed
384-vector per input hash. Loading real weights in a unit test turns a 2-second suite into a
90-second one.

What must be covered:

**`test_stix_parse.py`** — the gotchas from [graph-schema.md](../design/graph-schema.md) are each a
test:
- ATT&CK id is pulled from `external_references[source_name == "mitre-attack"].external_id`
- `revoked: true` objects are skipped
- `x_mitre_deprecated: true` objects are skipped
- edges pointing at a skipped object are dropped, not left dangling
- `BELONGS_TO` comes from `kill_chain_phases`, and a technique in two tactics yields two edges
- `subtechnique-of` produces `SUBTECHNIQUE_OF` with the right direction
- a sub-technique keeps its dotted id (`T1059.001`)

**`test_mappings_parse.py`**
- primary impact → weight 1.0, secondary → 0.5
- a CVE mapping to a technique not in the graph is logged and dropped, not crashed on
- URL-encoded `Att&ckToCveMappings.csv` parses with its `&`

**`test_nvd_parse.py`**
- CVSS v3.1 preferred, v4.0 accepted, missing score → `None` not `0.0` (a 0.0 severity is a
  lie that will show up in an answer)
- non-English descriptions filtered

**`test_chains_derivation.py`**
- pairs below `MIN_SHARED_ACTORS` are excluded
- direction follows kill-chain order
- a technique never chains to itself

**`test_fusion.py`** — RRF is pure math, table-driven:
- known ranks → known fused order
- a doc ranked #1 by one retriever and absent from the other still places well
- k=60 is applied, ties broken deterministically

## Integration tests

Real Postgres. Bring it up with `docker compose up -d db`; each test runs in a transaction
that rolls back, against a schema created once per session.

```python
@pytest.fixture(scope="session")
def engine():
    eng = create_engine(os.environ["THREATLENS_TEST_DSN"])
    run_schema_sql(eng)
    yield eng

@pytest.fixture
def db(engine):
    conn = engine.connect(); tx = conn.begin()
    yield conn
    tx.rollback()
```

Must cover:
- **Idempotency:** ingest the mini bundle twice → identical node and edge counts. Regression
  test for the most likely ingestion bug.
- **Golden graph:** mini bundle → exactly `expected_graph.json`. Update that file
  deliberately, never to make a test pass.
- **Traversal terminates on a cycle.** Build A→B→A, traverse, assert it returns rather than
  hanging. Wrap in `pytest.mark.timeout(10)`.
- **Depth and budget are honoured** — no path longer than `max_depth`, no more than
  `node_budget` nodes.
- **Path shape:** from a known CVE, the returned path is exactly
  `cve → technique → tactic`.
- **Vector search returns the planted nearest neighbour** with a hand-written embedding.

## Eval tests

Marked `eval`, skipped without `ANTHROPIC_API_KEY`:

```python
pytestmark = [
    pytest.mark.eval,
    pytest.mark.skipif(not os.getenv("ANTHROPIC_API_KEY"), reason="no API key"),
]
```

- **Agent loop terminates** within `MAX_AGENT_STEPS` on a normal question.
- **Refusal path:** a `stop_reason == "refusal"` response is handled without an exception.
- **Groundedness is 1.0** structurally on a sample of 5 real questions.
- **Ablation smoke:** each config in `eval/configs.py` runs end to end on 10 holdout CVEs
  and produces a metrics dict with no `None`s. This catches "config D crashes" before an
  overnight full run.

## Holdout protection

One test guards the eval set:

```python
def test_holdout_only_read_by_eval_module():
    hits = grep_repo("holdout.jsonl", exclude=["src/threatlens/eval/", "tests/", ".claude/"])
    assert not hits, f"holdout referenced outside eval/: {hits}"

def test_holdout_checksum_unchanged():
    assert sha256(HOLDOUT_PATH) == HOLDOUT_SHA  # pinned constant
```

If the checksum test fails, the split was regenerated and every published number is stale.
That is the intended alarm.

## What not to test

- Exact LLM wording.
- Exact float scores from the reranker (assert *ordering*, not values).
- Third-party parsing already covered by `stix2`.
- The live NVD or MITRE APIs. Fixtures only — a test suite that fails when GitHub is slow
  gets disabled.
