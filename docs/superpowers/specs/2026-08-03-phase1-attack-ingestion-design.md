# Phase 1 + independent Phase 2 — design

**Date:** 2026-08-03
**Status:** approved, ready for an implementation plan
**Team:** 4
**Covers:** the ATT&CK graph end to end, plus the Phase 2 pieces that need no graph

---

## Goal

Two outcomes, buildable in parallel:

1. **The ATT&CK Enterprise matrix as a queryable graph in Postgres**, verified by hand against
   the ATT&CK website. No AI, no embeddings — pure data plumbing.
2. **The Phase 2 pure parsers** — NVD client, CVE→ATT&CK mappings parser, eval metrics —
   unit-tested against fixtures and ready to wire up.

Success is a graph that answers `threatlens show T1190` correctly, and a suite that proves
the parser didn't quietly drop 15% of the edges.

## Why these two together

Phase 1 alone has three genuinely independent work items. With four people, a fourth would
either idle or contend for the same files. The Phase 2 parsers are pure functions over
fixtures — no database, no graph, no ordering constraint — so they absorb the fourth person
without creating a dependency.

Phase 2's *remaining* work (ingesting CVEs into the graph, building `ENABLES` edges, freezing
the eval holdout) is deliberately **out of scope**. It depends on technique nodes existing,
and the holdout freeze is an irreversible decision that deserves its own attention.

## Out of scope

- Embeddings, vector search, retrieval, the agent — Phases 3–6
- `CHAINS_TO` derivation — Phase 4, needs `USES` edges to exist first
- CVE node ingestion and `ENABLES` edges — Phase 2 proper
- The eval holdout split — Phase 2 proper, and irreversible

---

## Approach: contract first

**Decision:** freeze the shared types and the store API in one commit before anyone branches.

Considered and rejected:

- **Vertical slice first** — one person proves the interface end to end, then three fan out.
  Safer, but idles three people at the start, which defeats the reason for adding them. The
  data model is already fully specified in [.claude/graph-schema.md](../../../.claude/graph-schema.md),
  so the interface is transcription, not speculation. The risk it guards against is small.
- **Independent modules, integrate late** — zero coordination up front, but all the pain
  concentrates into one integration task and you end up writing adapters between four
  slightly different `Node` shapes.

**One piece borrowed from the vertical slice:** `upsert_nodes` and `upsert_edges` ship
*working* in the contract commit, not stubbed. Track B can then assert parser output against
a real database from its first integration test rather than discovering an impedance
mismatch at merge time.

---

## The contract

Lands as one commit on `main`. Nothing else starts until it is merged.

### `src/threatlens/models.py`

```python
@dataclass(frozen=True)
class Node:
    id: str                    # "technique:T1190" — deterministic, makes ingest idempotent
    kind: str                  # technique|tactic|mitigation|actor|software|cve
    external_id: str           # "T1190"
    name: str
    source_url: str            # the citation target
    description: str | None = None
    stix_id: str | None = None
    attrs: dict = field(default_factory=dict)

@dataclass(frozen=True)
class Edge:
    src: str                   # Node.id
    dst: str                   # Node.id
    kind: str                  # ENABLES|BELONGS_TO|MITIGATED_BY|USES|USES_SOFTWARE|
                               # SUBTECHNIQUE_OF|CHAINS_TO
    source: str                # "attack-stix v19.1" — provenance
    weight: float = 1.0
    attrs: dict = field(default_factory=dict)

@dataclass(frozen=True)
class Graph:
    nodes: list[Node]
    edges: list[Edge]
    version: str               # from the x-mitre-collection object
    skipped: int               # revoked / deprecated / dangling — reported, never hidden
```

Node ids are `f"{kind}:{external_id}"`. Deterministic ids are what make re-running an
ingestion an upsert rather than a duplication.

### `src/threatlens/graph/store.py`

```python
def get_engine() -> Engine
def init_schema(engine: Engine) -> None
def upsert_nodes(conn, nodes: Iterable[Node]) -> int      # implemented in the contract commit
def upsert_edges(conn, edges: Iterable[Edge]) -> int      # implemented in the contract commit
def record_ingest_run(conn, source: str, version: str, sha256: str,
                      n_nodes: int, n_edges: int) -> int
def node_counts(conn) -> dict[str, int]                   # kind -> count
def edge_counts(conn) -> dict[str, int]                   # kind -> count
def get_node(conn, node_id: str) -> Node | None
def neighbors(conn, node_id: str, kinds: list[str]) -> list[tuple[Edge, Node]]
```

Everything except the two upserts raises `NotImplementedError` until Track A fills it in.

**Changing this contract mid-flight requires telling all four people.** It is small and
derived from an already-settled schema, so this should not happen — but if it must, it is a
conversation, not a silent commit.

---

## Track A — Foundation

**Owns:** `config.py`, `graph/schema.sql`, `graph/store.py`
**Depends on:** the contract

- `Settings` — frozen dataclass, loaded once via `python-dotenv`. **The only place in the
  codebase that reads `os.environ`.** Holds `DATABASE_URL`, `NVD_API_KEY`, provider settings,
  and the retrieval knobs (`MAX_DEPTH`, `NODE_BUDGET`, `MIN_SHARED_ACTORS`, …) so they can be
  recorded in eval metadata later.
- `schema.sql` — the DDL from [.claude/graph-schema.md](../../../.claude/graph-schema.md):
  `nodes`, `node_chunks`, `edges`, `ingest_runs`, indexes, and
  `CREATE EXTENSION IF NOT EXISTS vector`. `node_chunks` is created now and left empty; Phase 3
  fills it.
- `store.py` — engine construction, `init_schema`, bulk upserts using `execute_values` with
  `ON CONFLICT DO UPDATE`, the count helpers, and the read helpers.

Row-by-row inserts are the trap here: 15k edges one at a time is minutes, batched is seconds.

**Done when:**
- `init_schema` applies cleanly to an empty database, and is idempotent on a second run
- `upsert_nodes` / `upsert_edges` are idempotent — same input twice, same counts
- Integration tests pass: `test_schema.py`, `test_upsert_idempotent.py`

## Track B — STIX parser

**Owns:** `ingest/attack.py`, `tests/fixtures/mini-attack-bundle.json`,
`tests/fixtures/expected_graph.json`
**Depends on:** the contract

`parse_bundle(path: Path) -> Graph`. Pure: no database, no network, no global state.

This track owns all four documented parsing corrections — each is a test, not a comment:

| Correction | Rule |
|---|---|
| D7 | ATT&CK id comes from `external_references[source_name == "mitre-attack"].external_id`; the same entry's `url` is `source_url` |
| D8 | `BELONGS_TO` comes from `kill_chain_phases[].phase_name` matched to the tactic's `x_mitre_shortname` — **there is no relationship object for this** |
| D9 | Skip `revoked: true` and `x_mitre_deprecated: true`; drop edges referencing skipped objects and count them in `Graph.skipped` |
| D10 | Read `x_mitre_version` off the `x-mitre-collection` object into `Graph.version` |

Relationship mapping:

| `relationship_type` | Edge |
|---|---|
| `mitigates` (course-of-action → attack-pattern) | `technique --MITIGATED_BY--> mitigation` (reversed) |
| `uses` (intrusion-set → attack-pattern) | `actor --USES--> technique` |
| `uses` (intrusion-set → malware/tool) | `actor --USES_SOFTWARE--> software` |
| `subtechnique-of` | `technique --SUBTECHNIQUE_OF--> technique` |

The fixture bundle is ~20 hand-checked objects and must include: one revoked object, one
deprecated object, one sub-technique with a dotted id, one technique in two tactics, and one
relationship pointing at a skipped object.

**This is the highest-risk track.** Every later phase inherits its output, and a parser that
silently drops edges produces a plausible-looking graph and a worthless ablation table.

**Done when:**
- `parse_bundle` on the fixture produces exactly `expected_graph.json`
- Every row in both tables above has a passing test
- Every technique in the output has at least one `BELONGS_TO` edge
- No edge references a node absent from `Graph.nodes`

## Track C — CLI and fetch

**Owns:** `cli.py`, `ingest/fetch.py`
**Depends on:** the contract; calls A and B through it

- `fetch.py` — download to `data/raw/`, compute sha256, write `data/manifest.json` with url,
  sha256, `fetched_at`, and version. Never overwrite an existing snapshot silently; require
  an explicit `--force`.
- `cli.py` — Typer app wiring `db init`, `fetch attack`, `ingest attack`, `stats`,
  `show <id>`, `list --tactic <id>`.

Because it goes through the contract, this track can be written and `CliRunner`-tested
against stubs before A or B land.

`stats` and `show` must work with no `ANTHROPIC_API_KEY` set — a reviewer should be able to
see the graph working without an API key.

**Done when:**
- Every command runs `--help` and exits 0 under `CliRunner`
- `fetch attack` writes the file and a correct manifest entry; re-running without `--force`
  refuses rather than overwriting
- `stats` prints per-kind node and edge counts

## Track D — Phase 2 pure parsers

**Owns:** `ingest/nvd.py`, `ingest/mappings.py`, `eval/metrics.py`
**Depends on:** nothing. Starts immediately.

- `NVDClient` — `httpx`, token-bucket rate limiter sized from the key's limit (50 req/30s
  with a key, 5 without), `tenacity` backoff on 403/503. Fetch by CVE id, batched.
- `parse_cve_record(raw: dict) -> Node` — CVSS v3.1 preferred, v4.0 accepted, **missing score
  is `None`, never `0.0`**. A fabricated 0.0 severity will end up in an answer.
- `parse_mappings(path) -> list[Edge]` — CSV and JSON both. Primary impact → weight 1.0,
  secondary → 0.5. A mapping to an unknown technique is logged and counted, not fatal.
- `eval/metrics.py` — `recall_at_k`, `mrr`, `path_correct`, `groundedness` as pure functions
  over `(predicted, gold)`. No harness, no pipeline — just the definitions Phase 3 will score
  row A with.

**Done when:**
- Rate limiter provably respects its budget (test with a fake clock, not `sleep`)
- CVSS fallback chain tested including the missing-score case
- Mappings weights tested for both primary and secondary
- Metric functions tested table-driven against hand-computed values

---

## Integration

```
        contract commit  ──►  main
                 │
    ┌────────┬───┴────┬─────────┐
    ▼        ▼        ▼         ▼
Track A   Track B  Track C   Track D
    │        │        │         │
    └──► merge A first          │
             │                  │
        merge B, then C ────────┴──► merge anytime
             │
    `threatlens ingest attack` works end to end
```

**Merge order matters for exactly one reason:** B's golden-graph integration test and C's
`ingest attack` command both need A's store. Their *unit* tests don't, so neither track is
blocked from working — only from merging last-mile tests.

**Workflow.** Four people cannot push to `main` directly; there have already been two push
collisions with two people. Protect `main`, one branch per track (`track-a-foundation`,
`track-b-stix-parser`, …), merge via PR with CI green. CI already gates on `ruff` +
`pytest -m "not eval"`.

## Testing

Follows [.claude/testing.md](../../../.claude/testing.md).

**Tests come first on Tracks B and D** — the parsers. That is the project rule, and it earns
its keep here specifically: a STIX parser and a CVSS fallback chain both fail *silently* and
plausibly. Writing the assertion first is the only cheap way to know the dropped edge was
intentional. Tracks A and C are structural enough that test-after is acceptable.

Per track:

| Track | Unit | Integration |
|---|---|---|
| A | — | `test_schema.py`, `test_upsert_idempotent.py` |
| B | `test_stix_parse.py` | golden graph vs `expected_graph.json` |
| C | `test_manifest.py`, CLI smoke via `CliRunner` | `ingest attack` on the fixture bundle |
| D | `test_nvd_parse.py`, `test_mappings_parse.py`, `test_metrics.py` | — |

Unit tests take no network, no database, no model weights — `conftest.py` already blocks
sockets for anything not marked `db` or `eval`.

## Phase-level done

- [ ] `docker compose up -d db && uv run threatlens db init` works on a clean clone
- [ ] `uv run threatlens ingest attack` loads the real bundle; a second run changes no counts
- [ ] Counts are in range: ~650 techniques, 14 tactics, ~45 mitigations, ~170 actors,
      ~750 software
- [ ] Every technique has ≥1 `BELONGS_TO` edge — zero tactic edges means D8 was missed
- [ ] No revoked or deprecated object is present, and no edge dangles
- [ ] 5–10 manual spot checks against the ATT&CK website agree
- [ ] `ingest_runs` has a row with the ATT&CK version and file sha256
- [ ] Track D parsers pass their suites against fixtures
- [ ] `uv run pytest -m "not eval"` green

## Risks

| Risk | Mitigation |
|---|---|
| Parser silently drops edges | Golden-graph test; `Graph.skipped` reported, never hidden; every technique asserted to have a tactic |
| Contract turns out wrong | Small and derived from a settled schema; upserts ship working so B validates against a real DB immediately |
| Four people, three files | Track ownership is explicit; D touches nothing A/B/C touch |
| Snapshot shifts mid-project | sha256 + version recorded in `manifest.json` and `ingest_runs`; `fetch` refuses to overwrite without `--force` |
| Port 5432 already occupied | Something is listening locally and the Docker daemon is down. Resolve before Track A starts — a native Postgres without pgvector will fail at `CREATE EXTENSION`. |

## Open environment item

Docker 29.4.1 is installed but its daemon is not running, and something is already listening
on `localhost:5432`. Identify what that is before Track A begins: if it is a native Postgres
without the `vector` extension, either install pgvector into it or remap the container to
another port and update `DATABASE_URL`.
