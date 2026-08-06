# ThreatLens — Phase 1 Task Division

Working doc for the team. Full detail with actual code for every step is in
`docs/superpowers/plans/2026-08-03-phase1-attack-ingestion.md` — this is the summary.

**Goal:** MITRE ATT&CK Enterprise as a queryable Postgres graph, plus the Phase 2 parsers
that need no graph. No AI, no embeddings — pure data plumbing.

---

## Before anyone starts

**Blocker.** Docker is installed (29.4.1) but its daemon is not running, and something
already holds `localhost:5432`. Integration tests cannot run until this is sorted.

```bash
docker info                      # start Docker Desktop if this fails
```

If a native Postgres owns 5432, either install pgvector into it or remap the container to
`5433:5432` in `docker-compose.yml` and update `DATABASE_URL`. A Postgres without the
`vector` extension dies at `CREATE EXTENSION` and takes every integration test with it.

**Everyone, once:**

```bash
git clone https://github.com/Shane07p/ThreatLens.git
cd ThreatLens
uv sync --all-groups
cp .env.example .env             # fill in DATABASE_URL at minimum
docker compose up -d db
uv run pytest -m "not eval"      # should be green before you touch anything
```

---

## Step 1 — Task 0: the contract

**One person. Everyone else waits. ~90 minutes.**

Creates the types and store API that all four tracks build against:

- `src/threatlens/models.py` — `Node`, `Edge`, `Graph` (frozen dataclasses)
- `src/threatlens/graph/schema.sql` — `nodes`, `node_chunks`, `edges`, `ingest_runs`
- `src/threatlens/graph/store.py` — `get_engine`, `init_schema`, and **working**
  `upsert_nodes` / `upsert_edges`. Five read helpers ship as `NotImplementedError` stubs.

The upserts ship working rather than stubbed so Track B can validate parser output against a
real database from its first test, instead of finding a mismatch at merge time.

Branch `contract` → PR → merge to `main` → **tell the other three**.

> Changing the contract afterwards means telling all four people. It is small and derived
> from an already-settled schema, so it shouldn't happen — but if it must, it's a
> conversation, not a silent commit.

---

## Step 2 — Four tracks in parallel

### Track A — Foundation · ~3h · branch `track-a-foundation`

| Task | Deliverable |
|---|---|
| A1 | `config.py` — frozen `Settings` loaded once from env. **The only module that reads `os.environ`.** |
| A2 | The five store read helpers: `node_counts`, `edge_counts`, `get_node`, `neighbors`, `record_ingest_run` |

**Merges first.** B and C both need the store.
Best suited to whoever is most comfortable with SQL.

### Track B — STIX parser · ~6h · branch `track-b-stix-parser`

| Task | Deliverable |
|---|---|
| B1 | `tests/fixtures/mini-attack-bundle.json` + `ingest/attack.py` → 17 tests |
| B2 | Golden-graph snapshot — the regression gate |
| B3 | `ingest_attack()` — parse and write to Postgres |
| B4 | Verify against the **real** bundle, plus 5 hand checks against attack.mitre.org |

**The highest-risk track. Give it to your strongest person** (ideally the same one who did
Task 0). Every later phase inherits its output, and a parser that silently drops edges
produces a plausible-looking graph and a worthless ablation table.

Owns all four documented parsing corrections:

| # | Correction |
|---|---|
| D7 | ATT&CK ids come from `external_references[source_name == "mitre-attack"]`, not off the object |
| D8 | `BELONGS_TO` comes from `kill_chain_phases` — **there is no relationship object for it** |
| D9 | Skip `revoked` / `x_mitre_deprecated`; drop their edges and count them |
| D10 | Read `x_mitre_version` off the `x-mitre-collection` object |

Following the source guide literally instead of D8 yields **zero tactic edges** and a graph
that can't answer "what tactic is this."

### Track C — CLI + fetch · ~4h · branch `track-c-cli`

| Task | Deliverable |
|---|---|
| C1 | `ingest/fetch.py` — download, sha256, `data/manifest.json`, refuses to overwrite without `--force` |
| C2 | `cli.py` — `db init`, `fetch attack`, `ingest attack`, `stats`, `show` |
| C3 | End-to-end run on a clean database *(needs A and B merged)* |

Good first track — it's wiring, and CLI work gives fast visible feedback.
C1 and C2 can be written against the contract before A or B land.

### Track D — Phase 2 parsers · ~5h · branch `track-d-parsers`

| Task | Deliverable |
|---|---|
| D1 | `TokenBucket` rate limiter — tested with a fake clock, never a real `sleep` |
| D2 | `parse_cve_record` — CVSS v3.1 → v4.0 → `None`. **Never `0.0`.** |
| D3 | `parse_mappings_csv` → weighted `ENABLES` edges (primary 1.0, secondary 0.5) |
| D4 | `eval/metrics.py` — `recall_at_k`, `mrr`, `path_correct`, `citation_coverage` |

**Depends on nothing.** Can start before Task 0 even lands. Suits whoever's schedule is
least predictable.

---

## Merge order

```
contract ──► main
             │
      ┌──────┼──────┬──────┐
      ▼      ▼      ▼      ▼
      A      B      C      D
      │      │      │      │
   merge A first    │      │
      └──► merge B, then C │
                          └──► merge anytime
```

Only reason the order matters: B's golden test and C's `ingest attack` both need A's store.
Their *unit* tests don't, so nobody is blocked from **working** — only from merging last.

---

## Rules everyone follows

- **`uv add`, never `pip install`.** Dependencies belong in `pyproject.toml` + `uv.lock`.
- **Tests first on Tracks B and D.** A STIX parser and a CVSS fallback chain both fail
  *silently and plausibly* — the assertion written first is the only cheap way to know a
  dropped edge was intentional.
- **No `os.environ` outside `config.py`. No SQL outside `graph/`.**
- **No f-string SQL.** Parameterized queries only.
- **A missing CVSS score is `None`, never `0.0`.** A fake 0.0 severity reads as "no risk"
  in an answer.
- **Every write path is an upsert.** Re-running ingestion must not duplicate.
- Before every commit:
  ```bash
  uv run ruff check . && uv run ruff format . && uv run pytest -m "not eval"
  ```
- Branch per track, PR with CI green, no direct pushes to `main`.
- Conventional Commits, phase-scoped. No Claude/Anthropic co-author lines.

---

## Definition of done

- [ ] `threatlens db init` creates the schema on an empty Postgres
- [ ] `threatlens fetch attack` writes the bundle and a manifest entry with sha256
- [ ] `threatlens ingest attack` loads the graph; a second run changes no counts
- [ ] Counts in range: ~650 techniques, **exactly 14 tactics**, ~45 mitigations,
      ~170 actors, ~750 software
- [ ] Every technique has ≥1 `BELONGS_TO` edge
- [ ] No revoked or deprecated object present; no dangling edges
- [ ] 5–10 manual spot checks against attack.mitre.org agree
- [ ] `ingest_runs` has a row with the ATT&CK version and file sha256
- [ ] Track D parsers pass their suites
- [ ] `uv run pytest -m "not eval"` green

Two of those are hard gates, not guidelines: **exactly 14 tactics** and **zero techniques
without a tactic**. Either one off means D8 was missed and the parser needs fixing before
anything downstream is trustworthy.

---

## Where to look things up

| Question | File |
|---|---|
| Step-by-step with real code | `docs/superpowers/plans/2026-08-03-phase1-attack-ingestion.md` |
| Why the design is shaped this way | `docs/superpowers/specs/2026-08-03-phase1-attack-ingestion-design.md` |
| Node/edge model, DDL, traversal SQL | `.claude/graph-schema.md` |
| Data sources, exact URLs | `.claude/data-sources.md` |
| Test layout, markers, CI | `.claude/testing.md` |
| Why we deviate from the source docs | `.claude/decisions.md` |
| Build order and cut list | `.claude/phases.md` |
