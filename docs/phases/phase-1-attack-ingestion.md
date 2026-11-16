# Phase 1 — ATT&CK ingestion

**Status:** not started
**Goal:** the ATT&CK Enterprise matrix as a queryable graph in Postgres.
**No AI in this phase.** No embeddings, no LLM. Pure data plumbing.

## Steps

1. **Scaffold.**
   ```bash
   uv add stix2 psycopg[binary] sqlalchemy typer python-dotenv
   uv add --dev pytest pytest-timeout ruff
   ```
   Create `src/threatlens/{__init__,cli,config}.py`, `graph/{schema.sql,store.py}`,
   `ingest/attack.py`.

2. **Database up.** `docker compose up -d db`, then `threatlens db init` runs
   `graph/schema.sql` (see [graph-schema.md](../design/graph-schema.md) for the DDL).

3. **Fetch the bundle.** `threatlens fetch attack` →
   `data/raw/enterprise-attack.json`, sha256 + version recorded in `data/manifest.json`.

4. **Parse.** `stix2.MemoryStore().load_from_file(...)`, then branch by `type`.

   Read [graph-schema.md](../design/graph-schema.md) § STIX → graph gotchas **first**. The four that
   will bite otherwise:
   - ATT&CK ids come from `external_references[source_name == "mitre-attack"].external_id`,
     not off the object.
   - Technique → tactic comes from `kill_chain_phases[].phase_name` matched to the tactic's
     `x_mitre_shortname`. **There is no relationship object for this** — follow the data
     guide literally and you get zero tactic edges.
   - Skip `revoked: true` and `x_mitre_deprecated: true`; drop edges pointing at them.
   - Read `x_mitre_version` off the `x-mitre-collection` object into `ingest_runs`.

5. **Load nodes.** techniques (incl. sub-techniques), tactics, mitigations, actors,
   software. Node id = `{kind}:{external_id}`. `source_url` = the mitre-attack external
   reference url — that is the citation target for every claim about this node.

6. **Load edges** from `relationship` objects:

   | `relationship_type` | edge |
   |---|---|
   | `mitigates` (course-of-action → attack-pattern) | `technique --MITIGATED_BY--> mitigation` (reversed) |
   | `uses` (intrusion-set → attack-pattern) | `actor --USES--> technique` |
   | `uses` (intrusion-set → malware/tool) | `actor --USES_SOFTWARE--> software` |
   | `subtechnique-of` | `technique --SUBTECHNIQUE_OF--> technique` |

   Plus `BELONGS_TO` from `kill_chain_phases` (step 4).

7. **Bulk insert, upsert on PK.** Re-running ingestion must not duplicate anything.

8. **Verify by hand.** Not optional — this is the phase where a silent parsing bug is
   cheapest to catch.
   ```bash
   uv run threatlens stats
   uv run threatlens show T1190
   uv run threatlens list --tactic TA0001     # all Initial Access techniques
   uv run threatlens list --actor G0016       # APT29's techniques
   ```
   Open the ATT&CK website for T1190 and compare, field by field: name, description,
   tactic, mitigations, actors. Then repeat for one sub-technique (`T1059.001`) and one
   mitigation (`M1030`).

## Sanity expectations

Order-of-magnitude only — exact counts move between ATT&CK releases. If a number is off by
10x, the parser is wrong.

| Node kind | Expect roughly |
|---|---|
| technique (incl. sub) | ~650 |
| tactic | 14 |
| mitigation | ~45 |
| actor | ~170 |
| software | ~750 |

Every technique must have ≥1 `BELONGS_TO` edge. Zero tactic edges means the
`kill_chain_phases` path was missed. A count of exactly 14 tactics is the quickest signal
the tactic parse worked.

## Tests that must pass

`tests/unit/test_stix_parse.py`, `tests/integration/test_schema.py`,
`tests/integration/test_upsert_idempotent.py`. Full list in
[testing.md](../conventions/testing.md).

Build `tests/fixtures/mini-attack-bundle.json` here — ~20 hand-checked objects including
one revoked, one deprecated, one sub-technique, one technique in two tactics. Every later
phase reuses it.

```bash
uv run pytest -m "not eval"
```

## Done when

- [ ] `threatlens db init` creates the schema from scratch on an empty Postgres
- [ ] `threatlens fetch attack` writes the bundle + manifest entry with sha256 and version
- [ ] `threatlens ingest attack` loads nodes and edges; a second run changes no counts
- [ ] `threatlens stats` counts are in the expected range
- [ ] Every technique has ≥1 `BELONGS_TO` edge
- [ ] Revoked and deprecated objects are absent, and no edge dangles
- [ ] 5–10 manual spot checks against the ATT&CK website agree
- [ ] `ingest_runs` has a row with the ATT&CK version and file sha256
- [ ] `uv run pytest -m "not eval"` is green

## Next

[Phase 2 — CVE bridge](phase-2-cve-bridge.md)
