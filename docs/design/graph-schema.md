# Graph schema

One generic `nodes` table and one generic `edges` table. Type-specific fields live in
`attrs jsonb`. This keeps traversal polymorphic — one query walks any edge type — instead
of needing a UNION per node type.

## Nodes

| `kind` | `external_id` example | Source |
|---|---|---|
| `technique` | `T1190`, `T1059.001` | ATT&CK `attack-pattern` |
| `tactic` | `TA0001` | ATT&CK `x-mitre-tactic` |
| `mitigation` | `M1030` | ATT&CK `course-of-action` |
| `actor` | `G0016` (APT29) | ATT&CK `intrusion-set` |
| `software` | `S0154` | ATT&CK `malware` / `tool` |
| `cve` | `CVE-2024-1234` | NVD |
| `detection` | Sigma rule id | Sigma (optional, v1.5) |

## Edges

| `kind` | From → To | Source | Weight |
|---|---|---|---|
| `ENABLES` | cve → technique | Mappings Explorer | 1.0 primary, 0.5 secondary or exploitation, 0.25 uncategorized |
| `BELONGS_TO` | technique → tactic | `kill_chain_phases` (**not** a relationship object) |1.0|
| `SUBTECHNIQUE_OF` | technique → technique | relationship `subtechnique-of` | 1.0 |
| `MITIGATED_BY` | technique → mitigation | relationship `mitigates` (reversed) | 1.0 |
| `USES` | actor → technique | relationship `uses` | 1.0 |
| `USES_SOFTWARE` | actor → software | relationship `uses` | 1.0 |
| `CHAINS_TO` | technique → technique | **derived** — see below | co-occurrence count, normalized |
| `DETECTED_BY` | technique → detection | Sigma frontmatter | 1.0 |

## DDL

`src/threatlens/graph/schema.sql`:

```sql
CREATE EXTENSION IF NOT EXISTS vector;

CREATE TABLE nodes (
    id           text PRIMARY KEY,          -- stable: "technique:T1190", "cve:CVE-2024-1234"
    kind         text NOT NULL,
    external_id  text NOT NULL,             -- T1190, CVE-2024-1234, M1030
    stix_id      text,                      -- attack-pattern--<uuid>, null for CVEs
    name         text NOT NULL,
    description  text,
    attrs        jsonb NOT NULL DEFAULT '{}'::jsonb,
    source_url   text NOT NULL,             -- the citation target
    embedding    vector(384)
);
CREATE UNIQUE INDEX nodes_kind_extid ON nodes (kind, external_id);
CREATE INDEX nodes_stix_id ON nodes (stix_id) WHERE stix_id IS NOT NULL;
CREATE INDEX nodes_embedding_hnsw ON nodes USING hnsw (embedding vector_cosine_ops);

-- bge-small truncates at 512 tokens; long descriptions are chunked (decisions.md D6)
CREATE TABLE node_chunks (
    node_id      text NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
    chunk_ix     int  NOT NULL,
    text         text NOT NULL,
    embedding    vector(384) NOT NULL,
    PRIMARY KEY (node_id, chunk_ix)
);
CREATE INDEX node_chunks_hnsw ON node_chunks USING hnsw (embedding vector_cosine_ops);

CREATE TABLE edges (
    src     text NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
    dst     text NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
    kind    text NOT NULL,
    weight  real NOT NULL DEFAULT 1.0,
    source  text NOT NULL,                  -- "attack-stix v19.1", "mappings-explorer kev"
    attrs   jsonb NOT NULL DEFAULT '{}'::jsonb,
    PRIMARY KEY (src, dst, kind)
);
CREATE INDEX edges_src_kind ON edges (src, kind);
CREATE INDEX edges_dst_kind ON edges (dst, kind);

-- provenance: which snapshot produced this graph
CREATE TABLE ingest_runs (
    id          serial PRIMARY KEY,
    source      text NOT NULL,
    version     text NOT NULL,              -- "enterprise-attack v19.1"
    sha256      text NOT NULL,              -- of the downloaded file
    node_count  int NOT NULL,
    edge_count  int NOT NULL,
    ran_at      timestamptz NOT NULL DEFAULT now()
);
```

Node ids are `"{kind}:{external_id}"` — deterministic, so ingestion is idempotent and
re-running an ingest upserts rather than duplicating.

## Bounded multi-hop traversal

`src/threatlens/graph/traverse.py` walks outward one depth at a time. Each level is one
indexed query for the arcs leaving the current frontier:

```sql
SELECT src AS from_id, dst AS to_id, weight
FROM edges WHERE kind = ANY(:edge_kinds) AND src = ANY(:frontier)
UNION ALL
SELECT dst AS from_id, src AS to_id, weight
FROM edges WHERE kind = ANY(:reverse_kinds) AND dst = ANY(:frontier)
```

Python then keeps the cheapest route to each node reached, drops any route that revisits a
node, and carries only the cheapest `node_budget` routes into the next level. The result is
each node's cheapest route of at most `max_depth` hops, the shortest among equally cheap
ones, ordered by cost, then depth, then id, and cut to `node_budget`.

Notes:
- **The budget bounds the work, not just the result** — see [decisions.md](decisions.md)
  D20. Each level touches at most `node_budget` frontier nodes, so a walk costs
  `max_depth + 2` indexed queries however dense the graph is. The earlier recursive CTE
  enumerated every simple path before applying the budget: 267,745 rows for a budget of one
  on 25 dense nodes, and a 3.9 s p95 at depth 4 on the real graph (now 36 ms).
- **The pruning is exact because every step costs something.** Cost is inverse weight
  (`1 / max(weight, 0.01)`), so it is always positive. A route dropped at some level costs
  at least as much as `node_budget` nodes already reached, so nothing it leads to can make
  the final cut. A zero- or negative-cost step would break that argument; the property
  test in `tests/integration/test_traversal_properties.py` compares against an unpruned
  brute-force walk to catch it.
- Defaults: `max_depth=3`, `node_budget=200`. Tune in `config.py`, not inline.

## The `CHAINS_TO` derivation

The fuzziest edge in the graph. Definition used here — deliberately narrow so it can be
defended:

> Techniques A and B are chained if ≥ `MIN_SHARED_ACTORS` distinct threat actors are
> documented using both. Direction runs from earlier to later kill-chain phase.

```sql
INSERT INTO edges (src, dst, kind, weight, source, attrs)
SELECT  a.technique_id, b.technique_id, 'CHAINS_TO',
        count(*)::real / %(max_shared)s,
        'derived: actor co-occurrence',
        jsonb_build_object('shared_actors', count(*))
FROM actor_techniques a
JOIN actor_techniques b ON a.actor_id = b.actor_id AND a.technique_id <> b.technique_id
JOIN tactic_order ta ON ta.technique_id = a.technique_id
JOIN tactic_order tb ON tb.technique_id = b.technique_id
WHERE ta.phase_ix < tb.phase_ix
GROUP BY a.technique_id, b.technique_id
HAVING count(*) >= %(min_shared_actors)s;
```

`MIN_SHARED_ACTORS = 3`. Lower and the graph fills with noise; higher and rare-but-real
chains vanish. **Say in the README that this is a co-occurrence heuristic, not observed
sequence data.** Overclaiming here is the easiest way to lose credibility.

`tactic_order` is a static map of the 14 Enterprise tactic shortnames to their kill-chain
index (`reconnaissance`=0 … `impact`=13). A technique in multiple tactics gets its lowest
index.

## STIX → graph gotchas

These are corrections to the data-sources guide; see [decisions.md](decisions.md) D7–D10.

1. **ATT&CK ids are not on the object.** `T1190` lives in
   `obj["external_references"]` where `source_name == "mitre-attack"` → `external_id`.
   The same block's `url` is the citation target.
2. **`BELONGS_TO` is not a relationship object.** Technique → tactic comes from
   `obj["kill_chain_phases"]` where `kill_chain_name == "mitre-attack"`, matching
   `phase_name` against the tactic's `x_mitre_shortname`.
3. **Filter revoked and deprecated.** Skip objects with `revoked is True` or
   `x_mitre_deprecated is True`, and drop edges pointing at them. Otherwise the graph
   contains retired techniques that will never match ground truth.
4. **The bundle contains an `x-mitre-collection` object.** Read its `x_mitre_version` and
   record it in `ingest_runs`; it is the ATT&CK version to cite in the README.
