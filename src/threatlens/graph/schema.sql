CREATE EXTENSION IF NOT EXISTS vector;

CREATE TABLE IF NOT EXISTS nodes (
    id           text PRIMARY KEY,
    kind         text NOT NULL,
    external_id  text NOT NULL,
    stix_id      text,
    name         text NOT NULL,
    description  text,
    attrs        jsonb NOT NULL DEFAULT '{}'::jsonb,
    source_url   text NOT NULL,
    embedding    vector(384)
);

CREATE UNIQUE INDEX IF NOT EXISTS nodes_kind_extid ON nodes (kind, external_id);

CREATE INDEX IF NOT EXISTS nodes_stix_id ON nodes (stix_id) WHERE stix_id IS NOT NULL;

CREATE TABLE IF NOT EXISTS node_chunks (
    node_id    text NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
    chunk_ix   int  NOT NULL,
    text       text NOT NULL,
    embedding  vector(384) NOT NULL,
    PRIMARY KEY (node_id, chunk_ix)
);

CREATE TABLE IF NOT EXISTS edges (
    src     text NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
    dst     text NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
    kind    text NOT NULL,
    weight  real NOT NULL DEFAULT 1.0,
    source  text NOT NULL,
    attrs   jsonb NOT NULL DEFAULT '{}'::jsonb,
    PRIMARY KEY (src, dst, kind)
);

CREATE INDEX IF NOT EXISTS edges_src_kind ON edges (src, kind);

CREATE INDEX IF NOT EXISTS edges_dst_kind ON edges (dst, kind);

CREATE TABLE IF NOT EXISTS ingest_runs (
    id          serial PRIMARY KEY,
    source      text NOT NULL,
    version     text NOT NULL,
    sha256      text NOT NULL,
    node_count  int NOT NULL,
    edge_count  int NOT NULL,
    ran_at      timestamptz NOT NULL DEFAULT now()
);
