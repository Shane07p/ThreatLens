# AGENTS.md — src/threatlens/ingest/

Adds to the root [AGENTS.md](../../../AGENTS.md). Background:
[docs/design/data-sources.md](../../../docs/design/data-sources.md) and
[docs/design/graph-schema.md](../../../docs/design/graph-schema.md).

This directory turns upstream snapshots into nodes and edges. It is the only code allowed
to touch the network, and it runs offline before any query — never at query time.

## Shape

- `parse_*` functions are pure: a file path or dict in, `Node`/`Edge`/`Graph` out. No
  database, no network. Most tests target these.
- `ingest_*` functions orchestrate the write and record provenance. All SQL goes through
  `graph/store.py`; nothing here builds a query.
- `fetch.py` downloads. It refuses to overwrite a snapshot without `--force`, and writes url,
  sha256, and timestamp into `data/manifest.json`.

## Rules

- **Tolerant in, visible loss.** Log a malformed record with its id, skip it, and count it.
  A long ingest must not die on one bad row, but a silent skip looks exactly like a bug.
- **Count only real loss.** An object or edge type this schema does not model is out of
  scope, not skipped. Counting out-of-scope edges once made a healthy bundle report 1,723
  losses when 2 objects were actually lost.
- **A missing value is `None`.** A missing CVSS score, version, or tactic position stays
  `None` — never `0.0`, `"1.0"`, or a sentinel index.
- **Every write is an upsert.** Re-running the *same* snapshot must leave every count
  unchanged. That is not the same as a correct refresh: upserting a newer snapshot never
  removes an object that was revoked or dropped upstream, so stale nodes and their edges
  survive. A refresh needs the old snapshot's rows removed, not just the new ones added.
- **Pin what you fetched.** A snapshot the graph depends on but nobody can identify later
  makes every number built on it unreproducible.

## STIX traps, each already guarded by a test

- The ATT&CK id (`T1190`) lives in `external_references` where `source_name ==
  "mitre-attack"`, not on the object.
- Technique → tactic comes from `kill_chain_phases`. There is no relationship object for it.
- Revoked and deprecated objects are still in the bundle and must be filtered out.
- The version is on the `x-mitre-collection` object. Kill-chain order is `tactic_refs` on
  the `x-mitre-matrix` object — never a hard-coded list, because the tactic count changes
  between releases.

## CSV traps

- Upstream CSVs can begin with a UTF-8 byte-order mark. Read them with
  `encoding="utf-8-sig"` and check the required headers exist. Under plain `utf-8` the BOM
  becomes part of the first column's name, so a lookup of `"CVE ID"` misses on every row
  and the whole file is skipped without an error.
- A mapping cell can hold several ids separated by `;` (`T1499; T1098`). Split, trim, and
  validate each one; never turn the whole cell into one node id.
- If a non-empty file yields zero usable rows, fail loudly. That outcome is never a
  legitimate result.

## HTTP traps

- `Content-Length` describes the *encoded* body. httpx decodes gzip transparently, so never
  compare it against decoded bytes — that check once rejected every real ATT&CK download.
- The NVD rate limiter is mandatory. Test it with a fake clock, never a real `sleep`, and
  test the *window*, not just the spacing: a token bucket that starts full allows a burst
  plus a steady refill, which can exceed "5 requests per 30 seconds" inside one window.
