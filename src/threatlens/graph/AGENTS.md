# AGENTS.md — src/threatlens/graph/

Adds to the root [AGENTS.md](../../../AGENTS.md). Background:
[docs/design/graph-schema.md](../../../docs/design/graph-schema.md).

The only directory in the project that contains SQL. If code elsewhere needs a query, add a
function to `store.py` and call it.

## Rules

- **Parameterized queries only.** `sqlalchemy.text()` with bound parameters, every time —
  including one-off scripts. No f-strings, no `%` formatting, no string concatenation.
- **`schema.sql` must be safe to re-run.** Every statement is `IF NOT EXISTS`, because
  `threatlens db init` applies it to databases that already have it.
- **Writes are upserts on the primary key.** `edges` is keyed on `(src, dst, kind)`, so a
  duplicate edge cannot exist. Do not add a `DISTINCT` to guard against one — it can never
  fire, and an earlier one survived mutation testing for exactly that reason.
- **Query-time reads never write.** Anything that changes the graph belongs to ingestion.

## Traversal traps

- **The budget bounds the work.** `traverse` expands one depth at a time and keeps only the
  cheapest `node_budget` routes before expanding again. Do not turn it back into one
  recursive CTE: Postgres cannot apply a budget inside the recursive term, so the CTE
  enumerated every simple path first (3.9 s p95 at depth 4 on the real graph, now 36 ms).
  See D20.
- **The pruning is exact only while every step costs something.** It relies on
  `1 / max(weight, 0.01)` being positive. A zero- or negative-cost step, a cost that can
  shrink along a route, or a different cost function needs the argument in D20 redone,
  and `test_traversal_properties.py` must still pass against its unpruned reference.
- **Ties are part of the contract.** Results sort by cost, then depth, then id, and a node
  reached by equally cheap routes reports the shortest. Changing the sort key changes
  which nodes survive when the budget binds — exactly when nobody is looking.
- The timing test on a dense graph is the only thing that proves the bound. A results-only
  test passes for the exhaustive walk too.
