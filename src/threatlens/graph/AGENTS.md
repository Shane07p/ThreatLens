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

- `DISTINCT ON (id)` forces `ORDER BY` to lead with `id`. Keep it in a subquery, then order
  by cost and apply `LIMIT` outside. Collapsed into one level, the budget keeps the
  alphabetically first nodes rather than the cheapest — wrong only when the budget binds,
  which is exactly when nobody is testing.
- The `NOT dst = ANY(path)` guard stops a path revisiting a node. It bounds path *length*,
  not the *number* of paths, and it is not what makes the walk terminate — `max_depth` is.
- **`node_budget` caps the output, not the work.** The CTE enumerates every simple path up
  to `max_depth`, deduplicates, sorts, and only then applies `LIMIT`. Twenty-five densely
  connected nodes at depth 4 produce 267,745 intermediate rows to return a budget of one.
  Densely derived edges such as `CHAINS_TO` make that the realistic shape, not a corner case.
  Until the budget is enforced during expansion and a statement timeout is set, measure
  before raising `max_depth`, and pass it explicitly in evaluation runs.
