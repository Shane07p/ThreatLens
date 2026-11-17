# AGENTS.md — tests/

Adds to the root [AGENTS.md](../AGENTS.md). Full guide:
[docs/conventions/testing.md](../docs/conventions/testing.md).

Testing is the priority here. A parser that silently drops edges, or a ranking that inverts
its sort, still produces plausible output — only an assertion turns that into a decision
rather than an accident.

## Where a test goes

| Testing | Directory | Marker |
|---|---|---|
| Pure logic: parsing, maths, ranking, formatting | `tests/unit/` | none |
| Anything that touches Postgres | `tests/integration/` | `db` |
| Real model weights or a large corpus | either | `slow` |
| Anything that calls an LLM | `tests/eval/` | `eval` — never in CI |

`conftest.py` blocks network access for tests not marked `db` or `eval` — Python sockets
*and* psycopg's `connect`, since libpq opens its own sockets in C where a socket patch cannot
see them. Integration tests connect through `THREATLENS_TEST_DSN` and truncate their
tables in a fixture.

## Beyond example tests

Parsers and anything taking untrusted input also get property tests (Hypothesis) in
`test_<module>_properties.py`: state an invariant, let it generate the inputs. CI checks
coverage of each PR's changed lines (diff-cover) and runs mutation testing weekly (mutmut,
Linux only). Details: [testing.md](../docs/conventions/testing.md#beyond-example-tests).

## Test-case report

`uv run pytest -m "not eval" --case-report=test-results/test-cases.csv` (with `=`) lists every test
with its level, white/black-box technique, positive/negative type, input, expected result,
and actual outcome ([how it classifies](../docs/conventions/testing.md#test-case-report)).
Mark security tests `@pytest.mark.security`; correct a wrong inference with
`@pytest.mark.negative`, `@pytest.mark.positive`, or `@pytest.mark.case(...)`.

## Rules

- **Write the test first** for parsers, traversal, and ranking. Watch it fail for the reason
  you expect before writing the fix.
- **Confirm the test can fail.** After it passes, break the implementation once and check it
  goes red. If it stays green, it is not testing what its name says.
- **Name the test after the behaviour** — `test_revoked_objects_are_skipped`, never
  `test_parse_2`. Add a docstring when the reason is not obvious, and always when the test
  guards a bug that already happened.
- **Assert properties, not incidental values.** Orderings rather than float scores;
  invariants (no dangling edges, every technique has a tactic) rather than counts that move
  with each upstream release.
- **Keep ignored and lost apart.** Something deliberately out of scope must not be counted
  as an error, and something genuinely dropped must be. Assert both sides.
- **Build robustness inputs inline** with small helpers, so the shape under test is visible
  in the test. Use `fixtures/` for shared realistic inputs.
- **Golden files are read by a human before they are committed**, and are never regenerated
  to make a red test green.
- **Never weaken an assertion or add a skip to get green.** A skipped test that should run is
  worse than a failing one.
- **No network, database, or model weights in unit tests.** Use the stub encoder for
  embeddings. It is not suitable for nearest-neighbour tests — its vectors are all positive,
  so any two score about 0.75 — write those vectors by hand.
