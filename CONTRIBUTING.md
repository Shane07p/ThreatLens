# Contributing

ThreatLens has two active maintainers, so every pull request has exactly one possible human
reviewer. CI and the automated reviewers carry the rest of the weight, which is why the
checks below are strict.

## Set up once

```bash
git clone https://github.com/Shane07p/ThreatLens.git && cd ThreatLens
uv sync --all-groups                  # Python 3.12, pinned in .python-version
cp .env.example .env                  # DATABASE_URL and THREATLENS_TEST_DSN at minimum
docker compose up -d db               # Postgres 16 + pgvector, plus a test database
uv run threatlens db init
uv run pre-commit install             # lint, format, type-check and secret-scan on commit
uv run pytest -m "not eval"           # must be green before you change anything
```

Full environment notes, API keys, and troubleshooting:
[docs/conventions/setup.md](docs/conventions/setup.md).

Dependencies are added with `uv add`, never `pip install` — `uv.lock` is exactly what CI
installs. `requirements.txt` exists for pip users and is not authoritative.

## Make a change

1. **Branch from an up-to-date `main`.** `git checkout main && git pull && git checkout -b
   <name>/<topic>`. One topic per branch.
2. **Test first** for parsers, traversal, and ranking — those fail silently and plausibly.
   See [docs/conventions/testing.md](docs/conventions/testing.md).
3. **Run the checks** before pushing. The pre-commit hook covers most of it:
   ```bash
   uv run ruff check . && uv run ruff format . && uv run mypy && uv run pytest -m "not eval"
   ```
4. **Rebase if `main` moved** — `git fetch origin && git rebase origin/main` — and re-run the
   checks. Never force-push a branch the other maintainer may have pulled.
5. **Open a pull request** and fill in the template. Keep it reviewable: a parser and a CI
   rewrite are two pull requests.

## Commits

[Conventional Commits](https://www.conventionalcommits.org/), scoped by module:

```
feat(ingest): parse kill_chain_phases into tactic edges
fix(graph): keep DISTINCT ON in a subquery so LIMIT keeps the cheapest nodes
test(retrieval): assert RRF tie-breaks are deterministic
```

Types: `feat`, `fix`, `test`, `docs`, `refactor`, `chore`, `ci`. The subject is imperative and
under about 60 characters. Add a body only when the *why* is not obvious from the diff.

## Review and merge

`main` is protected. A pull request merges when:

- **CI Gate** passes — it aggregates lint, type check, both test suites, the secret scan, and
  the workflow audit ([.github/workflows/ci.yml](.github/workflows/ci.yml))
- the other maintainer approves
- automated review comments are answered — fixed, or replied to with the reason not

Merge with a **merge commit or a rebase, never a squash.** Squashing collapses each
contributor's commits into one authored by whoever clicked merge, which erases credit from
the history and the contribution graph ([CONTRIBUTORS.md](CONTRIBUTORS.md)).

## Working with AI coding agents

Agents are welcome here, under three conditions:

- They read [AGENTS.md](AGENTS.md), which most agents load automatically. Do not add a
  `CLAUDE.md`, `GEMINI.md`, or `.cursorrules` alongside it — each becomes a second copy of
  the rules that drifts from the first, and a `CLAUDE.md` stops Claude Code from reading
  `AGENTS.md` at all.
- **You are the author of everything you commit.** Read every line an agent wrote before it
  goes into a pull request. "The agent did it" is not an answer in review.
- No AI attribution in commits, pull request descriptions, or tags.

## Where things are documented

| Need | Read |
|---|---|
| How the code is organised | [ARCHITECTURE.md](ARCHITECTURE.md) |
| All design and planning docs | [docs/README.md](docs/README.md) |
| Code style, boundaries, comments | [docs/conventions/code.md](docs/conventions/code.md) |
| Git, data handling, secrets, CI | [docs/conventions/workflow.md](docs/conventions/workflow.md) |
| Why something differs from the spec | [docs/design/decisions.md](docs/design/decisions.md) |
| Reporting a vulnerability | [SECURITY.md](SECURITY.md) |
