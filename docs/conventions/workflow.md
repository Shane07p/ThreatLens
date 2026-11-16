# Other rules

Git, repository visibility, CI, data handling, secrets, and working style.
Code and comment rules are in [code.md](code.md); testing is in
[testing.md](testing.md).

---

## Git and commits

**Commits carry no AI attribution.** No `Co-Authored-By: Claude`, no
`Generated with Claude Code`, no Anthropic mention in a commit message, pull request
description, or tag. Commits are authored by the repository owner alone. This applies to
every commit without exception and does not need re-asking. It is enforced mechanically by
`attribution: {commit: "", pr: ""}` in `.claude/settings.json`.

**Conventional Commits.** `type(scope): summary` — `feat`, `fix`, `docs`, `test`, `chore`,
`refactor`. Scope is the module: `ingest`, `graph`, `retrieval`, `agent`, `eval`, `cli`, `ci`.

```
feat(ingest): parse kill_chain_phases into tactic edges
fix(graph): force the psycopg driver so CI does not reach for psycopg2
test(ingest): cover malformed and duplicate STIX objects
```

Subject in the imperative, under ~60 characters. A body only when the *why* is not obvious
from the diff — and then explain the reasoning, not the mechanics.

**Never push without being asked.** Show what is staged and the commit message, then wait.

**Always check the remote before pushing.** Other people are working:

```bash
git fetch origin && git log HEAD..origin/main --oneline
```

If the remote is ahead, `git pull --rebase`, re-run the checks, then push. Never force-push
a branch someone else may have pulled.

**Verify, don't assert.** "Pushed" means `git rev-parse HEAD` equals
`git rev-parse origin/main`. Check it rather than assuming the command worked.

**Keep unrelated work in separate commits.** A commit that adds a parser and rewrites the
CI config is two commits.

---

## Branching

`main` is protected. One branch per work track, merged by pull request with CI green.

```bash
git checkout main && git pull
git checkout -b track-b-stix-parser
# work, commit, run the checks
git push -u origin track-b-stix-parser
```

Rebase rather than merge when `main` moves under you — it keeps history linear and makes
`git log` readable:

```bash
git checkout main && git pull
git checkout track-b-stix-parser && git rebase main
```

GitHub settings that matter: `main` protected by a ruleset requiring one approving review
and the single **CI Gate** status check. The gate aggregates every other job, so adding a
job never means touching repository settings. Merge methods are merge commit and rebase;
squash is disabled because it erases contributor credit.

---

## Repository visibility

**Public since 2026-11-17**, with its real history. Squashing would have cost every
contributor their commit history and their contribution graph, and the development history
is evidence the work was understood rather than generated.

Everything pushed is published immediately — every branch, every commit, every file that was
ever added and later deleted. Three things guard that:

- **Push protection** (GitHub secret scanning) rejects a push containing a recognised token.
- **gitleaks** runs in pre-commit and over the full history in CI, which also catches
  generic secrets such as passwords in connection strings.
- **GitHub secret scanning** raises an alert for anything that gets through.

**If a secret is pushed, rotate it first.** Deleting the commit is not enough: it stays
reachable by SHA, it may already be in someone's clone or a mirror, and automated scrapers
read public pushes within minutes. Rewriting history afterwards is clean-up, not
containment — and on a public repository it breaks every existing clone, so it needs both
maintainers to agree.

**Local-only, never committed:** `.env`, `CLAUDE.md`, `CLAUDE.local.md`,
`task-division.md`, `data/raw/`. The two `CLAUDE` files are excluded for a functional reason,
not a cosmetic one: if either exists, Claude Code reads it *instead of* `AGENTS.md`, so
committing one would silently switch off the shared agent instructions for everyone.
**Committed deliberately:** `data/eval/holdout.jsonl` and `data/manifest.json` — without
them nobody can check a published number.

---

## CI

`.github/workflows/ci.yml` runs on every pull request, every push to `main`, and manual
dispatch. Branch protection points at one job, **CI Gate**, which passes only when every
other job did.

| Job | Does | Why |
|---|---|---|
| Lint and type check | `ruff check`, `ruff format --check`, `mypy` | Type hints on every function are a rule; mypy makes it a mechanical one |
| Unit tests (Python 3.13) | `pytest -m "not db and not eval"` on the newest supported Python | Catches version-specific breakage without running everything twice |
| Full suite (Python 3.12) | `pytest -m "not eval"` against a `pgvector/pgvector:pg16` service, with coverage | The real database, and a coverage floor so untested modules cannot slip in |
| Secret scan | gitleaks over the **entire** history | A key committed and later deleted is still in the history |
| Workflow audit | zizmor over `.github/workflows/` | Workflows run with repository credentials; a bad one is a supply-chain hole |

Every action is pinned to a full commit SHA, with the version in a trailing comment so
Dependabot can bump both. Jobs run with read-only `contents` permission, and checkouts do
not persist credentials.

**CI never runs the eval suite.** Those tests call a paid API and are non-deterministic. A
build that goes red for reasons outside the diff is a build people learn to ignore.

**Run the same commands locally before pushing** — `uv run pre-commit install` once makes
most of this automatic:

```bash
uv run ruff check . && uv run ruff format . && uv run mypy && uv run pytest -m "not eval"
```

`uv.lock` is committed so CI installs exactly what you ran, and a transitive dependency
releasing a broken version cannot turn the build red on its own.

**A red build is stopped work.** Fix it or revert it; do not stack commits on top.

## Automated maintenance

**Dependabot** ([.github/dependabot.yml](../../.github/dependabot.yml)) checks monthly for
Python dependencies, GitHub Actions, the pre-commit hooks, and the Postgres image. Minor and
patch updates arrive as one grouped pull request per ecosystem; a major version arrives on
its own so it can be read properly. A new release must be at least a week old before
Dependabot proposes it, which keeps a compromised or yanked release from landing the day it
ships. **Security updates ignore the schedule** and open as soon as an advisory is published.

Treat a Dependabot pull request like any other: CI green, read the changelog for anything
major, then merge.

**AI review.** [.coderabbit.yaml](../../.coderabbit.yaml) configures CodeRabbit with this
project's rules per directory. It is free because the repository is public, and takes
effect once the GitHub app is installed. With two maintainers, an automated first pass is
worth having — but it supplements the human review, it never replaces the approval. Do not
enable its Autofix: it would commit to pull request branches.

**CodeQL** runs as GitHub's default setup — no workflow file to maintain — with the
`security-extended` query suite over the Python and the workflows, on every pull request, on
pushes to `main`, and weekly. Findings appear under the Security tab. A finding is treated
like a failing test: fix it, or dismiss it with a written reason.

---

## Data

**Snapshots, never live APIs at query time.** Ingestion writes to `data/`; query-time code
must never call NVD, GitHub, or MITRE.

**Pin every snapshot.** URL, sha256, version, and timestamp go into `data/manifest.json` and
the `ingest_runs` table. "Built against ATT&CK v19.1" is checkable; "built against ATT&CK"
is not. A graph that shifts mid-project makes every previously measured number
incomparable, and nothing warns you.

**Fetching refuses to overwrite** an existing snapshot without an explicit `--force`.

**Never regenerate the evaluation holdout.** It is split once with a fixed seed and
committed. Regenerating it invalidates every published number, silently. A checksum test
guards it; if that test fails, something upstream is wrong — investigate rather than
re-rolling.

**A missing value is `None`, never a plausible default.** A fabricated `0.0` severity reads
as "no risk" in an answer that someone may act on.

**Every generated claim carries a citation** to a node id. Ungrounded output is a bug, not a
style preference.

---

## Secrets

`.env` only, read through `config.py`, gitignored. Never hardcoded, never committed, never
pasted into a test file "just to check something".

`.claude/settings.json` denies reads of `.env` so its contents cannot be pulled into a
transcript.

This project will accumulate an NVD key plus up to seven LLM provider keys. The honest case
is handled by `.gitignore`; the dishonest case is a key pasted into a notebook at 2am, which
is what the pre-publish scan is for.

---

## Working style

**Verify before claiming.** Run the command and read the output. "Tests pass" means the
suite was run in this session. If something was skipped, say it was skipped, and say why.

**Report failures with the output**, not a summary of the output.

**Ask when two readings would produce materially different work.** Otherwise make the call,
say which call was made, and continue.

**Raise a concern once, then follow the decision.** Disagreement is stated in a sentence or
two, not relitigated.

**Look before deleting or overwriting.** Especially anything that is the only copy of
something.

**Finish the whole task.** If part of it is blocked, complete everything else and say
plainly what was left and why.
