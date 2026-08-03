# Other rules

Git, repository visibility, CI, data handling, secrets, and working style.
Code and comment rules are in [coderule.md](coderule.md); testing is in
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

GitHub settings that matter: collaborators added, `main` protected, required status checks
set to `lint` and `test`. Status check names only appear in that dropdown after they have
run once, so open one pull request first.

---

## Repository visibility

Private during development, public at the end.

The plan is to push the **real history** to the public repository. Squashing costs every
contributor their commit history and their contribution graph, and the development history
is evidence the work was understood rather than generated.

**Before anything goes public, scan the whole history for secrets:**

```bash
docker run --rm -v "$(pwd):/repo" zricethezav/gitleaks:latest detect --source=/repo -v
```

A key in a public commit is compromised the moment it lands. Rotate it — deleting the commit
is not enough, because it can be served by SHA until garbage collection.

If one specific file must not be public, filter it out of a **mirror clone** rather than the
working repository, so nobody's clone breaks:

```bash
git clone --mirror <url> tmp-publish && cd tmp-publish
git filter-repo --path <file> --invert-paths
git push <public-remote> --all
```

**Local-only, never committed:** `.env`, `CLAUDE.md`, `task-division.md`, `data/raw/`.
**Committed deliberately:** `data/eval/holdout.jsonl` and `data/manifest.json` — without
them nobody can check a published number.

---

## CI

`.github/workflows/ci.yml` runs on every push and pull request:

| Job | Does |
|---|---|
| `lint` | `ruff check` + `ruff format --check` |
| `test` | `pytest -m "not eval"` against a `pgvector/pgvector:pg16` service container |

**CI never runs the eval suite.** Those tests call a paid API and are non-deterministic. A
build that goes red for reasons outside the diff is a build people learn to ignore.

**Run the same commands locally before pushing:**

```bash
uv run ruff check . && uv run ruff format . && uv run pytest -m "not eval"
```

`uv.lock` is committed so CI installs exactly what you ran, and a transitive dependency
releasing a broken version cannot turn the build red on its own.

**A red build is stopped work.** Fix it or revert it; do not stack commits on top.

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
