## What and why

<!-- One paragraph. Link the phase doc or decision this implements, if any. -->

## How it was verified

<!-- The commands you ran and what they printed. "Tests pass" means you ran them. -->

## Checklist

- [ ] Parser, traversal, or ranking changes have a test written first and seen to fail
- [ ] `uv run pytest -m "not eval"` is green locally against Postgres
- [ ] Docs updated where commands, layout, or behaviour changed (`AGENTS.md`, `ARCHITECTURE.md`, `docs/`)
- [ ] Any deviation from the spec or design is recorded in `docs/design/decisions.md`
- [ ] No secrets, nothing from `data/raw/`, no AI co-author lines
