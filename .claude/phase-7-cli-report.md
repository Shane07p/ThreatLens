# Phase 7 — CLI and Markdown report

**Status:** not started
**Goal:** the thing a person actually uses. Command line first; the shareable artifact is a
Markdown file.

## Steps

1. **CLI surface** — `cli.py`, Typer. Final command set:

   ```
   threatlens ask "CVE-2021-44228 showed up. How would an attacker exploit it,
                   what next, and how do I defend?"
   threatlens ask "..." --report out.md      # write the Markdown artifact
   threatlens ask "..." --json               # machine-readable answer + evidence
   threatlens explain CVE-2021-44228          # fixed-pipeline lookup, no agent
   threatlens path CVE-2021-44228             # traversal only, no LLM
   threatlens show T1190
   threatlens stats
   threatlens eval --all --md
   threatlens db init | fetch | ingest | embed
   ```

   `path` and `show` must work with no `ANTHROPIC_API_KEY` set — a reviewer should be able
   to see the graph working without an API key.

2. **Terminal output.** Answer, then a compact attack path, then a numbered citation list.
   Keep it readable in an 80-column terminal. No colour-only signalling.

3. **Markdown report** — `report/markdown.py`. Sections:
   - **Finding** — the CVE/technique, severity, KEV status
   - **What it enables** — technique(s), tactic(s)
   - **Attack path** — the traversed chain, rendered as a Mermaid flowchart
   - **Who uses this** — threat actors
   - **Defenses** — mitigations, and detections if Sigma landed
   - **Sources** — every cited node with its `source_url`
   - **Provenance** — ATT&CK version, mappings snapshot date, config, generated-at

   Node ids from the model resolve to URLs here and only here.

4. **Attack-path visualization.** Mermaid inside the Markdown — no extra dependency, renders
   on GitHub:

   ```mermaid
   flowchart LR
     CVE["CVE-2021-44228"] -->|ENABLES| T1190["T1190 Exploit Public-Facing App"]
     T1190 -->|BELONGS_TO| TA0001["Initial Access"]
     T1190 -->|CHAINS_TO| T1059["T1059 Command & Scripting"]
     T1190 -->|MITIGATED_BY| M1030["M1030 Network Segmentation"]
   ```

   Cap rendered nodes (~25). A 200-node subgraph is unreadable — render the paths from
   anchors to cited nodes, not the whole traversal.

5. **Errors that read like errors.** No anchor found, DB not initialized, missing API key,
   empty subgraph — each gets a one-line message saying what to do next, not a traceback.

6. **Latency feedback.** Anything over ~2s prints progress: resolving → traversing →
   retrieving → generating. The agent loop can run tens of seconds; silence reads as a hang.

## Cut list within this phase

If time is short, drop in this order: Mermaid viz → `--json` → `explain`. The `ask` command
plus the Markdown report is the minimum shippable surface.

## Tests that must pass

- CLI smoke tests via Typer's `CliRunner` — every command runs `--help` and exits 0
- `path` and `show` work with `ANTHROPIC_API_KEY` unset
- Markdown renderer: golden-file test on a fixed evidence set
- Every citation in the rendered report resolves to a `source_url` (no bare node ids leak
  into user-facing output)
- Mermaid node cap is enforced

```bash
uv run pytest -m "not eval"
```

## Done when

- [ ] All commands implemented and `--help` is accurate
- [ ] `ask --report out.md` produces a complete, correctly-cited Markdown file
- [ ] Mermaid attack path renders on GitHub and respects the node cap
- [ ] Graph-only commands work without an API key
- [ ] Error messages are actionable
- [ ] Golden-file renderer test green
- [ ] `uv run pytest -m "not eval"` is green

## Next

[Phase 8 — Release](phase-8-release.md)
