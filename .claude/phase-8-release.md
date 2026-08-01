# Phase 8 — Release

**Status:** not started
**Goal:** a README that makes the case honestly, and a repo someone else can run.

The engineering is done by now. This phase is where the project either reads as credible or
reads as a demo.

## The README

Order matters — the ablation table goes near the top, not buried at the bottom.

1. **One line.** *"A GraphRAG threat-intelligence agent: it answers analyst questions by
   multi-hop traversal over the ATT&CK/CVE knowledge graph, with hybrid retrieval,
   reranking, an agentic re-query loop, and an ablation-based evaluation."*

2. **The problem, in two sentences.** Answering "here's a CVE — how bad is it, how would it
   be used, what do I do" means cross-referencing several separate knowledge bases by hand.
   That stitching is slow, needs expertise, and is easy to get wrong under alert pressure.

3. **A real demo.** One CVE, the actual command, the actual output, with the Mermaid attack
   path. Use a CVE anyone recognises. Show the citations.

4. **The ablation table** — real numbers, n, confidence intervals, and the headline
   sentence: *"naive vector RAG retrieved the correct technique X% of the time; adding graph
   traversal and reranking took it to Y%."* This is the project's entire credibility. If
   the numbers are unimpressive, publish them anyway with the failure analysis.

5. **How it works.** The six-stage pipeline, one paragraph each, with the architecture
   diagram.

6. **Reproduce it.** Exact commands from clone to ablation table. Someone with Docker and
   `uv` should get there without asking you a question.

7. **Data provenance.** ATT&CK version, mappings snapshot date, NVD pull scope and date,
   holdout seed and size. Link the manifest.

8. **Related work — by name.** CyKG-RAG, the IEEE GraphRAG-CTI dataset, Minerva. State
   plainly: the general approach is prior art; what is ours is a well-built, well-evaluated,
   usable implementation. **Do not claim novelty.** Positioning on execution is a strength;
   getting caught overclaiming is fatal.

9. **Limitations — the section that earns trust.** All of these, stated plainly:
   - It is a **comprehension tool, not a detector.** It does not scan, monitor, or detect.
     A clean answer does not mean "you are safe."
   - `CHAINS_TO` is derived from **threat-actor co-occurrence**, not observed attack
     sequences. It is a heuristic with a support threshold, and it is described as one.
   - Ground truth covers **CISA KEV CVEs** (~800 mappings), so results generalize to
     known-exploited vulnerabilities, not all CVEs.
   - Holdout n ≈ 160. Small. Differences within the confidence interval are not differences.
   - Data is a **fixed snapshot**; it does not reflect ATT&CK or NVD updates after that date.
   - Generation is grounded to retrieved evidence, but the *retrieval* can still miss — see
     the failure analysis.

10. **License and attribution.** MITRE ATT&CK® usage terms, NVD, Center for Threat-Informed
    Defense. Credit them.

## Repo hygiene

- [ ] `uv sync && docker compose up -d db && threatlens db init` works on a clean clone
- [ ] `.env.example` committed with every variable and no values
- [ ] `data/eval/holdout.jsonl` and `data/manifest.json` committed; `data/raw/` gitignored
- [ ] `eval_results/` committed — the numbers are checkable
- [ ] `uv run pytest -m "not eval"` green from a clean clone
- [ ] `ruff check` clean
- [ ] Every phase doc in `.claude/` has its status updated
- [ ] [phases.md](phases.md) status table reflects reality, including anything cut

## Recording what was cut

If Phase 6 was cut, say so: *"The agentic re-query loop was not completed; the system runs a
fixed traversal pipeline (config D). Row E is not measured."* An honest gap reads as
judgment. A vague implication that it exists reads as a lie once someone runs it.

## Done when

- [ ] README complete, ablation table near the top with real numbers
- [ ] Working demo on a real CVE, with output shown
- [ ] Reproduction steps verified from a clean clone
- [ ] Related work cited by name; no novelty claimed
- [ ] Limitations section complete and specific
- [ ] Attribution and licensing correct
- [ ] `.claude/` statuses accurate, cuts recorded
