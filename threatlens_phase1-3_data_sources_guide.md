# ThreatLens — Phase 1, 2, 3: Exact Data Sources & Execution Guide

*Every repo link, every file inside it, every command — so there's zero ambiguity about where the data comes from or how to pull it.*

---

# PHASE 1 — MITRE ATT&CK Ingestion

## The repo to use (recommended)

**`mitre-attack/attack-stix-data`**
🔗 https://github.com/mitre-attack/attack-stix-data

This is MITRE's current, actively maintained repository, in **STIX 2.1** format, with proper version tracking via "collections." This is the one to use — it's the modern replacement for the older `mitre/cti` repo.

**What's inside it (folder structure):**
```
attack-stix-data/
├── enterprise-attack/              ← the one you need for this project
│   ├── enterprise-attack.json      ← ALWAYS the latest release — this is your target file
│   ├── enterprise-attack-9.0.json  ← older versions, kept for reference
│   ├── enterprise-attack-10.1.json
│   └── ... (every historical version, in case you need to pin one)
├── mobile-attack/                  ← not needed for this project
│   └── [Mobile ATT&CK releases]
├── ics-attack/                     ← not needed for this project
│   └── [ICS ATT&CK releases]
├── index.json                      ← machine-readable list of all collections/versions
└── index.md                        ← human-readable list of all collections/versions
```

You only need the **`enterprise-attack/enterprise-attack.json`** file — that's the whole Enterprise ATT&CK matrix (tactics, techniques, sub-techniques, mitigations, groups, software, and all relationships) in one JSON file.

## Alternative / legacy repo (still works, simpler for quick scripting)

**`mitre/cti`**
🔗 https://github.com/mitre/cti

This is the older STIX 2.0 repo. It contains the *same underlying data* but organized slightly differently, and MITRE's own official usage examples (`USAGE.md` in that repo) are written against it — useful if you're following their documented Python patterns. It also has folders that break out individual objects by type if you ever want to browse one technique's raw JSON in isolation:
```
cti/
└── enterprise-attack/
    ├── enterprise-attack.json     ← same idea: combined single-file version
    ├── attack-pattern/            ← one JSON file per technique/sub-technique
    ├── course-of-action/          ← one JSON file per mitigation
    ├── intrusion-set/             ← one JSON file per threat actor/group
    ├── tool/                      ← one JSON file per tool
    ├── malware/                   ← one JSON file per malware
    ├── x-mitre-tactic/            ← one JSON file per tactic
    ├── x-mitre-matrix/            ← the matrix layout definition
    └── relationship/              ← one JSON file per edge (uses, mitigates, etc.)
```
**Recommendation: use `mitre-attack/attack-stix-data` as your primary source (it's the current one); only reference `mitre/cti` if you want to browse individual object files or follow MITRE's official code samples.**

## Downloading it

Option A — clone the whole repo (gives you every historical version too):
```bash
git clone https://github.com/mitre-attack/attack-stix-data.git
```

Option B — just grab the one file you need, no git history:
```bash
curl -o enterprise-attack.json \
  https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json
```

Option C — pull it live in Python at runtime (MITRE's own documented pattern, useful if you want "always current" instead of a static snapshot):
```python
import requests
from stix2 import MemoryStore

def get_attack_data(domain="enterprise-attack", branch="master"):
    url = f"https://raw.githubusercontent.com/mitre/cti/{branch}/{domain}/{domain}.json"
    stix_json = requests.get(url).json()
    return MemoryStore(stix_data=stix_json["objects"])

src = get_attack_data()
```
**For this project: use Option B or A, save it to disk, and treat it as a fixed snapshot** — you don't want your graph silently changing mid-development if MITRE pushes an update.

## What's actually inside the JSON — object types you'll parse

Install the official parsing library first:
```bash
pip install stix2 --break-system-packages
```

| STIX object type | What it maps to in your graph | Notes |
|---|---|---|
| `attack-pattern` | `Technique` node (includes sub-techniques) | Sub-techniques have an `x_mitre_is_subtechnique: true` field |
| `x-mitre-tactic` | `Tactic` node | |
| `course-of-action` | `Mitigation` node | |
| `intrusion-set` | `ThreatActor`/`Group` node | |
| `malware` / `tool` | `Software` node | |
| `x-mitre-data-source` / `x-mitre-data-component` | (optional, for a future Detection layer) | |
| `relationship` | The **edges** — has a `relationship_type` field (`uses`, `mitigates`, `subtechnique-of`, etc.) plus `source_ref` and `target_ref` pointing to the STIX IDs of the two connected objects | This is where `Technique —BELONGS_TO→ Tactic`, `ThreatActor —USES→ Technique`, `Technique —MITIGATED_BY→ Mitigation` all come from |

## Phase 1 step checklist
1. `git clone` or `curl` the `enterprise-attack.json` file from `mitre-attack/attack-stix-data` (Option A or B above).
2. `pip install stix2 --break-system-packages`
3. Load the file with `stix2.MemoryStore().load_from_file("enterprise-attack.json")`.
4. Loop through all objects; branch by `type` field into your node tables (techniques, tactics, mitigations, groups, software).
5. Loop through all `relationship` objects; use `relationship_type` + `source_ref`/`target_ref` to populate your edge table.
6. Run 5–10 manual sanity queries (e.g. "list all techniques under tactic Initial Access") and eyeball the output before moving to Phase 2. No AI, no embeddings yet — this phase is pure data plumbing.

---

# PHASE 2 — CVE Ingestion + the CVE↔ATT&CK Bridge

This phase has **two separate data sources** — the CVEs themselves, and the mapping that connects a CVE to the technique(s) it enables.

## Part A — CVE data: the NVD API

There's no GitHub repo here — NVD is a live government API, not a static dataset.

- **Base endpoint (v2.0):** `https://services.nvd.nist.gov/rest/json/cves/2.0`
- **Get a free API key:** https://nvd.nist.gov/developers/request-an-api-key
  - Fill in organization name + email, agree to the terms, and you'll get an activation email with a single-use link to reveal your key.
  - Not strictly required, but **strongly recommended** — rate limits are 5 requests/30 sec without a key vs. 50 requests/30 sec with one.
- **Example request** (pulling a page of CVEs, results per page capped at 2000):
```bash
curl -H "apiKey: YOUR_KEY_HERE" \
  "https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage=2000&startIndex=0"
```
- **Pagination:** increment `startIndex` by `resultsPerPage` until the response's `totalResults` is reached.
- **What each CVE record gives you:** ID, description, CVSS v3.1/v4.0 scores, published/modified dates, affected CPEs (products), and reference URLs.
- **Do this once, save to disk as a local snapshot** (JSON files or load straight into your Postgres `CVE` table) — don't re-query NVD live every time you run your pipeline, both for rate-limit sanity and so your graph doesn't shift under you mid-project.

## Part B — CVE→ATT&CK mapping: two real options

**Option 1 — Recommended: Center for Threat-Informed Defense "Mappings Explorer" (current, larger dataset)**

- 🔗 Repo: https://github.com/center-for-threat-informed-defense/mappings-explorer
- 🔗 The actual browsable/downloadable data (easier than digging through the raw repo): https://center-for-threat-informed-defense.github.io/mappings-explorer/external/kev/
- This specific dataset maps **CISA's Known Exploited Vulnerabilities (KEV) catalog CVEs** to the ATT&CK techniques they enable — around 800 CVE→technique mappings, tied to CVEs that are *confirmed exploited in the wild* (which, as discussed earlier, is also a great triage signal worth surfacing in your own tool).
- **Download formats available directly from the website, no scraping needed:** JSON, YAML, CSV, Excel (.xlsx), STIX Bundle, or ATT&CK Navigator Layer — pick JSON or CSV for your ingestion script.
- The methodology behind how a CVE gets mapped to a technique is documented here, worth skimming so you can explain it if asked: https://center-for-threat-informed-defense.github.io/mappings-explorer/about/methodology/cve-methodology/
- The raw repo itself (`mappings-explorer`) has a top-level `mappings/` folder containing the underlying source data if you want to browse it directly on GitHub instead of using the website's download buttons.

**Option 2 — Simpler starter set (smaller, archived, but a real ready-to-use file)**

- 🔗 Repo: https://github.com/center-for-threat-informed-defense/attack_to_cve *(archived — kept online, just no longer actively updated; the data has "moved" conceptually to Option 1, but this file still works fine as a smaller starter set)*
- Direct file: `Att&ckToCveMappings.csv` in that repo's root
- Raw download:
```bash
curl -o attck_to_cve_legacy.csv \
  "https://raw.githubusercontent.com/center-for-threat-informed-defense/attack_to_cve/master/Att%26ckToCveMappings.csv"
```
- **Columns:** `CVE ID, Primary Impact, Secondary Impact, Exploitation Technique, Uncategorized, Phase`
- This was the original methodology-development dataset — smaller (a few hundred CVEs) but clean and immediately usable if you want something to test your ingestion script against before pulling the larger Option 1 dataset.

**Recommendation: ingest Option 1 as your primary bridge dataset (bigger, current, multi-format), and optionally use Option 2 as a quick first test of your parsing code since it's a single small CSV.**

## Critical step — reserve your held-out eval labels NOW

Before you write a single line of retrieval code, split whichever mapping dataset you use:
- ~80% → visible during development, used to sanity-check the graph
- ~20% → locked away, touched only by the eval harness in Phase 5

Write this split to its own file/table right now and don't regenerate it later — this is what makes your eventual ablation table honest.

## Phase 2 step checklist
1. Get an NVD API key (link above).
2. Pull CVEs in pages of 2000 via the `/rest/json/cves/2.0` endpoint; snapshot to disk.
3. Download the Mappings Explorer KEV→ATT&CK CVE mapping data (JSON or CSV) from the website link above.
4. (Optional) Also grab the legacy `Att&ckToCveMappings.csv` as a small first test file.
5. Ingest CVEs into a `CVE` table; ingest the mappings as `CVE —ENABLES→ Technique` edges, joining against the `Technique` nodes you built in Phase 1.
6. Split off and lock your held-out evaluation set.

---

# PHASE 3 — Naive Vector RAG Baseline

No GitHub *data* repo here — this phase is about a model and a database extension.

## The embedding model

**`BAAI/bge-small-en-v1.5`**
🔗 https://huggingface.co/BAAI/bge-small-en-v1.5
🔗 BAAI's own GitHub (the library it's part of, `FlagEmbedding`): https://github.com/FlagOpen/FlagEmbedding

- **Output vector size: 384 dimensions** — this is the number you'll use when defining your pgvector column type.
- **Max input length: 512 tokens.**
- **~33M parameters** — small enough to run comfortably on CPU, which is why it's the right pick for a solo project without guaranteed GPU access.
- License: MIT — free for any use, including this project.

Install:
```bash
pip install sentence-transformers --break-system-packages
```
Basic usage:
```python
from sentence_transformers import SentenceTransformer
model = SentenceTransformer("BAAI/bge-small-en-v1.5")
embedding = model.encode("Exploit Public-Facing Application technique description text...")
# embedding.shape → (384,)
```

## The vector database extension

**`pgvector/pgvector`**
🔗 https://github.com/pgvector/pgvector

This is the Postgres extension that gives you a native vector column type plus similarity search operators and the HNSW index type. Easiest install path is via a Postgres Docker image that already bundles it:
```yaml
# docker-compose.yml
services:
  db:
    image: pgvector/pgvector:pg16
    environment:
      POSTGRES_PASSWORD: yourpassword
    ports:
      - "5432:5432"
```
Then, inside your database:
```sql
CREATE EXTENSION IF NOT EXISTS vector;

ALTER TABLE nodes ADD COLUMN embedding vector(384);  -- 384 matches bge-small's output size

CREATE INDEX ON nodes USING hnsw (embedding vector_cosine_ops);
```

## Phase 3 step checklist
1. `pip install sentence-transformers`
2. Load `BAAI/bge-small-en-v1.5`, embed every node's description text (techniques, CVEs, mitigations, etc.) from Phase 1/2.
3. Store each embedding in a `vector(384)` pgvector column; build an HNSW index on it.
4. Write a bare top-k cosine similarity query — no graph traversal at all — feed the top results straight to an LLM call for the answer.
5. **Run this against your held-out eval set from Phase 2 immediately and record the score.** This is Row 1 of your ablation table and the number everything else in the project gets measured against — don't skip recording it before moving on to Phase 4.

---

## Quick reference — every link in one place

| Phase | Resource | Link |
|---|---|---|
| 1 | ATT&CK STIX data (primary) | https://github.com/mitre-attack/attack-stix-data |
| 1 | ATT&CK STIX data (legacy/alt) | https://github.com/mitre/cti |
| 2 | NVD API | https://services.nvd.nist.gov/rest/json/cves/2.0 |
| 2 | NVD API key request | https://nvd.nist.gov/developers/request-an-api-key |
| 2 | CVE→ATT&CK mappings (primary) | https://center-for-threat-informed-defense.github.io/mappings-explorer/external/kev/ |
| 2 | CVE→ATT&CK mappings repo | https://github.com/center-for-threat-informed-defense/mappings-explorer |
| 2 | CVE→ATT&CK mappings (legacy CSV) | https://github.com/center-for-threat-informed-defense/attack_to_cve |
| 3 | Embedding model | https://huggingface.co/BAAI/bge-small-en-v1.5 |
| 3 | pgvector extension | https://github.com/pgvector/pgvector |
