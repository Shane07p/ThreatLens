# Data sources

All free, all public, all snapshotted to `data/` and never fetched at query time.

## Snapshot layout

```
data/
├── raw/
│   ├── enterprise-attack.json          # ATT&CK STIX bundle
│   ├── kev-mappings.json               # CVE→ATT&CK from Mappings Explorer
│   ├── attck_to_cve_legacy.csv         # optional small test file
│   └── nvd/cves-<batch>.json           # NVD records, scoped (see below)
├── eval/
│   └── holdout.jsonl                   # COMMITTED. frozen in Phase 2.
└── manifest.json                       # url, sha256, fetched_at per file
```

`data/raw/` is gitignored (large, reproducible). `data/eval/holdout.jsonl` and
`data/manifest.json` **are committed** — they are what makes the ablation table
reproducible.

## 1. MITRE ATT&CK Enterprise (backbone)

- Repo: https://github.com/mitre-attack/attack-stix-data
- File: `enterprise-attack/enterprise-attack.json` — always the latest release
- Raw: `https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json`

```bash
curl -o data/raw/enterprise-attack.json \
  https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json
```

Pin it. Record the sha256 and the collection's `x_mitre_version` in `ingest_runs` and in the
README. Do not re-download mid-project — the graph shifting under the eval set invalidates
every measured number.

`mitre/cti` (the older STIX 2.0 repo) is only useful for browsing individual object files.
Do not ingest from it.

| STIX type | → node kind | Notes |
|---|---|---|
| `attack-pattern` | `technique` | `x_mitre_is_subtechnique: true` marks sub-techniques |
| `x-mitre-tactic` | `tactic` | `x_mitre_shortname` joins to `kill_chain_phases[].phase_name` |
| `course-of-action` | `mitigation` | |
| `intrusion-set` | `actor` | |
| `malware`, `tool` | `software` | |
| `relationship` | edges | `relationship_type` + `source_ref`/`target_ref` |
| `x-mitre-collection` | — | read `x_mitre_version`, don't store as a node |

Parsing gotchas are in [graph-schema.md](graph-schema.md) § STIX → graph gotchas. Read them
before writing `ingest/attack.py`.

## 2. NVD (CVE records)

- Endpoint: `https://services.nvd.nist.gov/rest/json/cves/2.0`
- API key (free, strongly recommended): https://nvd.nist.gov/developers/request-an-api-key
- Rate limits: 5 req / 30s without a key, 50 req / 30s with one

**Do not bulk-pull the whole database.** The data guide's paginate-everything recipe pulls
250k+ CVEs, most of which have no ATT&CK mapping and can never appear in an answer. See
[decisions.md](decisions.md) D3. Pull this scope instead:

1. Every CVE id referenced by the mappings dataset (the only CVEs with `ENABLES` edges)
2. The full CISA KEV catalog (confirmed exploited in the wild — a useful triage signal to
   surface in answers)
3. Optionally, a recent window (`pubStartDate`/`pubEndDate`) for demo freshness

Fetch by id, batched, with the key header and a token-bucket limiter:

```bash
curl -H "apiKey: $NVD_API_KEY" \
  "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2024-1234"
```

Per record, keep: id, English description, CVSS v3.1/v4.0 base score + vector, published /
last-modified dates, affected CPEs, reference URLs. Store the rest in `attrs`.

## 3. CVE → ATT&CK mappings (the bridge, and the ground truth)

**Primary — Center for Threat-Informed Defense, Mappings Explorer (KEV dataset):**
- Browse/download: https://center-for-threat-informed-defense.github.io/mappings-explorer/external/kev/
- Repo: https://github.com/center-for-threat-informed-defense/mappings-explorer
- Methodology (skim it, you will be asked): https://center-for-threat-informed-defense.github.io/mappings-explorer/about/methodology/cve-methodology/
- ~800 CVE→technique mappings over CISA KEV CVEs. JSON, YAML, CSV, XLSX, STIX, Navigator layer.

**Secondary — legacy starter CSV** (archived, smaller, good for testing the parser first):
```bash
curl -o data/raw/attck_to_cve_legacy.csv \
  "https://raw.githubusercontent.com/center-for-threat-informed-defense/attack_to_cve/master/Att%26ckToCveMappings.csv"
```
Columns: `CVE ID, Primary Impact, Secondary Impact, Exploitation Technique, Uncategorized, Phase`.

This dataset does double duty:
- It is the `CVE —ENABLES→ Technique` edge set.
- **It is the labelled ground truth for evaluation.** 20% is split off and frozen in Phase 2
  before any retrieval code exists. See [evaluation.md](evaluation.md).

Weighting: primary impact → `weight 1.0`, secondary impact → `weight 0.5`.

## 4. Optional enrichment (v1.5, only if time allows)

| Source | Gives | Link |
|---|---|---|
| Sigma rules | Detection rules tagged with ATT&CK ids | https://github.com/SigmaHQ/sigma |
| D3FEND | Defensive technique mappings | https://d3fend.mitre.org |
| IEEE GraphRAG-CTI Neo4j dump | A prebuilt ATT&CK+APT graph to eyeball the shape | IEEE DataPort |

The IEEE dump is for *looking at*, not ingesting. Building the graph is the point.

## Manifest

`ingest/` writes `data/manifest.json` on every fetch:

```json
{
  "enterprise-attack.json": {
    "url": "https://raw.githubusercontent.com/...",
    "sha256": "...",
    "fetched_at": "2026-08-02T14:22:10Z",
    "version": "19.1"
  }
}
```

The README quotes these versions. "Built against ATT&CK v19.1 and the KEV mappings snapshot
of 2026-08-02" is the difference between a reproducible result and a claim.
