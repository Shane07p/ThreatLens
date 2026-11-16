# Contributors

ThreatLens is built by a small team. Credit follows the git history: every contributor's
commits are kept as they wrote them, which is why pull requests here merge with a merge
commit or a rebase and never a squash.

## Maintainers

| | GitHub | Built |
|---|---|---|
| **Shane Christian** | [@Shane07p](https://github.com/Shane07p) | The shared data contract (`models.py`, `schema.sql`, `graph/store.py`); ATT&CK STIX parsing and ingestion; bounded multi-hop traversal and `threatlens path`; CI and repository tooling |
| **Madhav Thesiya** | [@madhavthesiya](https://github.com/madhavthesiya) | NVD CVE parsing and KEV flagging; CVE→ATT&CK mapping ingestion with drop-count reporting; the evaluation metrics |

## Past contributors

| | GitHub | Built |
|---|---|---|
| **Raj Patel** | [@Raj-Patel7807](https://github.com/Raj-Patel7807) | The `threatlens` CLI; snapshot fetching with sha256 provenance; the scoped NVD pull with its per-key rate limiter and retry policy |
| **Pranamya Sanghvi** | [@Elite407](https://github.com/Elite407) | Configuration and architecture-boundary test suites; node chunking, embeddings, and the pgvector HNSW index |

## Data

The knowledge graph is built from public data, used under each source's terms:

- [MITRE ATT&CK®](https://attack.mitre.org/) — ATT&CK is a registered trademark of The MITRE
  Corporation
- [NIST National Vulnerability Database](https://nvd.nist.gov/)
- [Center for Threat-Informed Defense](https://ctid.mitre.org/) — CVE→ATT&CK mappings
- [CISA Known Exploited Vulnerabilities Catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)

Want to contribute? Start with [CONTRIBUTING.md](CONTRIBUTING.md).
