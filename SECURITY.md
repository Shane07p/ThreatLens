# Security

## Scope

ThreatLens is a research and comprehension tool over **public** threat intelligence. It is
not a scanner, a detector, or a monitoring system, and a clean answer from it never means a
system is safe.

Issues worth reporting:

- a way to make the tool execute code, read files, or reach the network at query time
- SQL injection or any query built from untrusted input
- a secret committed to the repository or its history
- a dependency with a known vulnerability that affects how ThreatLens uses it
- generated output that can cite a URL the knowledge graph does not contain

Out of scope: inaccuracies in MITRE ATT&CK, NVD, or the CVE→ATT&CK mappings themselves.
Report those upstream.

## Supported versions

Pre-release. Only `main` receives fixes.

## Reporting a vulnerability

**Do not open a public issue or pull request for a vulnerability.**

Use GitHub's **Report a vulnerability** button under the
[Security tab](https://github.com/Shane07p/ThreatLens/security/advisories/new). It opens a
private advisory visible only to the maintainers listed in [CONTRIBUTORS.md](CONTRIBUTORS.md).

Include what you found, how to reproduce it, and what an attacker could do with it.
Expect an acknowledgement within a week. Fixes are credited unless you ask otherwise.

## How the project protects itself

| Risk | Control |
|---|---|
| Secrets in commits | `.env` only, read through `config.py`; gitleaks runs in pre-commit and scans the full history in CI; GitHub secret scanning and push protection are on |
| A leaked key | Rotate it immediately. Deleting the commit is not enough — a commit stays reachable by SHA until garbage collection |
| SQL injection and other code flaws | All SQL lives in `graph/` and uses bound parameters; string-built SQL is banned outright. CodeQL (extended queries) analyses the Python and the workflows on every pull request and weekly |
| Vulnerable dependencies | Dependabot security updates open as soon as an advisory is published; `uv.lock` pins exact versions |
| Compromised CI actions | Every action is pinned to a full commit SHA; workflows run with read-only permissions and are audited by zizmor |
| Hallucinated or injected links *(planned, agent layer)* | Generated answers cite node ids only. The renderer resolves each id to the URL stored at ingest, so the model cannot introduce a link |
| Prompt injection via ingested text *(planned, agent layer)* | CVE and ATT&CK descriptions are third-party text. They are passed to the model as quoted evidence, never as instructions, and query-time code has no network or write access to act on them |

Controls marked *planned* are design commitments for the agent layer, which is not built
yet; they are listed so the design is held to them.

What to do if a secret is ever pushed:
[docs/conventions/workflow.md](docs/conventions/workflow.md#repository-visibility).
