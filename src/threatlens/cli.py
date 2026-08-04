"""Typer entrypoint for the threatlens CLI commands.

Wiring only — logic belongs in the underlying domain modules called by these commands.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path

import typer

app = typer.Typer(
    help="threatlens — a Graph-RAG threat-intelligence agent",
    no_args_is_help=True,
)
db_app = typer.Typer(help="Database management commands", no_args_is_help=True)
fetch_app = typer.Typer(help="Download data snapshots", no_args_is_help=True)
ingest_app = typer.Typer(help="Load snapshots into the graph", no_args_is_help=True)

app.add_typer(db_app, name="db")
app.add_typer(fetch_app, name="fetch")
app.add_typer(ingest_app, name="ingest")

DATA_RAW = Path("data/raw")
MANIFEST = Path("data/manifest.json")


@app.callback()
def main(
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Enable verbose logging"),
) -> None:
    """Configure global application settings such as logging verbosity.

    Pass --verbose or -v to enable DEBUG level logs across all CLI commands.
    """
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO,
        format="%(levelname)s %(name)s %(message)s",
    )


@db_app.command("init")
def db_init() -> None:
    """Apply the relational graph schema to the database.

    Idempotent schema migration. Connects to the database configured in Settings
    and creates necessary tables, extensions, and indexes.

    Raises RuntimeError if database connection fails.
    """
    from threatlens.graph.store import get_engine, init_schema

    init_schema(get_engine())
    typer.echo("schema applied")


@fetch_app.command("attack")
def fetch_attack(
    force: bool = typer.Option(False, "--force", help="Overwrite existing snapshot"),
) -> None:
    """Download the MITRE ATT&CK Enterprise STIX bundle snapshot.

    Fetches the latest ATT&CK STIX 2.1 dataset from the official repository, stores it
    in data/raw/, and records SHA-256 provenance in data/manifest.json.

    Raises typer.Exit(code=1) if the file exists and --force is not supplied.
    """
    from threatlens.ingest.fetch import ATTACK_URL, fetch_url, update_manifest

    dest = DATA_RAW / "enterprise-attack.json"
    try:
        entry = fetch_url(ATTACK_URL, dest, force=force)
    except FileExistsError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=1) from exc

    update_manifest(MANIFEST, dest.name, entry)
    typer.echo(f"{dest}  sha256={entry['sha256'][:12]}...  {entry['bytes']} bytes")


@ingest_app.command("attack")
def ingest_attack_cmd() -> None:
    """Parse the ATT&CK STIX snapshot and populate the Postgres graph database.

    Reads the enterprise-attack.json snapshot, transforms STIX objects into domain Node
    and Edge records, and performs idempotent batch upserts into Postgres.

    Raises typer.Exit(code=1) if the snapshot file is missing or parser is unavailable.
    """
    path = DATA_RAW / "enterprise-attack.json"
    if not path.exists():
        typer.echo("snapshot missing — run: threatlens fetch attack", err=True)
        raise typer.Exit(code=1)

    try:
        from threatlens.ingest.attack import ingest_attack
    except ImportError:
        typer.echo("ingest attack parser unavailable", err=True)
        raise typer.Exit(code=1) from None

    from threatlens.graph.store import get_engine

    sha = ""
    if MANIFEST.exists():
        try:
            manifest_data = json.loads(MANIFEST.read_text(encoding="utf-8"))
            sha = manifest_data.get(path.name, {}).get("sha256", "")
        except json.JSONDecodeError:
            sha = ""

    with get_engine().begin() as conn:
        n_nodes, n_edges = ingest_attack(path, sha, conn)

    typer.echo(f"ingested {n_nodes} nodes, {n_edges} edges")


@app.command("stats")
def stats() -> None:
    """Print count summaries of graph nodes and edges grouped by kind.

    Connects to the configured database, retrieves entity counts by category,
    and displays a formatted breakdown.

    Requires a initialized database schema.
    """
    from threatlens.graph.store import edge_counts, get_engine, node_counts

    with get_engine().connect() as conn:
        nodes = node_counts(conn)
        edges = edge_counts(conn)

    typer.echo("nodes:")
    for kind, n in sorted(nodes.items()):
        typer.echo(f"  {kind:<12} {n:>6}")

    typer.echo("edges:")
    for kind, n in sorted(edges.items()):
        typer.echo(f"  {kind:<16} {n:>6}")


@app.command("show")
def show(
    node_id: str = typer.Argument(
        ..., help="Node ID or external ID (e.g. T1190 or technique:T1190)"
    ),
) -> None:
    """Display detailed attributes and outgoing relationships for a specific graph node.

    Accepts full node IDs (e.g., technique:T1190) or bare external IDs (e.g., T1190, TA0001,
    M1030, G0016, S0154, CVE-2021-44228) and prints its metadata and linked neighbors.

    Raises typer.Exit(code=1) if the requested node is not found in the database.
    """
    from threatlens.graph.store import get_engine, get_node, neighbors

    resolved = node_id if ":" in node_id else _guess_id(node_id)
    with get_engine().connect() as conn:
        node = get_node(conn, resolved)
        if node is None:
            typer.echo(f"not found: {resolved}", err=True)
            raise typer.Exit(code=1)

        typer.echo(f"{node.id}  {node.name}")
        typer.echo(node.source_url)
        if node.description:
            typer.echo(f"\n{node.description[:400]}")

        rows = neighbors(
            conn,
            node.id,
            ["BELONGS_TO", "MITIGATED_BY", "SUBTECHNIQUE_OF", "CHAINS_TO", "USES", "USES_SOFTWARE"],
        )

    if rows:
        typer.echo("\nedges:")
        for edge, target in rows:
            typer.echo(f"  --{edge.kind}--> {target.id}  {target.name}")


def _guess_id(external_id: str) -> str:
    """Resolve a bare external identifier to a canonical prefixed node ID.

    Maps external format conventions (CVE-, TA, T, M, G, S) to their respective entity
    kinds. Note that tactic checks (TA) precede technique checks (T) to avoid misclassification.

    Returns the formatted node ID string (e.g. 'technique:T1190').
    """
    upper = external_id.upper()
    if upper.startswith("CVE-"):
        return f"cve:{external_id}"
    if upper.startswith("TA"):
        return f"tactic:{external_id}"

    kind = {"T": "technique", "M": "mitigation", "G": "actor", "S": "software"}.get(
        upper[0] if upper else ""
    )
    return f"{kind or 'technique'}:{external_id}"
