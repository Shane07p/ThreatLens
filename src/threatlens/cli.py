"""Typer entrypoint for the threatlens CLI commands.

Wiring only — logic belongs in the underlying domain modules called by these commands.
"""

from __future__ import annotations

import json
import logging
import subprocess
from pathlib import Path

import typer
from rich.console import Console
from rich.panel import Panel
from rich.progress import (
    BarColumn,
    DownloadColumn,
    Progress,
    TextColumn,
    TimeRemainingColumn,
    TransferSpeedColumn,
)
from rich.table import Table

from threatlens.config import get_settings

logger = logging.getLogger(__name__)
console = Console()
err_console = Console(stderr=True)

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


def _get_data_paths() -> tuple[Path, Path]:
    """Retrieve raw data directory and manifest file path from application settings."""
    settings = get_settings()
    return settings.data_raw_dir, settings.manifest_path


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


@app.command("version")
def version_cmd(
    json_output: bool = typer.Option(
        False, "--json", "-j", help="Output version info in JSON format"
    ),
) -> None:
    """Display the threatlens CLI package version.

    Use --json / -j to format the output as JSON for script consumption.
    """
    ver = "0.1.0"
    if json_output:
        print(json.dumps({"version": ver}, indent=2))
    else:
        console.print(f"threatlens v{ver}")


@app.command("config")
def config_cmd(
    json_output: bool = typer.Option(
        False, "--json", "-j", help="Output configuration in JSON format"
    ),
) -> None:
    """Show current application settings loaded from environment or defaults.

    Masks sensitive values such as NVD API keys. Use --json / -j for JSON output.
    """
    s = get_settings()
    raw_dict = {
        "database_url": s.database_url,
        "nvd_api_key": "****" if s.nvd_api_key else None,
        "provider": s.provider,
        "model": s.model,
        "data_raw_dir": str(s.data_raw_dir),
        "manifest_path": str(s.manifest_path),
        "max_depth": s.max_depth,
        "node_budget": s.node_budget,
        "min_shared_actors": s.min_shared_actors,
        "rrf_k": s.rrf_k,
        "rerank_candidates": s.rerank_candidates,
        "evidence_top_n": s.evidence_top_n,
        "max_agent_steps": s.max_agent_steps,
    }

    if json_output:
        print(json.dumps(raw_dict, indent=2))
        return

    table = Table(title="ThreatLens Settings", show_header=True, header_style="bold magenta")
    table.add_column("Setting", style="cyan")
    table.add_column("Value", style="green")

    for k, v in raw_dict.items():
        table.add_row(k, str(v))

    console.print(table)


@app.command("doctor")
def doctor_cmd(
    json_output: bool = typer.Option(
        False, "--json", "-j", help="Output health diagnostic results in JSON format"
    ),
) -> None:
    """Verify database connection, data paths, and Docker availability.

    Runs pre-flight system diagnostics and provides actionable remedy suggestions on failure.
    """
    data_raw, manifest = _get_data_paths()
    checks: list[dict] = []

    # 1. Database Connection
    db_ok = False
    db_msg = "Connected successfully"
    try:
        from threatlens.graph.store import get_engine, ping

        db_ok = ping(get_engine())
        if not db_ok:
            db_msg = "Connection failed"
    except Exception as exc:
        db_msg = f"Connection failed: {exc}"

    checks.append(
        {
            "name": "Database Connection",
            "ok": db_ok,
            "message": db_msg,
            "suggestion": "Verify Postgres container is running: docker compose up -d db",
        }
    )

    # 2. Data Paths
    paths_ok = False
    paths_msg = f"Paths OK ({data_raw}, {manifest})"
    try:
        data_raw.mkdir(parents=True, exist_ok=True)
        manifest.parent.mkdir(parents=True, exist_ok=True)
        paths_ok = True
    except Exception as exc:
        paths_msg = f"Path creation/permission error: {exc}"

    checks.append(
        {
            "name": "Data Paths Access",
            "ok": paths_ok,
            "message": paths_msg,
            "suggestion": "Check file permissions for data directory",
        }
    )

    # 3. Docker Availability
    docker_ok = False
    docker_msg = "Docker daemon responsive"
    try:
        res = subprocess.run(["docker", "info"], capture_output=True, timeout=5)
        if res.returncode == 0:
            docker_ok = True
        else:
            docker_msg = f"Docker info returned exit code {res.returncode}"
    except Exception as exc:
        docker_msg = f"Docker unavailable: {exc}"

    checks.append(
        {
            "name": "Docker Daemon",
            "ok": docker_ok,
            "message": docker_msg,
            "suggestion": "Start Docker Desktop or start docker system daemon service",
        }
    )

    overall_ok = all(c["ok"] for c in checks)

    if json_output:
        status_val = "ok" if overall_ok else "error"
        print(json.dumps({"status": status_val, "checks": checks}, indent=2))
        return

    table = Table(title="ThreatLens Health Doctor", show_header=True, header_style="bold blue")
    table.add_column("Component", style="cyan")
    table.add_column("Status")
    table.add_column("Details", style="dim")

    for c in checks:
        status_str = "[bold green]✔ OK[/bold green]" if c["ok"] else "[bold red]✖ FAILED[/bold red]"
        table.add_row(c["name"], status_str, c["message"])

    console.print(table)

    if not overall_ok:
        err_console.print("\n[bold yellow]Remedy Suggestions:[/bold yellow]")
        for c in checks:
            if not c["ok"]:
                err_console.print(f" • [bold]{c['name']}:[/bold] {c['suggestion']}")
        raise typer.Exit(code=1)


@db_app.command("init")
def db_init() -> None:
    """Apply the relational graph schema to the database.

    Idempotent schema migration. Connects to the database configured in Settings
    and creates necessary tables, extensions, and indexes.

    Raises RuntimeError if database connection fails.
    """
    from threatlens.graph.store import get_engine, init_schema

    try:
        init_schema(get_engine())
        console.print("[green]✔ Schema applied successfully[/green]")
    except Exception as exc:
        err_console.print(f"[red]✖ Database schema init failed:[/red] {exc}")
        err_console.print("[yellow]Suggestion:[/yellow] Did you mean to start Postgres first?")
        err_console.print("            Run: docker compose up -d db")
        raise typer.Exit(code=1) from exc


@fetch_app.callback(invoke_without_command=True)
def fetch_callback(
    ctx: typer.Context,
    list_sources: bool = typer.Option(
        False, "--list", "-l", help="List available snapshot data sources"
    ),
) -> None:
    """Manage snapshot downloads. Use --list / -l to view available sources."""
    if list_sources:
        _print_fetch_sources(json_output=False)
        raise typer.Exit(code=0)


@fetch_app.command("list")
def fetch_list_cmd(
    json_output: bool = typer.Option(
        False, "--json", "-j", help="Output available sources in JSON format"
    ),
) -> None:
    """Display all available snapshot data sources."""
    _print_fetch_sources(json_output=json_output)


def _print_fetch_sources(json_output: bool) -> None:
    from threatlens.ingest.fetch import ATTACK_URL

    data_raw, _ = _get_data_paths()
    sources = [
        {
            "name": "attack",
            "file": str(data_raw / "enterprise-attack.json"),
            "url": ATTACK_URL,
            "description": "MITRE ATT&CK Enterprise STIX 2.1 dataset snapshot",
        },
        {
            "name": "mappings",
            "file": str(data_raw / "Att&ckToCveMappings.csv"),
            "url": "https://raw.githubusercontent.com/.../Att%26ckToCveMappings.csv",
            "description": "CVE to ATT&CK Technique KEV mappings dataset",
        },
        {
            "name": "nvd",
            "file": str(data_raw / "nvd-scoped.json"),
            "url": "https://services.nvd.nist.gov/rest/json/cves/2.0",
            "description": "NVD CVE API snapshot feed",
        },
    ]

    if json_output:
        print(json.dumps(sources, indent=2))
        return

    table = Table(title="Available Data Sources", show_header=True, header_style="bold green")
    table.add_column("Source", style="cyan")
    table.add_column("Target Path", style="dim")
    table.add_column("Description")

    for s in sources:
        table.add_row(s["name"], s["file"], s["description"])

    console.print(table)


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

    data_raw, manifest = _get_data_paths()
    dest = data_raw / "enterprise-attack.json"

    try:
        with Progress(
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            DownloadColumn(),
            TransferSpeedColumn(),
            TimeRemainingColumn(),
            console=console,
            transient=True,
        ) as progress:
            task = progress.add_task("[cyan]Downloading ATT&CK bundle...", total=None)

            def _on_progress(chunk_size: int, total_bytes: int | None) -> None:
                if total_bytes and progress.tasks[task].total != total_bytes:
                    progress.update(task, total=total_bytes)
                progress.update(task, advance=chunk_size)

            entry = fetch_url(
                ATTACK_URL,
                dest,
                force=force,
                progress_callback=_on_progress,
                manifest_path=manifest,
            )

    except FileExistsError as exc:
        err_console.print(f"[red]✖ Download failed:[/red] {exc}")
        err_console.print("[yellow]Suggestion:[/yellow] Pass --force to re-download snapshot.")
        raise typer.Exit(code=1) from exc
    except Exception as exc:
        err_console.print(f"[red]✖ Download failed:[/red] {exc}")
        raise typer.Exit(code=1) from exc

    if entry.get("not_modified"):
        console.print(
            f"[yellow]✔ Unchanged[/yellow] {dest.name} (HTTP 304 Not Modified) "
            f"sha256={entry['sha256'][:12]}...",
            soft_wrap=True,
        )
    else:
        update_manifest(manifest, dest.name, entry)
        console.print(
            f"[green]✔ Downloaded[/green] {dest}  sha256={entry['sha256'][:12]}...  "
            f"{entry['bytes']} bytes",
            soft_wrap=True,
        )


@ingest_app.command("attack")
def ingest_attack_cmd() -> None:
    """Parse the ATT&CK STIX snapshot and populate the Postgres graph database.

    Reads the enterprise-attack.json snapshot, transforms STIX objects into domain Node
    and Edge records, and performs idempotent batch upserts into Postgres.

    Raises typer.Exit(code=1) if the snapshot file is missing or parser is unavailable.
    """
    data_raw, manifest = _get_data_paths()
    path = data_raw / "enterprise-attack.json"
    if not path.exists():
        err_console.print(f"[red]✖ Snapshot missing at {path}[/red]")
        err_console.print("[yellow]Suggestion:[/yellow] Run: threatlens fetch attack")
        raise typer.Exit(code=1)

    try:
        from threatlens.ingest.attack import ingest_attack
    except ImportError:
        err_console.print("[red]✖ Ingest attack parser unavailable[/red]")
        raise typer.Exit(code=1) from None

    from threatlens.graph.store import get_engine

    sha = ""
    if manifest.exists():
        try:
            manifest_data = json.loads(manifest.read_text(encoding="utf-8"))
            sha = manifest_data.get(path.name, {}).get("sha256", "")
        except json.JSONDecodeError:
            sha = ""

    try:
        with get_engine().begin() as conn:
            n_nodes, n_edges = ingest_attack(path, sha, conn)
    except Exception as exc:
        err_console.print(f"[red]✖ Ingestion failed:[/red] {exc}")
        err_console.print(
            "[yellow]Suggestion:[/yellow] Verify database schema with: threatlens db init"
        )
        raise typer.Exit(code=1) from exc

    console.print(f"[green]✔ Inserted[/green] {n_nodes} nodes, {n_edges} edges")


@app.command("stats")
def stats(
    json_output: bool = typer.Option(
        False, "--json", "-j", help="Output entity stats in JSON format"
    ),
) -> None:
    """Print count summaries of graph nodes and edges grouped by kind.

    Connects to the configured database, retrieves entity counts by category,
    and displays a formatted breakdown. Use --json / -j for JSON format.

    Requires an initialized database schema.
    """
    from threatlens.graph.store import edge_counts, get_engine, node_counts

    try:
        with get_engine().connect() as conn:
            nodes = node_counts(conn)
            edges = edge_counts(conn)
    except Exception as exc:
        err_console.print(f"[red]✖ Database error:[/red] {exc}")
        err_console.print("[yellow]Suggestion:[/yellow] Did you mean threatlens db init?")
        raise typer.Exit(code=1) from exc

    if json_output:
        print(json.dumps({"nodes": nodes, "edges": edges}, indent=2))
        return

    table = Table(title="Graph Entity Statistics", show_header=True, header_style="bold green")
    table.add_column("Category", style="cyan")
    table.add_column("Kind", style="yellow")
    table.add_column("Count", style="magenta", justify="right")

    for kind, n in sorted(nodes.items()):
        table.add_row("Node", kind, str(n))
    for kind, n in sorted(edges.items()):
        table.add_row("Edge", kind, str(n))

    console.print(table)


@app.command("show")
def show(
    node_id: str = typer.Argument(
        ..., help="Node ID or external ID (e.g. T1190 or technique:T1190)"
    ),
    json_output: bool = typer.Option(
        False, "--json", "-j", help="Output node metadata in JSON format"
    ),
) -> None:
    """Display detailed attributes and outgoing relationships for a specific graph node.

    Accepts full node IDs (e.g., technique:T1190) or bare external IDs (e.g., T1190, TA0001,
    M1030, G0016, S0154, CVE-2021-44228) and prints its metadata and linked neighbors.

    Raises typer.Exit(code=1) if the requested node is not found in the database.
    """
    from threatlens.graph.store import get_engine, get_node, neighbors

    resolved = node_id if ":" in node_id else _guess_id(node_id)
    try:
        with get_engine().connect() as conn:
            node = get_node(conn, resolved)
            if node is None:
                err_console.print(f"[red]✖ Not found:[/red] {resolved}")
                err_console.print(
                    "[yellow]Suggestion:[/yellow] Check node ID (e.g. T1190, TA0001, M1030)"
                )
                raise typer.Exit(code=1)

            kinds = [
                "BELONGS_TO",
                "MITIGATED_BY",
                "SUBTECHNIQUE_OF",
                "CHAINS_TO",
                "USES",
                "USES_SOFTWARE",
            ]
            rows = neighbors(conn, node.id, kinds)
    except typer.Exit:
        raise
    except Exception as exc:
        err_console.print(f"[red]✖ Database error:[/red] {exc}")
        err_console.print("[yellow]Suggestion:[/yellow] Did you mean threatlens db init?")
        raise typer.Exit(code=1) from exc

    if json_output:
        edge_list = [
            {"kind": edge.kind, "target_id": target.id, "target_name": target.name}
            for edge, target in rows
        ]
        out = {
            "id": node.id,
            "kind": node.kind,
            "external_id": node.external_id,
            "name": node.name,
            "source_url": node.source_url,
            "description": node.description,
            "edges": edge_list,
        }
        print(json.dumps(out, indent=2))
        return

    content = f"[bold cyan]{node.id}[/bold cyan] — [bold]{node.name}[/bold]\n"
    content += f"[dim]{node.source_url}[/dim]\n"
    if node.description:
        content += f"\n{node.description[:400]}..."

    console.print(Panel(content, title=f"Node Detail: {node.external_id}", expand=False))

    if rows:
        table = Table(title="Outgoing Relationships", show_header=True, header_style="bold blue")
        table.add_column("Relationship", style="yellow")
        table.add_column("Target ID", style="cyan")
        table.add_column("Target Name")

        for edge, target in rows:
            table.add_row(edge.kind, target.id, target.name)

        console.print(table)


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
