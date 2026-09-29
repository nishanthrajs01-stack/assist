"""InfraGraph Command-Line Interface."""
import asyncio
import json
import click
import uvicorn
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

from infragraph.scanner import InfraScanner
from infragraph.models.graph import InfraGraph
from infragraph.models.nodes import RiskLevel, NodeType
from infragraph.models.edges import EdgeType
from infragraph.analyzer.diff import GraphDiffEngine

console = Console()


@click.group()
def main():
    """🌐 InfraGraph — Attack Surface Graph & Orphan Asset Tracker."""
    pass


@main.command()
@click.argument("domain")
@click.option("--output", "-o", default=None, help="Save snapshot to JSON file.")
@click.option("--concurrency", "-c", default=50, help="Async DNS concurrency.")
@click.option("--no-bruteforce", is_flag=True, default=False, help="Disable common prefix active bruteforce.")
def scan(domain: str, output: str, concurrency: int, no_bruteforce: bool):
    """Scan target domain for subdomains, IPs, ASNs, and takeover vulnerabilities."""
    console.print(Panel.fit(
        f"[bold cyan]InfraGraph Reconnaissance Engine[/bold cyan]\nTarget: [bold yellow]{domain}[/bold yellow]",
        border_style="cyan"
    ))

    async def _run():
        scanner = InfraScanner(
            concurrency=concurrency,
            enable_active_bruteforce=not no_bruteforce
        )
        with console.status("[bold green]Scanning CT logs, DNS records, ASN routing, and Cloud assets...[/bold green]"):
            graph = await scanner.scan_domain(domain)
        return graph

    graph = asyncio.run(_run())
    stats = graph.get_stats()

    # Print Summary Table
    table = Table(title="[bold green]Scan Summary[/bold green]", border_style="dim")
    table.add_column("Metric", style="cyan")
    table.add_column("Count", style="magenta")

    table.add_row("Total Graph Nodes", str(stats.total_nodes))
    table.add_row("Total Graph Edges", str(stats.total_edges))
    table.add_row("Subdomains Discovered", str(stats.subdomains_count))
    table.add_row("Resolved IP Addresses", str(stats.ips_count))
    table.add_row("Carrier ASNs", str(stats.asns_count))
    table.add_row("Cloud Target Pointers", str(stats.cloud_resources_count))
    table.add_row("🚨 Dangling Takeovers", f"[bold red]{stats.dangling_records_count}[/bold red]")
    console.print(table)

    # Print Findings Table
    dangling_edges = [e for e in graph.edges.values() if e.type == EdgeType.DANGLING_TARGET]
    if dangling_edges:
        vuln_table = Table(title="[bold red]🚨 Dangling Takeover Findings[/bold red]", border_style="red")
        vuln_table.add_column("Vulnerable Subdomain", style="yellow")
        vuln_table.add_column("Target / Service", style="cyan")
        vuln_table.add_column("Remediation", style="green")

        for edge in dangling_edges:
            vuln_table.add_row(
                edge.source_id,
                edge.target_id,
                edge.attributes.get("remediation", "Delete DNS CNAME")
            )
        console.print(vuln_table)
    else:
        console.print("[green]✔ No dangling CNAME takeover vulnerabilities detected.[/green]")

    # Save to file
    out_file = output or f"infragraph_{domain.replace('.', '_')}.json"
    with open(out_file, "w", encoding="utf-8") as f:
        f.write(graph.to_json())
    console.print(f"[dim]Graph snapshot saved to: [bold]{out_file}[/bold][/dim]\n")


@main.command()
@click.argument("old_snapshot")
@click.argument("new_snapshot")
def diff(old_snapshot: str, new_snapshot: str):
    """Compare two InfraGraph snapshot JSON files."""
    with open(old_snapshot, "r", encoding="utf-8") as f:
        g_old = InfraGraph.from_json(f.read())
    with open(new_snapshot, "r", encoding="utf-8") as f:
        g_new = InfraGraph.from_json(f.read())

    delta = GraphDiffEngine.compare(g_old, g_new)

    console.print(Panel.fit(
        f"[bold blue]InfraGraph Differential Comparison[/bold blue]\n"
        f"Old: [yellow]{delta.old_snapshot_name}[/yellow] vs New: [green]{delta.new_snapshot_name}[/green]",
        border_style="blue"
    ))

    t = Table(title="Asset Deltas", border_style="dim")
    t.add_column("Category", style="cyan")
    t.add_column("Delta Count", style="magenta")

    t.add_row("Added Nodes (New Assets)", f"[green]+{len(delta.added_nodes)}[/green]")
    t.add_row("Removed Nodes (Decommissioned)", f"[red]-{len(delta.removed_nodes)}[/red]")
    t.add_row("Added Edges", f"[green]+{len(delta.added_edges)}[/green]")
    t.add_row("Removed Edges", f"[red]-{len(delta.removed_edges)}[/red]")
    t.add_row("🚨 New Takeovers Introduced", f"[bold red]+{len(delta.new_vulnerabilities)}[/bold red]")
    t.add_row("✔ Resolved Takeovers", f"[bold green]-{len(delta.resolved_vulnerabilities)}[/bold green]")
    console.print(t)

    if delta.added_nodes:
        console.print("\n[bold green]New Discovered Assets:[/bold green]")
        for n in delta.added_nodes:
            console.print(f"  + [{n.type.value}] {n.label}")


@main.command()
@click.option("--host", default="0.0.0.0", help="Host address to bind to.")
@click.option("--port", default=8888, help="Port number for web server.")
def serve(host: str, port: int):
    """Start the interactive InfraGraph Web Dashboard & API."""
    console.print(Panel.fit(
        f"[bold green]Starting InfraGraph Web UI & API Server[/bold green]\n"
        f"URL: [bold cyan]http://localhost:{port}[/bold cyan]",
        border_style="green"
    ))
    uvicorn.run("infragraph.web.server:app", host=host, port=port, log_level="info")


if __name__ == "__main__":
    main()
