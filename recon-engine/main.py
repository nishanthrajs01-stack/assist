"""
main.py — Master CLI entrypoint for ReconEngine.

Usage:
  python main.py init-db
  python main.py scan --all
  python main.py scan --program "Example Program"
  python main.py dashboard
  python main.py notify
"""

import asyncio
import sys
from pathlib import Path
from typing import Optional

import click
import yaml
from rich.console import Console
from rich.table import Table

console = Console()

# Resolve project root relative to this file so CLI works from any CWD
PROJECT_ROOT = Path(__file__).parent


@click.group()
def cli():
    """ReconEngine — Automated Bug Bounty Recon Pipeline"""
    pass


# ---------------------------------------------------------------------------
# init-db
# ---------------------------------------------------------------------------

@cli.command("init-db")
def init_db_cmd():
    """Initialize the SQLite database and create all tables."""
    from core.database import init_db
    init_db()
    console.print("[green]✔ Database initialized successfully.[/]")


# ---------------------------------------------------------------------------
# scan
# ---------------------------------------------------------------------------

@cli.command("scan")
@click.option("--program", "-p", default=None, help="Run scan for a specific program name.")
@click.option("--all", "scan_all", is_flag=True, default=False, help="Run scan for all configured programs.")
@click.option("--no-nuclei", is_flag=True, default=False, help="Skip Nuclei scanning phase.")
@click.option("--notify/--no-notify", default=True, help="Send webhook alerts after scan (default: on).")
def scan(program: Optional[str], scan_all: bool, no_nuclei: bool, notify: bool):
    """Run the recon pipeline for one or all programs."""
    if not program and not scan_all:
        console.print("[red]✘ Specify --program 'Name' or --all[/]")
        sys.exit(1)

    with open(PROJECT_ROOT / "config" / "targets.yaml") as f:
        targets = yaml.safe_load(f)

    programs_cfg = targets.get("programs", [])

    if program:
        programs_cfg = [p for p in programs_cfg if p["name"] == program]
        if not programs_cfg:
            console.print(f"[red]✘ Program '{program}' not found in targets.yaml[/]")
            sys.exit(1)

    asyncio.run(_run_all(programs_cfg, run_nuclei=not no_nuclei, notify=notify))


async def _run_all(programs_cfg: list, run_nuclei: bool, notify: bool):
    from core.database import Program, SessionLocal
    from core.diff_engine import DiffEngine
    from core.ingester import Ingester
    from core.runner import PipelineRunner
    from alerts.notifier import dispatch_pending

    for prog_cfg in programs_cfg:
        prog_name = prog_cfg["name"]
        domains   = prog_cfg.get("domains", [])

        # Ensure program exists in DB
        with SessionLocal() as db:
            prog = db.query(Program).filter_by(name=prog_name).first()
            if not prog:
                prog = Program(name=prog_name)
                db.add(prog)
                db.commit()
                db.refresh(prog)
            prog_id = prog.id

        ingester = Ingester(prog_name)
        runner   = PipelineRunner(prog_name, domains, ingester)
        await runner.run(run_nuclei=run_nuclei)

        # Run diff engine
        engine = DiffEngine(prog_id)
        events = engine.run()
        console.print(f"[cyan]▶ Diff Engine: {len(events)} change events detected[/]")

    # Dispatch notifications
    if notify:
        dispatched = await dispatch_pending()
        console.print(f"[green]✔ Notifications dispatched: {dispatched} alerts sent[/]")


# ---------------------------------------------------------------------------
# dashboard
# ---------------------------------------------------------------------------

@cli.command("dashboard")
@click.option("--host", default=None, help="Override dashboard host.")
@click.option("--port", default=None, type=int, help="Override dashboard port.")
def dashboard(host: Optional[str], port: Optional[int]):
    """Start the FastAPI dashboard server."""
    import uvicorn
    from core.config import settings

    h = host or settings.dashboard.host
    p = port or settings.dashboard.port

    console.print(f"[bold green]ReconEngine Dashboard starting on http://{h}:{p}[/]")
    console.print(f"[dim]Access via SSH tunnel: ssh -L {p}:{h}:{p} user@your-vps[/]")
    uvicorn.run("dashboard.app:app", host=h, port=p, log_level="warning")


# ---------------------------------------------------------------------------
# notify
# ---------------------------------------------------------------------------

@cli.command("notify")
def notify():
    """Dispatch pending webhook alerts for all un-notified diff events."""
    from alerts.notifier import dispatch_pending
    dispatched = asyncio.run(dispatch_pending())
    console.print(f"[green]✔ Dispatched {dispatched} pending alert(s).[/]")


# ---------------------------------------------------------------------------
# status
# ---------------------------------------------------------------------------

@cli.command("status")
def status():
    """Show a summary of the current asset database."""
    from core.database import Domain, Endpoint, DiffEvent, Program, SessionLocal
    from sqlalchemy import func

    with SessionLocal() as db:
        table = Table(title="ReconEngine Database Status", style="cyan")
        table.add_column("Metric", style="white", justify="left")
        table.add_column("Count", style="bold green", justify="right")

        table.add_row("Programs",       str(db.query(func.count(Program.id)).scalar()))
        table.add_row("Total Domains",  str(db.query(func.count(Domain.id)).scalar()))
        table.add_row("Active Domains", str(db.query(func.count(Domain.id)).filter(Domain.is_active == True).scalar()))
        table.add_row("Endpoints",      str(db.query(func.count(Endpoint.id)).scalar()))
        table.add_row("Diff Events",    str(db.query(func.count(DiffEvent.id)).scalar()))
        table.add_row("Unread Alerts",  str(db.query(func.count(DiffEvent.id)).filter(DiffEvent.notified == False).scalar()))

        console.print(table)


if __name__ == "__main__":
    cli()
