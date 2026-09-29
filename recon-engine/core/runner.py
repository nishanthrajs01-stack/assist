"""
core/runner.py — Async subprocess orchestrator.

Runs the full pipeline per program:
  subfinder → dnsx → httpx → gau+katana → (nuclei)
Each stage streams JSONL stdout line-by-line into the ingester.
"""

import asyncio
import json
import os
import tempfile
from pathlib import Path
from typing import AsyncIterator, Callable, List, Optional

from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, TimeElapsedColumn

from core.config import settings

console = Console()


# ---------------------------------------------------------------------------
# Low-level process execution
# ---------------------------------------------------------------------------

async def _stream_jsonl(
    cmd: List[str],
    timeout: int = 900,
    cwd: Optional[str] = None,
) -> AsyncIterator[dict]:
    """
    Run a command and yield each line of stdout parsed as JSON.
    Lines that are not valid JSON are silently skipped.
    """
    proc = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.DEVNULL,
        cwd=cwd,
    )
    try:
        async with asyncio.timeout(timeout):
            async for raw_line in proc.stdout:
                line = raw_line.decode("utf-8", errors="replace").strip()
                if not line:
                    continue
                try:
                    yield json.loads(line)
                except json.JSONDecodeError:
                    continue
    except asyncio.TimeoutError:
        console.print(f"[yellow]⚠ Timeout reached for: {' '.join(cmd[:3])}[/]")
        proc.kill()
    await proc.wait()


async def _run_to_file(cmd: List[str], output_path: str, timeout: int = 900) -> bool:
    """Run a command writing stdout to a file. Returns True on success."""
    with open(output_path, "w") as fout:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=fout,
            stderr=asyncio.subprocess.DEVNULL,
        )
        try:
            async with asyncio.timeout(timeout):
                await proc.wait()
        except asyncio.TimeoutError:
            console.print(f"[yellow]⚠ Timeout: {' '.join(cmd[:3])}[/]")
            proc.kill()
            return False
    return proc.returncode == 0


# ---------------------------------------------------------------------------
# Pipeline stages
# ---------------------------------------------------------------------------

class PipelineRunner:
    def __init__(self, program_name: str, domains: List[str], on_result: Callable):
        """
        :param program_name: Bug bounty program label.
        :param domains: List of root domains for this program.
        :param on_result: Async callback receiving (stage: str, record: dict) per result.
        """
        self.program_name = program_name
        self.domains = domains
        self.on_result = on_result
        self.cfg = settings.tools
        self.scan = settings.scan
        self.timeout = self.scan.phase_timeout

    # ------------------------------------------------------------------
    # Stage 1: Subdomain Discovery
    # ------------------------------------------------------------------
    async def _phase_subdomains(self, tmpdir: str) -> str:
        """Runs subfinder across all root domains. Returns path to combined subdomain list."""
        console.print(f"[cyan]▶ Phase 1: Subdomain Discovery — {self.program_name}[/]")
        all_subs_path = os.path.join(tmpdir, "subdomains.txt")
        gathered = set()

        for domain in self.domains:
            cmd = [
                self.cfg.subfinder, "-d", domain,
                "-all", "-silent",
                "-t", str(self.scan.subfinder_threads),
            ]
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.DEVNULL,
            )
            try:
                async with asyncio.timeout(self.timeout):
                    stdout, _ = await proc.communicate()
                    for line in stdout.decode().splitlines():
                        sub = line.strip()
                        if sub:
                            gathered.add(sub)
                            await self.on_result("subdomain", {"subdomain": sub, "program": self.program_name})
            except asyncio.TimeoutError:
                console.print(f"[yellow]⚠ subfinder timeout for {domain}[/]")
                proc.kill()

        with open(all_subs_path, "w") as f:
            f.write("\n".join(sorted(gathered)))

        console.print(f"[green]✔ Phase 1: {len(gathered)} subdomains discovered[/]")
        return all_subs_path

    # ------------------------------------------------------------------
    # Stage 2: DNS Resolution
    # ------------------------------------------------------------------
    async def _phase_dns(self, subdomains_path: str, tmpdir: str) -> str:
        """Resolves active DNS records using dnsx. Returns path to active hosts."""
        console.print(f"[cyan]▶ Phase 2: DNS Resolution[/]")
        active_path = os.path.join(tmpdir, "active_hosts.txt")
        dns_json_path = os.path.join(tmpdir, "dns.jsonl")

        cmd = [
            self.cfg.dnsx,
            "-l", subdomains_path,
            "-r", self.cfg.resolvers,
            "-t", str(self.scan.dnsx_threads),
            "-silent", "-resp", "-json",
            "-a", "-cname", "-aaaa",
        ]

        count = 0
        with open(active_path, "w") as active_f, open(dns_json_path, "w") as json_f:
            async for record in _stream_jsonl(cmd, timeout=self.timeout):
                host = record.get("host", "")
                if host:
                    active_f.write(host + "\n")
                    json_f.write(json.dumps(record) + "\n")
                    count += 1
                    await self.on_result("dns", record)

        console.print(f"[green]✔ Phase 2: {count} active hosts resolved[/]")
        return active_path

    # ------------------------------------------------------------------
    # Stage 3: HTTP Probing
    # ------------------------------------------------------------------
    async def _phase_http(self, active_hosts_path: str, tmpdir: str) -> str:
        """Probes HTTP services using httpx. Returns path to alive URL list."""
        console.print(f"[cyan]▶ Phase 3: HTTP Probing[/]")
        alive_urls_path = os.path.join(tmpdir, "alive_urls.txt")

        cmd = [
            self.cfg.httpx,
            "-l", active_hosts_path,
            "-t", str(self.scan.httpx_threads),
            "-silent", "-json",
            "-title", "-status-code", "-tech-detect",
            "-web-server", "-content-length",
            "-hash", "sha256",
            "-follow-redirects",
        ]

        count = 0
        with open(alive_urls_path, "w") as f:
            async for record in _stream_jsonl(cmd, timeout=self.timeout):
                url = record.get("url", "")
                if url:
                    f.write(url + "\n")
                    count += 1
                    await self.on_result("http", record)

        console.print(f"[green]✔ Phase 3: {count} live HTTP services found[/]")
        return alive_urls_path

    # ------------------------------------------------------------------
    # Stage 4: URL & Endpoint Harvesting
    # ------------------------------------------------------------------
    async def _phase_endpoints(self, alive_urls_path: str) -> None:
        """Harvests endpoints from Wayback Machine (gau) and live crawling (katana)."""
        console.print(f"[cyan]▶ Phase 4: Endpoint Harvesting[/]")
        count = 0

        # 4a. gau — historical URLs from Wayback / Common Crawl
        for domain in self.domains:
            cmd = [self.cfg.gau, domain, "--json", "--threads", "5", "--timeout", "30"]
            async for record in _stream_jsonl(cmd, timeout=self.timeout):
                record["source"] = "gau"
                count += 1
                await self.on_result("endpoint", record)

        # 4b. katana — active JavaScript crawl
        cmd = [
            self.cfg.katana,
            "-list", alive_urls_path,
            "-d", str(self.scan.katana_depth),
            "-jc",   # enable JS crawl
            "-silent", "-json",
        ]
        async for record in _stream_jsonl(cmd, timeout=self.timeout):
            record["source"] = "katana"
            count += 1
            await self.on_result("endpoint", record)

        console.print(f"[green]✔ Phase 4: {count} endpoints harvested[/]")

    # ------------------------------------------------------------------
    # Stage 5: Nuclei Scanning (new assets only)
    # ------------------------------------------------------------------
    async def _phase_nuclei(self, alive_urls_path: str) -> None:
        """Runs Nuclei against configured template tags on discovered assets."""
        console.print(f"[cyan]▶ Phase 5: Nuclei Scanning[/]")
        count = 0

        tags = ",".join(self.scan.nuclei_tags)
        cmd = [
            self.cfg.nuclei,
            "-l", alive_urls_path,
            "-tags", tags,
            "-silent", "-json",
            "-timeout", "10",
        ]

        async for record in _stream_jsonl(cmd, timeout=self.timeout * 2):
            count += 1
            await self.on_result("nuclei", record)

        console.print(f"[green]✔ Phase 5: {count} Nuclei findings[/]")

    # ------------------------------------------------------------------
    # Full Pipeline Entry Point
    # ------------------------------------------------------------------
    async def run(self, run_nuclei: bool = True) -> None:
        console.print(f"\n[bold magenta]══ ReconEngine — {self.program_name} ══[/]\n")

        # Pre-flight: verify all required external tools exist
        from core.tool_check import check_tools
        tool_overrides = {
            "subfinder": self.cfg.subfinder,
            "dnsx":      self.cfg.dnsx,
            "httpx":     self.cfg.httpx,
            "katana":    self.cfg.katana,
            "gau":       self.cfg.gau,
            "nuclei":    self.cfg.nuclei,
        }
        check_tools(tool_overrides)

        with tempfile.TemporaryDirectory(prefix="recon_") as tmpdir:
            subs_path   = await self._phase_subdomains(tmpdir)
            active_path = await self._phase_dns(subs_path, tmpdir)
            alive_path  = await self._phase_http(active_path, tmpdir)
            await self._phase_endpoints(alive_path)
            if run_nuclei:
                await self._phase_nuclei(alive_path)

        console.print(f"\n[bold green]✔ Pipeline complete — {self.program_name}[/]\n")
