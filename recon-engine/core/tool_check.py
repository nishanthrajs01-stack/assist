"""
core/tool_check.py — Pre-flight check for required external tools.

Run before any pipeline phase to ensure all binaries are available.
"""

import shutil
import sys
from typing import Dict, List, Optional, Tuple

from rich.console import Console
from rich.table import Table

console = Console()

# Tools required for the full pipeline vs optional phases
REQUIRED_TOOLS: List[str] = ["subfinder", "dnsx", "httpx"]
OPTIONAL_TOOLS: List[Tuple[str, str]] = [
    ("katana", "Phase 4 – JS crawl"),
    ("gau",    "Phase 4 – historical URL harvesting"),
    ("nuclei", "Phase 5 – vulnerability scanning"),
]


def check_tools(
    tool_paths: Optional[Dict[str, str]] = None,
) -> Dict[str, Optional[str]]:
    """
    Check that all required and optional external tools are available.

    :param tool_paths: Optional dict overriding PATH lookup (e.g. from settings.yaml).
                       Keys are tool names, values are configured paths.
    :returns: Dict mapping tool name → resolved path (or None if not found).
    :raises SystemExit: If any REQUIRED tool is missing.
    """
    overrides = tool_paths or {}
    results: Dict[str, Optional[str]] = {}

    all_tools = [(t, "required") for t in REQUIRED_TOOLS] + [
        (t, f"optional – {desc}") for t, desc in OPTIONAL_TOOLS
    ]

    table = Table(title="[bold]ReconEngine — Tool Pre-flight Check[/]", border_style="dim")
    table.add_column("Tool",   style="cyan",  no_wrap=True)
    table.add_column("Status", style="white", no_wrap=True)
    table.add_column("Path",   style="dim")
    table.add_column("Role",   style="dim")

    missing_required: List[str] = []

    for tool, role in all_tools:
        # Use settings-configured path first, then PATH lookup
        configured = overrides.get(tool, tool)
        resolved = shutil.which(configured)
        results[tool] = resolved

        if resolved:
            table.add_row(tool, "[green]✔ found[/]", resolved, role)
        else:
            if role == "required":
                table.add_row(tool, "[bold red]✘ MISSING[/]", "—", f"[bold red]{role}[/]")
                missing_required.append(tool)
            else:
                table.add_row(tool, "[yellow]⚠ not found[/]", "—", role)

    console.print(table)

    if missing_required:
        console.print(
            f"\n[bold red]✘ {len(missing_required)} required tool(s) missing: "
            f"{', '.join(missing_required)}[/]\n"
            "[dim]Install from: https://github.com/projectdiscovery[/]\n"
            "  go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest\n"
            "  go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest\n"
            "  go install github.com/projectdiscovery/httpx/cmd/httpx@latest\n"
        )
        sys.exit(1)

    return results
