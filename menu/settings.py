"""
menu/settings.py
Gulf DataStream Labs — Sombra
Settings screen — manage tool filenames without editing tools.json directly.

Allows the analyst to:
  - View all configured tool slots and their current filenames
  - See which tools are present on disk (green) vs missing (red)
  - Update any tool filename to match what's actually in the tools/ folder
  - Save changes back to tools.json
"""

import os
from pathlib import Path
from typing import Optional

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich import box

from engine.tools import ToolConfig

console = Console()

C_GOOD  = "bold green"
C_WARN  = "bold yellow"
C_BAD   = "bold red"
C_CYAN  = "cyan"
C_DIM   = "dim white"
C_WHITE = "white"


def _clear():
    os.system("cls" if os.name == "nt" else "clear")


def _build_table(tc: ToolConfig) -> tuple:
    """
    Build the settings table and return (table, index_map).
    index_map maps display number -> (category, slug).
    """
    table = Table(
        show_header=True,
        header_style="bold cyan",
        box=box.SIMPLE_HEAD,
        padding=(0, 1),
    )
    table.add_column("#",         width=4,  style="cyan")
    table.add_column("Category",  width=14)
    table.add_column("Tool Slot", width=16)
    table.add_column("Configured Filename", width=36)
    table.add_column("Status",    width=10)

    index_map = {}
    num = 1

    for category in ["sysinternals", "nirsoft", "memory"]:
        for slug, filename in tc._config.get(category, {}).items():
            p = tc.tools_dir / filename
            if p.exists():
                status = Text("FOUND",   style=C_GOOD)
                fname_style = C_WHITE
            else:
                status = Text("MISSING", style=C_BAD)
                fname_style = C_BAD

            table.add_row(
                str(num),
                category,
                slug,
                Text(filename, style=fname_style),
                status,
            )
            index_map[num] = (category, slug)
            num += 1

    return table, index_map


def show_settings(tools_dir: Path):
    """
    Display the settings screen and handle tool filename editing.

    Args:
        tools_dir: Path to the tools/ directory containing tools.json.
    """
    while True:
        _clear()
        tc = ToolConfig(tools_dir)

        # Count found vs total
        status = tc.check_tools()
        found  = sum(1 for v in status.values() if v["found"])
        total  = len(status)

        table, index_map = _build_table(tc)

        console.print(Panel(
            f"[{C_CYAN}]Tools Directory:[/{C_CYAN}] {tools_dir}\n"
            f"[{C_CYAN}]Status         :[/{C_CYAN}] "
            f"[{C_GOOD}]{found}[/{C_GOOD}] found / "
            f"[{C_BAD}]{total - found}[/{C_BAD}] missing / "
            f"{total} total\n\n"
            f"[{C_DIM}]Enter a number to edit that tool's filename.[/{C_DIM}]\n"
            f"[{C_DIM}]Sombra will look for the file in the tools/ directory.[/{C_DIM}]",
            title="[bold cyan]Settings — Tool Configuration[/bold cyan]",
            border_style="cyan",
        ))

        console.print(table)

        # Show available files in tools/ for reference
        _show_available_files(tools_dir)

        console.print(
            f"\n  [{C_DIM}]Enter number to edit · [S] Save · [R] Reload · [Q] Back[/{C_DIM}]\n"
        )

        try:
            choice = console.input(f"  [{C_CYAN}]>[/{C_CYAN}] ").strip().upper()
        except KeyboardInterrupt:
            break

        if choice == "Q":
            break

        elif choice == "S":
            tc.save()
            console.print(f"  [{C_GOOD}][+] Saved to tools/tools.json[/{C_GOOD}]")
            console.input(f"  [{C_DIM}]Press Enter to continue...[/{C_DIM}]")

        elif choice == "R":
            # Reload just re-runs the loop
            continue

        else:
            try:
                num = int(choice)
                if num in index_map:
                    _edit_tool(tc, index_map[num], tools_dir)
                else:
                    console.print(f"  [{C_WARN}]Invalid number[/{C_WARN}]")
                    console.input(f"  [{C_DIM}]Press Enter...[/{C_DIM}]")
            except ValueError:
                pass


def _edit_tool(tc: ToolConfig, slot: tuple, tools_dir: Path):
    """
    Prompt the analyst to enter a new filename for a tool slot.

    Args:
        tc:        ToolConfig instance to modify.
        slot:      (category, slug) tuple identifying the tool.
        tools_dir: Path to the tools directory.
    """
    category, slug = slot
    current  = tc.filename(category, slug) or ""

    console.print()
    console.print(f"  [{C_CYAN}]Tool    :[/{C_CYAN}] {category} / {slug}")
    console.print(f"  [{C_CYAN}]Current :[/{C_CYAN}] {current}")

    # Show matching files as suggestions
    _show_matching_files(tools_dir, slug, current)

    console.print()
    try:
        new_name = console.input(
            f"  [{C_CYAN}]New filename (Enter to keep current):[/{C_CYAN}] "
        ).strip()
    except KeyboardInterrupt:
        return

    if not new_name:
        console.print(f"  [{C_DIM}]Unchanged.[/{C_DIM}]")
        console.input(f"  [{C_DIM}]Press Enter...[/{C_DIM}]")
        return

    # Check if the file exists before accepting
    new_path = tools_dir / new_name
    if new_path.exists():
        tc._config[category][slug] = new_name
        tc.save()
        console.print(f"  [{C_GOOD}][+] Updated: {slug} → {new_name}[/{C_GOOD}]")
        console.print(f"  [{C_GOOD}]    Saved to tools/tools.json[/{C_GOOD}]")
    else:
        console.print(
            f"  [{C_WARN}][!] File not found in tools/: {new_name}[/{C_WARN}]"
        )
        console.print(
            f"  [{C_WARN}]    Copy the file to {tools_dir} first, then try again.[/{C_WARN}]"
        )
        try:
            force = console.input(
                f"  [{C_DIM}]Save anyway? (file may be staged later) [y/N]: [/{C_DIM}]"
            ).strip().lower()
        except KeyboardInterrupt:
            return
        if force == "y":
            tc._config[category][slug] = new_name
            tc.save()
            console.print(f"  [{C_WARN}][~] Saved (file not yet present): {slug} → {new_name}[/{C_WARN}]")

    console.input(f"  [{C_DIM}]Press Enter...[/{C_DIM}]")


def _show_available_files(tools_dir: Path):
    """Show all .exe files currently in the tools directory."""
    if not tools_dir.exists():
        return

    exe_files = sorted(tools_dir.glob("*.exe"))
    if not exe_files:
        console.print(f"\n  [{C_DIM}]No .exe files found in tools/ directory yet.[/{C_DIM}]")
        return

    console.print(f"\n  [{C_DIM}]Files in tools/ directory:[/{C_DIM}]")
    for f in exe_files:
        size_kb = f.stat().st_size // 1024
        console.print(f"  [{C_DIM}]  {f.name:<45} ({size_kb:,} KB)[/{C_DIM}]")


def _show_matching_files(tools_dir: Path, slug: str, current: str):
    """Show files in tools/ that might match this tool slot."""
    if not tools_dir.exists():
        return

    slug_lower = slug.lower()
    matches = [
        f for f in sorted(tools_dir.glob("*.exe"))
        if slug_lower in f.name.lower() or f.name == current
    ]

    if matches:
        console.print(f"  [{C_DIM}]Possible matches in tools/:[/{C_DIM}]")
        for f in matches:
            marker = " ← current" if f.name == current else ""
            console.print(f"  [{C_CYAN}]  {f.name}[/{C_CYAN}][{C_DIM}]{marker}[/{C_DIM}]")
