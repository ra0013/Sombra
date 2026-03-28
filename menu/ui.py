"""
menu/ui.py
Gulf DataStream Labs — Sombra
Rich-based terminal UI — banner, profile selection, and toggle screen.

Uses the 'rich' library for colored output, panels, and tables.
Works identically on Windows and Linux, and over remote shells
including SSH, RDP console sessions, and PsExec.

pip install rich
"""

import os
import sys
from pathlib import Path
from typing import Optional

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich import box

from engine.platform import (
    HOSTNAME, PLATFORM, ARCH, IS_WIN,
    is_elevated, elevation_label, now_str
)
from engine.profile import Profile, load_all_profiles

console = Console()

# ── Color scheme ──────────────────────────────────────────────────────────────
C_TITLE   = "bold cyan"
C_GOOD    = "bold green"
C_WARN    = "bold yellow"
C_BAD     = "bold red"
C_DIM     = "dim white"
C_WHITE   = "white"
C_CYAN    = "cyan"
C_MAGENTA = "magenta"


# ── Banner ────────────────────────────────────────────────────────────────────

def print_banner(case_name: str = "", output_dir: str = "", profile_name: str = ""):
    """
    Print the Sombra banner with current session state.

    Displays:
      - Sombra title and Gulf DataStream Labs attribution
      - Host, platform, architecture, timestamp
      - Elevation status (green if admin, red if not)
      - Current case name, output directory, and active profile

    Args:
        case_name:   Active case name (empty string if not set).
        output_dir:  Active output directory path.
        profile_name: Active profile name.
    """
    os.system("cls" if IS_WIN else "clear")

    # Elevation badge
    if is_elevated():
        elev_text = Text(f"  [+] {elevation_label()}", style=C_GOOD)
    else:
        elev_text = Text(f"  [!] {elevation_label()} — some collections will fail", style=C_BAD)

    # Header panel
    header = (
        f"[{C_TITLE}]Sombra[/{C_TITLE}] — Gulf DataStream Labs\n"
        f"[{C_DIM}]Digital Forensics Collection Engine[/{C_DIM}]\n\n"
        f"[{C_CYAN}]Host      :[/{C_CYAN}] {HOSTNAME}\n"
        f"[{C_CYAN}]Platform  :[/{C_CYAN}] {PLATFORM}  ({ARCH})\n"
        f"[{C_CYAN}]Time      :[/{C_CYAN}] {now_str()}\n"
    )
    console.print(Panel(header, border_style="cyan", padding=(0, 1)))
    console.print(elev_text)

    # Session state
    if case_name or output_dir or profile_name:
        console.print()
        if case_name:
            console.print(f"  [{C_WHITE}]Case    :[/{C_WHITE}] {case_name}")
        else:
            console.print(f"  [{C_WARN}]Case    : (not set)[/{C_WARN}]")
        console.print(f"  [{C_WHITE}]Output  :[/{C_WHITE}] {output_dir or str(Path.cwd())}")
        console.print(f"  [{C_WHITE}]Profile :[/{C_WHITE}] {profile_name or '(not set)'}")
    console.print()


# ── Profile selection ─────────────────────────────────────────────────────────

def select_profile(profiles: dict) -> Optional[Profile]:
    """
    Display profile selection menu and return the chosen profile.

    Shows each profile with its name and description. The analyst
    selects by number. The selected profile is cloned so modifications
    on the toggle screen do not affect the source profile file.

    Args:
        profiles: Dict mapping slug to Profile instance.

    Returns:
        Cloned Profile instance, or None if user exits.
    """
    slugs = list(profiles.keys())

    table = Table(
        show_header=True,
        header_style="bold cyan",
        box=box.SIMPLE_HEAD,
        padding=(0, 1),
    )
    table.add_column("#",           style="cyan",  width=4)
    table.add_column("Profile",     style="white", width=20)
    table.add_column("Description", style="dim white")

    for i, slug in enumerate(slugs, 1):
        p = profiles[slug]
        table.add_row(str(i), p.name, p.description)

    console.print(Panel(table, title="[bold cyan]Select Investigation Profile[/bold cyan]",
                        border_style="cyan"))

    while True:
        try:
            choice = console.input(f"  [{C_CYAN}]Profile number (or Q to quit):[/{C_CYAN}] ").strip()
            if choice.upper() == "Q":
                return None
            idx = int(choice) - 1
            if 0 <= idx < len(slugs):
                selected = profiles[slugs[idx]].clone()
                console.print(f"\n  [{C_GOOD}][+] Profile selected: {selected.name}[/{C_GOOD}]\n")
                return selected
            console.print(f"  [{C_WARN}]Invalid selection — enter a number between 1 and {len(slugs)}[/{C_WARN}]")
        except ValueError:
            console.print(f"  [{C_WARN}]Enter a number[/{C_WARN}]")
        except KeyboardInterrupt:
            return None


# ── Toggle screen ─────────────────────────────────────────────────────────────

def toggle_screen(profile: Profile) -> Profile:
    """
    Display the toggle screen for reviewing and modifying profile settings.

    The toggle screen shows three panels:
      1. Collection sections — enable/disable major collection areas
      2. Tools — Sysinternals and Nirsoft tool toggles
      3. Memory — memory acquisition options

    The analyst can toggle any item before running. Changes are
    in-memory only — the profile file is never modified here.

    Args:
        profile: The cloned profile to modify.

    Returns:
        Modified profile (same object, modified in place).
    """
    while True:
        os.system("cls" if IS_WIN else "clear")
        console.print(Panel(
            f"[{C_TITLE}]Profile: {profile.name}[/{C_TITLE}]\n"
            f"[{C_DIM}]{profile.description}[/{C_DIM}]",
            border_style="cyan"
        ))

        # ── Sections table ────────────────────────────────────────────────────
        sec_table = Table(box=box.SIMPLE, padding=(0, 1), show_header=True,
                          header_style="bold cyan")
        sec_table.add_column("#",       width=4,  style="cyan")
        sec_table.add_column("Section", width=22)
        sec_table.add_column("Status",  width=10)

        section_keys = list(profile.sections.keys())
        for i, key in enumerate(section_keys, 1):
            enabled = profile.sections[key]
            status = Text("ENABLED",  style=C_GOOD) if enabled else Text("disabled", style=C_DIM)
            sec_table.add_row(str(i), key.replace("_", " ").title(), status)

        console.print(Panel(sec_table, title="[bold]Collection Sections[/bold]",
                            border_style="dim cyan"))

        # ── Tools table ───────────────────────────────────────────────────────
        tool_table = Table(box=box.SIMPLE, padding=(0, 1), show_header=True,
                           header_style="bold cyan")
        tool_table.add_column("#",      width=4,  style="cyan")
        tool_table.add_column("Tool",   width=18)
        tool_table.add_column("Type",   width=14, style="dim")
        tool_table.add_column("Status", width=10)

        tool_offset = len(section_keys)
        all_tools = (
            [(k, "Sysinternals") for k in profile.sysinternals.keys()] +
            [(k, "Nirsoft")      for k in profile.nirsoft.keys()]
        )
        for i, (key, tool_type) in enumerate(all_tools, tool_offset + 1):
            if tool_type == "Sysinternals":
                enabled = profile.sysinternals[key]
            else:
                enabled = profile.nirsoft[key]
            status = Text("ENABLED", style=C_GOOD) if enabled else Text("disabled", style=C_DIM)
            tool_table.add_row(str(i), key, tool_type, status)

        console.print(Panel(tool_table, title="[bold]Tools[/bold]",
                            border_style="dim cyan"))

        # ── Memory table ──────────────────────────────────────────────────────
        mem_table = Table(box=box.SIMPLE, padding=(0, 1), show_header=True,
                          header_style="bold cyan")
        mem_table.add_column("#",       width=4,  style="cyan")
        mem_table.add_column("Method",  width=18)
        mem_table.add_column("Status",  width=10)
        mem_table.add_column("Note",    style="dim")

        mem_offset = tool_offset + len(all_tools)
        mem_notes = {
            "winpmem":  "Recommended — open source",
            "dumpit":   "Magnet/Comae — widely accepted",
            "procdump": f"Targeted — PID: {profile.memory.get('procdump_pid', 'not set')}",
            "hiberfil": "[bold red]WILL HIBERNATE SYSTEM[/bold red]",
        }
        mem_keys = [k for k in profile.memory.keys() if k != "procdump_pid"]
        for i, key in enumerate(mem_keys, mem_offset + 1):
            enabled = profile.memory.get(key, False)
            status = Text("ENABLED", style=C_GOOD) if enabled else Text("disabled", style=C_DIM)
            mem_table.add_row(str(i), key, status, mem_notes.get(key, ""))

        console.print(Panel(mem_table, title="[bold]Memory Acquisition[/bold]",
                            border_style="dim red" if profile.any_memory_enabled() else "dim cyan"))

        # ── Commands ──────────────────────────────────────────────────────────
        console.print(
            f"  [{C_DIM}]Enter a number to toggle · [R] Run · [S] Save profile · [Q] Back[/{C_DIM}]\n"
        )

        try:
            choice = console.input(f"  [{C_CYAN}]>[/{C_CYAN}] ").strip().upper()
        except KeyboardInterrupt:
            break

        if choice == "R":
            break
        elif choice == "Q":
            break
        elif choice == "S":
            _save_custom_profile(profile)
        else:
            try:
                num = int(choice)
                _handle_toggle(num, profile, section_keys, all_tools, mem_keys, mem_offset, tool_offset)
            except ValueError:
                pass

    return profile


def _handle_toggle(num, profile, section_keys, all_tools, mem_keys, mem_offset, tool_offset):
    """Handle a numbered toggle selection."""
    # Section toggle
    if 1 <= num <= len(section_keys):
        key = section_keys[num - 1]
        profile.sections[key] = not profile.sections[key]
        return

    # Tool toggle
    tool_num = num - len(section_keys)
    if 1 <= tool_num <= len(all_tools):
        key, tool_type = all_tools[tool_num - 1]
        if tool_type == "Sysinternals":
            profile.sysinternals[key] = not profile.sysinternals[key]
        else:
            profile.nirsoft[key] = not profile.nirsoft[key]
        return

    # Memory toggle
    mem_num = num - tool_offset - len(all_tools)
    if 1 <= mem_num <= len(mem_keys):
        key = mem_keys[mem_num - 1]
        # Only one full memory tool at a time
        if key in ["winpmem", "dumpit", "hiberfil"]:
            current = profile.memory.get(key, False)
            # Disable all others first
            for k in ["winpmem", "dumpit", "hiberfil"]:
                profile.memory[k] = False
            profile.memory[key] = not current
        else:
            profile.memory[key] = not profile.memory.get(key, False)


def _save_custom_profile(profile: Profile):
    """Prompt for a name and save the current profile to the profiles folder."""
    profiles_dir = Path(__file__).parent.parent / "profiles"
    try:
        name = console.input("  Save as (slug, e.g. my_custom): ").strip()
        if name:
            path = profiles_dir / f"{name}.json"
            profile.name = name
            profile.save_as(path)
            console.print(f"  [{C_GOOD}][+] Saved: {path}[/{C_GOOD}]")
    except Exception as e:
        console.print(f"  [{C_BAD}][!] Save failed: {e}[/{C_BAD}]")


# ── Case setup ────────────────────────────────────────────────────────────────

def setup_case() -> tuple:
    """
    Prompt for case name and output directory.

    Returns:
        Tuple of (case_name: str, output_dir: Path)
    """
    console.print(Panel("[bold cyan]Case Setup[/bold cyan]", border_style="cyan"))

    case_name = console.input(f"  [{C_CYAN}]Case name:[/{C_CYAN}] ").strip().strip('"').strip("'")
    if not case_name:
        case_name = "Sombra_Case"

    default_output = str(Path.cwd())
    console.print(f" [{C_CYAN}]Output directory:[/{C_CYAN}] ", end="")
    console.print(f"[{default_output}]: ", markup=False)
    output_raw = input("  > ").strip().strip('"').strip("'")

    output_dir = Path(output_raw) if output_raw else Path(default_output)
    
    try:
        output_dir.mkdir(parents=True, exist_ok=True)
        # Verify writable
        test = output_dir / ".sombra_test"
        test.touch()
        test.unlink()
    except Exception as e:
        console.print(f"  [{C_WARN}]Output directory error: {e} — using current directory[/{C_WARN}]")
        output_dir = Path.cwd()

    console.print(f"  [{C_GOOD}][+] Case: {case_name}[/{C_GOOD}]")
    console.print(f"  [{C_GOOD}][+] Output: {output_dir}[/{C_GOOD}]")
    console.print()

    return case_name, output_dir
