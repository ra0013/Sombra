#!/usr/bin/env python3
"""
==============================================================================
  Sombra — Digital Forensics Collection Engine
  Gulf DataStream Labs

  Sombra works in the shade — the artifacts the OS keeps hidden from
  the average user. Registry persistence keys, BAM/DAM execution
  timestamps, WMI subscriptions, prefetch evidence, named pipes,
  USB history. The things that are there whether the user knows it
  or not. That's where the analyst works.

  USAGE:
    python sombra.py
    python sombra.py --case "Case2025-001" --output "D:\\IR" --profile ransomware

  DEPENDENCIES:
    rich    — pip install rich
    psutil  — pip install psutil

  TOOLS (place in tools/ directory):
    Sysinternals: autorunsc.exe, pslist.exe, sigcheck.exe, handle.exe,
                  tcpvcon.exe, listdlls.exe, streams.exe, pipelist.exe,
                  logonsessions.exe, PsLoggedon.exe, psinfo.exe, procdump.exe
    Nirsoft:      LastActivityView.exe, BrowsingHistoryView.exe
    Memory:       winpmem.exe, DumpIt.exe

  VERSION: 1.0.0
==============================================================================
"""

import argparse
import sys
from datetime import datetime
from pathlib import Path

# ── Dependency check ──────────────────────────────────────────────────────────
try:
    from rich.console import Console
    from rich.panel import Panel
except ImportError:
    print("[ERROR] 'rich' is required: pip install rich")
    sys.exit(1)

try:
    import psutil  # noqa: F401
except ImportError:
    print("[WARN] 'psutil' not installed — process/network collections will be skipped")
    print("       pip install psutil")

# ── Sombra imports ────────────────────────────────────────────────────────────
sys.path.insert(0, str(Path(__file__).parent))

from engine.platform import IS_WIN, is_elevated, now_str
from engine.profile  import load_all_profiles, get_profile
from engine.collector import SombraCollector, _console as _coll_console

from menu.ui import (
    console, print_banner, select_profile,
    toggle_screen, setup_case,
    C_GOOD, C_WARN, C_BAD, C_CYAN, C_DIM
)
from menu.settings import show_settings


# ── Logger ────────────────────────────────────────────────────────────────────

def make_logger():
    """Return a log function that writes to console with rich styling."""
    def log(msg: str, level: str = "INFO"):
        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        if level == "WARN":
            _coll_console.print(f"[{C_WARN}][{ts}] [WARN] {msg}[/{C_WARN}]")
        elif level == "ERROR":
            _coll_console.print(f"[{C_BAD}][{ts}] [ERROR] {msg}[/{C_BAD}]")
        else:
            _coll_console.print(f"[dim]{ts}[/dim] [{C_CYAN}]INFO[/{C_CYAN}]  {msg}")
    return log


# ── CLI mode ──────────────────────────────────────────────────────────────────

def run_cli(args) -> int:
    """
    Run Sombra in non-interactive CLI mode.

    Used when case name, output, and profile are all specified on the
    command line — no menu interaction required. Useful for automated
    deployment or scripted IR workflows.

    Returns:
        0 on success, 1 on failure.
    """
    log = make_logger()

    profile = get_profile(args.profile)
    if not profile:
        console.print(f"[{C_BAD}][ERROR] Profile not found: {args.profile}[/{C_BAD}]")
        return 1

    if getattr(sys, 'frozen', False):
        tools_dir = Path(sys.executable).parent / "tools"
    else:
        tools_dir = Path(__file__).parent / "tools"

    collector = SombraCollector(
        case_name  = args.case,
        output_dir = Path(args.output),
        tools_dir  = tools_dir,
        profile    = profile,
        log        = log,
    )

    result = collector.run()
    return 0 if result["integrity_pass"] else 1


def _check_tools(tools_dir: Path):
    """Display tool presence check — FOUND in green, MISSING in red."""
    from engine.tools import ToolConfig
    tc     = ToolConfig(tools_dir)
    status = tc.check_tools()
    found  = sum(1 for v in status.values() if v["found"])
    total  = len(status)

    console.print()
    console.print(Panel(
        f"[{C_CYAN}]Tools directory:[/{C_CYAN}] {tools_dir}\n"
        f"[{C_GOOD}]{found}[/{C_GOOD}] found / [{C_BAD}]{total - found}[/{C_BAD}] missing",
        title="[bold cyan]Tool Check[/bold cyan]",
        border_style="cyan"
    ))

    for key, info in status.items():
        category, slug = key.split("/", 1)
        if info["found"]:
            console.print(f"  [{C_GOOD}][FOUND  ][/{C_GOOD}] {slug:<18} {info['filename']}")
        else:
            console.print(f"  [{C_BAD}][MISSING][/{C_BAD}] {slug:<18} {info['filename']}")

    console.print()
    try:
        input("  Press Enter to continue...")
    except KeyboardInterrupt:
        pass


# ── Interactive mode ──────────────────────────────────────────────────────────

def run_interactive() -> int:
    """
    Run Sombra in interactive menu mode.

    Main menu:
      [1] Set case name + output directory
      [2] Check tools — verify staged executables
      [3] Run triage
      [4] Settings — configure tool filenames
      [Q] Quit

    Returns:
        0 on success or clean exit, 1 on failure.
    """
    log       = make_logger()
    if getattr(sys, 'frozen', False):
        tools_dir = Path(sys.executable).parent / "tools"
    else:
        tools_dir = Path(__file__).parent / "tools"
    tools_dir.mkdir(exist_ok=True)

    profiles = load_all_profiles()
    if not profiles:
        console.print(f"[{C_BAD}][ERROR] No profiles found in profiles/ directory[/{C_BAD}]")
        return 1

    # Session state — persists across menu loops
    case_name  = ""
    output_dir = Path.cwd()

    # Elevation check once at startup
    print_banner()
    if not is_elevated():
        console.print(
            f"[{C_WARN}]  [!] Not running as Administrator / root.[/{C_WARN}]\n"
            f"[{C_DIM}]      Some collections will be incomplete.[/{C_DIM}]\n"
            f"[{C_DIM}]      Restart with elevated privileges for full coverage.[/{C_DIM}]\n"
        )
        try:
            if input("  Continue anyway? [y/N]: ").strip().lower() != "y":
                return 0
        except KeyboardInterrupt:
            return 0

    # ── Main menu loop ────────────────────────────────────────────────────────
    while True:
        print_banner(case_name, str(output_dir))

        # Show case state
        if case_name:
            console.print(f"  [{C_CYAN}][1][/{C_CYAN}]  Case setup       [{C_GOOD}]{case_name}[/{C_GOOD}]")
        else:
            console.print(f"  [{C_CYAN}][1][/{C_CYAN}]  Case setup       [{C_WARN}](not set)[/{C_WARN}]")

        console.print(f"  [{C_CYAN}][2][/{C_CYAN}]  Check tools")
        console.print(f"  [{C_CYAN}][3][/{C_CYAN}]  Run triage")
        console.print(f"  [{C_CYAN}][4][/{C_CYAN}]  Settings — configure tools")
        console.print(f"  [{C_DIM}][Q][/{C_DIM}]  Quit")
        console.print()

        try:
            choice = console.input(f"  [{C_CYAN}]>[/{C_CYAN}] ").strip().upper()
        except KeyboardInterrupt:
            return 0

        if choice == "Q":
            return 0

        elif choice == "1":
            case_name, output_dir = setup_case()

        elif choice == "2":
            _check_tools(tools_dir)

        elif choice == "4":
            show_settings(tools_dir)

        elif choice == "3":
            # Require case name before running
            if not case_name:
                console.print(f"\n  [{C_WARN}][!] Set a case name first (option 1)[/{C_WARN}]\n")
                try:
                    input("  Press Enter to continue...")
                except KeyboardInterrupt:
                    pass
                continue

            # Profile selection
            profile = select_profile(profiles)
            if not profile:
                continue

            # Toggle screen
            print_banner(case_name, str(output_dir), profile.name)
            console.print(
                f"  [{C_DIM}]Review and toggle collection settings before running.[/{C_DIM}]\n"
            )
            profile = toggle_screen(profile)

            # Confirmation
            print_banner(case_name, str(output_dir), profile.name)
            console.print(Panel(
                f"[{C_WARN}]Ready to run collection.[/{C_WARN}]\n\n"
                f"Case    : {case_name}\n"
                f"Output  : {output_dir}\n"
                f"Profile : {profile.name}\n"
                f"Memory  : {'ENABLED' if profile.any_memory_enabled() else 'disabled'}\n",
                title="[bold]Confirm[/bold]",
                border_style="yellow"
            ))

            try:
                confirm = input("  Run now? [y/N]: ").strip().lower()
            except KeyboardInterrupt:
                continue

            if confirm != "y":
                console.print(f"\n  [{C_DIM}]Cancelled — returning to menu.[/{C_DIM}]\n")
                continue

            # Run collection
            collector = SombraCollector(
                case_name  = case_name,
                output_dir = output_dir,
                tools_dir  = tools_dir,
                profile    = profile,
                log        = log,
            )
            result = collector.run()

            # Summary
            status_style = C_GOOD if result["integrity_pass"] else C_BAD
            console.print(Panel(
                f"[{C_GOOD}]Collection complete.[/{C_GOOD}]\n\n"
                f"Output   : {result['case_dir']}\n"
                f"Files    : {result['file_count']}\n"
                f"Elapsed  : {result['elapsed_seconds']}s\n"
                f"Integrity: [{status_style}]"
                f"{'PASS' if result['integrity_pass'] else 'FAIL'}"
                f"[/{status_style}]",
                title="[bold green]Done[/bold green]",
                border_style="green"
            ))

            try:
                input("\n  Press Enter to return to menu...")
            except KeyboardInterrupt:
                pass

    return 0


# ── Entry point ───────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Sombra — Digital Forensics Collection Engine",
        epilog="Run without arguments for interactive mode."
    )
    parser.add_argument("--case",    help="Case name (enables CLI mode)")
    parser.add_argument("--output",  help="Output directory", default=str(Path.cwd()))
    parser.add_argument("--profile", help="Profile slug (default, ransomware, etc.)",
                        default="default")
    args = parser.parse_args()

    # CLI mode if case name provided, interactive otherwise
    if args.case:
        sys.exit(run_cli(args))
    else:
        sys.exit(run_interactive())


if __name__ == "__main__":
    main()
