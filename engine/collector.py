"""
engine/collector.py
Gulf DataStream Labs — Sombra
Collection orchestrator — runs all enabled modules in order of volatility.

Order of volatility (RFC 3227):
  1.  Memory acquisition (if enabled) — most volatile, do first
  2.  Running processes + network connections
  3.  Login sessions + logged on users
  4.  Network state (ARP, DNS, routing)
  5.  Services and drivers
  6.  Open handles, DLLs, named pipes
  7.  Persistence mechanisms
  8.  Semi-volatile artifacts (event logs, prefetch)
  9.  Filesystem artifacts
  10. Software inventory
  11. Sysinternals tools
  12. Nirsoft tools
  13. Hash manifest + integrity check (always last)
"""

import socket
from datetime import datetime
from pathlib import Path
from typing import Callable

from engine.hasher import ToolHashRegistry, hash_output_files, write_manifest
from engine.platform import system_info, timestamp_folder, IS_WIN, IS_LINUX
from engine.profile import Profile

from collect.volatile    import run_volatile
from collect.network     import run_network
from collect.services    import run_services
from collect.handles     import run_handles
from collect.persistence import run_persistence
from collect.artifacts   import run_artifacts
from collect.filesystem  import run_filesystem
from collect.software    import run_software
from collect.sysinternals import run_sysinternals
from collect.nirsoft     import run_nirsoft
from collect.memory      import run_memory

from reports.timeline_parser import parse_all
from reports.timeline_html   import write_html_timeline
from reports.timeline_csv    import write_csv_timeline
from reports.timeline_plaso  import write_l2t_timeline

from rich.progress import Progress, BarColumn, TextColumn, TimeElapsedColumn, TaskProgressColumn
from rich.text import Text
from rich.console import Console

_console = Console()

class SombraCollector:
    """
    Orchestrates the full Sombra collection run.

    Usage:
        collector = SombraCollector(
            case_name="Case2025-001",
            output_dir=Path("D:/IR"),
            tools_dir=Path("./tools"),
            profile=profile,
            log=log_func,
        )
        result = collector.run()
    """

    def __init__(
        self,
        case_name:  str,
        output_dir: Path,
        tools_dir:  Path,
        profile:    Profile,
        log:        Callable,
    ):
        self.case_name  = case_name
        self.tools_dir  = tools_dir
        self.profile    = profile
        self.log        = log
        self.hostname   = socket.gethostname()

        # Build timestamped case folder
        self.case_dir = output_dir / f"{case_name}_{timestamp_folder()}"
        self.case_dir.mkdir(parents=True, exist_ok=True)

        # Initialize hash registry with this script
        self.registry = ToolHashRegistry(Path(__file__).parent.parent / "sombra.py")

        self.written = []
        self.start_time = None
        self.end_time   = None

    def _section(self, title: str):
        """Update progress section banner."""
        bar = "=" * 64
        self.log(f"\n{bar}")
        self.log(f"  {title}")
        self.log(bar)
        if hasattr(self, '_progress'):
            self._progress.update(self._task, description=f"  {title}", advance=1)

    def _add(self, paths):
        """Add written paths to the collection list."""
        if isinstance(paths, list):
            self.written.extend([p for p in paths if p])
        elif paths:
            self.written.append(paths)

    def run(self) -> dict:
        """
        Execute the full collection run in order of volatility.

        Returns:
            Dict with run summary including case_dir, file_count,
            integrity_pass, and elapsed_seconds.
        """
        self.start_time = datetime.now()
        
        self._progress = Progress(
            TextColumn("[bold cyan]{task.description}"),
            BarColumn(bar_width=40, style="blue", complete_style="green"),
            TaskProgressColumn(),
            TimeElapsedColumn(),
            console=_console,
            transient=True,
        )
        _section_count = sum([
            self.profile.any_memory_enabled(),
            self.profile.section_enabled("volatile"),
            self.profile.section_enabled("network"),
            self.profile.section_enabled("services"),
            self.profile.section_enabled("handles"),
            self.profile.section_enabled("persistence"),
            self.profile.section_enabled("artifacts"),
            self.profile.section_enabled("filesystem"),
            self.profile.section_enabled("software"),
            True, True, True, True,  # sysinternals, nirsoft, timeline, manifest
        ])
        self._task = self._progress.add_task("Starting...", total=_section_count)
        self._progress.start()


         
        self.log(f"\nSombra — Collection Started")
        self.log(f"Case     : {self.case_name}")
        self.log(f"Host     : {self.hostname}")
        self.log(f"Profile  : {self.profile.name}")
        self.log(f"Platform : {'Windows' if IS_WIN else 'Linux'}")
        self.log(f"Output   : {self.case_dir}")
        self.log(f"Elevated : {system_info()['elevated']}")

        # ── 1. Memory (most volatile — acquire first if enabled) ──────────────
        if self.profile.any_memory_enabled():
            self._section("MEMORY ACQUISITION")
            self._add(run_memory(
                self.case_dir, self.tools_dir, self.registry, self.profile, self.log
            ))

        # ── 2. Volatile — processes, connections, sessions ────────────────────
        if self.profile.section_enabled("volatile"):
            self._section("VOLATILE ARTIFACTS")
            self._add(run_volatile(self.case_dir, self.log))

        # ── 3. Network state ──────────────────────────────────────────────────
        if self.profile.section_enabled("network"):
            self._section("NETWORK STATE")
            self._add(run_network(self.case_dir, self.log))

        # ── 4. Services and drivers ───────────────────────────────────────────
        if self.profile.section_enabled("services"):
            self._section("SERVICES AND DRIVERS")
            self._add(run_services(self.case_dir, self.log))

        # ── 5. Handles, DLLs, named pipes ─────────────────────────────────────
        if self.profile.section_enabled("handles"):
            self._section("HANDLES, DLLS, NAMED PIPES")
            self._add(run_handles(self.case_dir, self.tools_dir, self.log))

        # ── 6. Persistence mechanisms ─────────────────────────────────────────
        if self.profile.section_enabled("persistence"):
            self._section("PERSISTENCE MECHANISMS")
            self._add(run_persistence(self.case_dir, self.log))

        # ── 7. Artifacts — event logs, prefetch, accounts ─────────────────────
        if self.profile.section_enabled("artifacts"):
            self._section("ARTIFACTS")
            self._add(run_artifacts(self.case_dir, self.log))

        # ── 9. Filesystem artifacts ───────────────────────────────────────────
        if self.profile.section_enabled("filesystem"):
            self._section("FILESYSTEM ARTIFACTS")
            self._add(run_filesystem(self.case_dir, self.tools_dir, self.log))

        # ── 10. Software inventory ────────────────────────────────────────────
        if self.profile.section_enabled("software"):
            self._section("SOFTWARE INVENTORY")
            self._add(run_software(self.case_dir, self.log))

        # ── 11. Sysinternals ──────────────────────────────────────────────────
        self._section("SYSINTERNALS")
        self._add(run_sysinternals(
            self.case_dir, self.tools_dir, self.registry, self.profile, self.log
        ))

        # ── 12. Nirsoft ───────────────────────────────────────────────────────
        self._section("NIRSOFT")
        self._add(run_nirsoft(
            self.case_dir, self.tools_dir, self.registry, self.profile, self.log
        ))

        # ── 13. Timeline reports (before manifest so they get hashed) ────────
        self._section("TIMELINE REPORTS")
        self._generate_timelines()

        # ── 14. Hash manifest + integrity check (always last) ─────────────────
        self._section("HASH MANIFEST + INTEGRITY CHECK")
        integrity_pass = self._write_manifest()

        self.end_time = datetime.now()
        elapsed = (self.end_time - self.start_time).seconds

        self._section("COLLECTION COMPLETE")
        self.log(f"Output   : {self.case_dir}")
        self.log(f"Files    : {sum(1 for _ in self.case_dir.iterdir())}")
        self.log(f"Elapsed  : {elapsed}s")
        self.log(f"Integrity: {'PASS' if integrity_pass else 'FAIL — review manifest'}")
        self._progress.update(self._task, description="  Complete")
        self._progress.stop()
        return {
            "case_dir":       self.case_dir,
            "file_count":     sum(1 for _ in self.case_dir.iterdir()),
            "integrity_pass": integrity_pass,
            "elapsed_seconds": elapsed,
            "profile":        self.profile.name,
        }

    def _generate_timelines(self):
        """Parse collected artifacts and write all three timeline formats."""
        try:
            self.log("Parsing artifact sources...")
            events = parse_all(self.case_dir, self.profile, self.hostname)
            self.log(f"  Total events: {len(events):,} ({sum(1 for e in events if e.get('flagged'))} flagged)")

            write_html_timeline(
                self.case_dir, self.case_name, self.hostname,
                self.profile.name, events, self.log
            )
            write_csv_timeline(
                self.case_dir, self.case_name, self.hostname,
                self.profile.name, events, self.log
            )
            write_l2t_timeline(
                self.case_dir, self.case_name, self.hostname,
                self.profile.name, events, self.log
            )
        except Exception as e:
            self.log(f"  [WARN] Timeline generation failed: {e}", "WARN")

    def _write_manifest(self) -> bool:
        """Write the hash manifest and return overall integrity status."""
        manifest_path = self.case_dir / "Hash_Manifest.txt"
        verify_results = self.registry.verify_all()
        output_hashes = hash_output_files(self.case_dir)
        try:
            all_pass = write_manifest(
                manifest_path  = manifest_path,
                case_name      = self.case_name,
                hostname       = self.hostname,
                profile_name   = self.profile.name,
                registry       = self.registry,
                output_hashes  = output_hashes,
                verify_results = verify_results,
            )
        except OSError as e:
            self.log(f"  [WARN] Could not write manifest: {e}", "WARN")
            return False
        status = "PASS — all items verified unchanged" if all_pass else "FAIL — review mismatches"
        self.log(f"Integrity: {status}")
        self.log(f"  -> Saved: Hash_Manifest.txt")
        return all_pass
