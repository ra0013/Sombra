"""
collect/nirsoft.py
Gulf DataStream Labs — Sombra
Nirsoft tool wrappers — Windows only.

All tools must be present in the tools/ directory and are hashed
before execution as part of the trusted toolset methodology.

Supported tools:
  LastActivityView.exe  — user activity timeline aggregation
  BrowsingHistoryView.exe — browser history (Chrome, Firefox, Edge, IE)

All Nirsoft tools use /scomma for silent CSV export without GUI.
Sleep delays are used after execution since Nirsoft tools write
output asynchronously.
"""

import time
from pathlib import Path
from typing import Optional

from engine.platform import IS_WIN, run, save_text
from engine.hasher import ToolHashRegistry
from engine.tools import ToolConfig


def _run_nirsoft(
    tool_path: Path,
    args: list,
    output_path: Path,
    registry: ToolHashRegistry,
    timeout: int = 30,
    wait: int = 8
) -> Optional[Path]:
    """
    Hash and run a Nirsoft tool, waiting for async output.

    Nirsoft tools write output asynchronously — the process exits
    before the file is fully written. A sleep delay is required.

    Args:
        tool_path:   Path to the tool executable.
        args:        Additional arguments.
        output_path: Expected output file path.
        registry:    ToolHashRegistry for pre-run hashing.
        timeout:     Max seconds for subprocess.
        wait:        Seconds to wait for async file write.

    Returns:
        Path to output file if it exists, None otherwise.
    """
    if not tool_path.exists():
        return None

    registry.register_tool(tool_path)
    run([str(tool_path)] + args, timeout=timeout)
    time.sleep(wait)

    return output_path if output_path.exists() else None


# ── Tool wrappers ─────────────────────────────────────────────────────────────

def run_lastactivityview(case_dir: Path, tools_dir: Path, registry: ToolHashRegistry) -> Optional[Path]:
    tc   = ToolConfig(tools_dir)
    path = tc.get("nirsoft", "lastactivityview")
    output_path = case_dir / "50_lastactivityview.csv"
    return _run_nirsoft(path, ["/scomma", str(output_path)], output_path, registry) if path else None


def run_browsing_history(case_dir: Path, tools_dir: Path, registry: ToolHashRegistry) -> Optional[Path]:
    tc   = ToolConfig(tools_dir)
    path = tc.get("nirsoft", "browsinghistory")
    output_path = case_dir / "51_browsing_history.csv"
    return _run_nirsoft(path, ["/scomma", str(output_path)], output_path, registry, timeout=60, wait=10) if path else None


# ── Entry point ───────────────────────────────────────────────────────────────

TOOL_MAP = {
    "lastactivityview": run_lastactivityview,
    "browsinghistory":  run_browsing_history,
}


def run_nirsoft(
    case_dir: Path,
    tools_dir: Path,
    registry: ToolHashRegistry,
    profile,
    log
) -> list:
    """
    Run all enabled Nirsoft tools based on the active profile.

    Args:
        case_dir:  Path to the timestamped case output folder.
        tools_dir: Path to the tools directory.
        registry:  ToolHashRegistry for pre-run hashing.
        profile:   Active Profile instance.
        log:       Callable for status logging.

    Returns:
        List of Path objects for all files written.
    """
    if not IS_WIN:
        log("  [SKIP] Nirsoft tools — Windows only", "INFO")
        return []

    written = []
    tc = ToolConfig(tools_dir)

    for slug, func in TOOL_MAP.items():
        if not profile.nirsoft_enabled(slug):
            log(f"  [SKIP] {slug} (disabled by profile)")
            continue

        tool_path = tc.get("nirsoft", slug)
        if not tool_path:
            log(f"  [WARN] {slug} not found — check tools/tools.json", "WARN")
            continue

        log(f"Collecting: {slug} ({tool_path.name})")
        p = func(case_dir, tools_dir, registry)
        if p:
            log(f"  -> Saved: {p.name}")
            written.append(p)
        else:
            log(f"  [WARN] {slug} not found or produced no output", "WARN")

    return written
