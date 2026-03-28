"""
collect/sysinternals.py
Gulf DataStream Labs — Sombra
Sysinternals tool wrappers — Windows only.

All tools must be present in the tools/ directory and are hashed
before execution as part of the trusted toolset methodology.

Supported tools:
  autorunsc.exe  — persistence enumeration (all categories, CSV + hash)
  pslist.exe     — process tree with memory and thread detail
  sigcheck.exe   — binary signature verification
  handle.exe     — open file handles per process (see handles.py)
  tcpvcon.exe    — network connections with process detail
  listdlls.exe   — loaded DLLs per process (see handles.py)
  streams.exe    — Alternate Data Streams enumeration
  pipelist.exe   — named pipe enumeration (see handles.py)
  logonsessions.exe — active logon sessions with detail
  psloggedon.exe — users logged on locally and via network shares
  psinfo.exe     — detailed system information
  procdump.exe   — process memory dump (targeted)
"""

import time
from pathlib import Path
from typing import Optional

from engine.platform import IS_WIN, run, save_text
from engine.hasher import ToolHashRegistry
from engine.tools import ToolConfig


def _run_tool(
    tool_path: Path,
    args: list,
    registry: ToolHashRegistry,
    timeout: int = 120
) -> Optional[str]:
    """
    Hash a tool, run it, and return output.
    Returns None if the tool is not found.

    Args:
        tool_path: Path to the tool executable.
        args:      Additional arguments to pass.
        registry:  ToolHashRegistry to record the pre-run hash.
        timeout:   Maximum seconds to wait.
    """
    if not tool_path.exists():
        return None
    registry.register_tool(tool_path)
    return run([str(tool_path)] + args, timeout=timeout)


# ── Tool wrappers ─────────────────────────────────────────────────────────────

def run_autorunsc(case_dir: Path, tools_dir: Path, registry: ToolHashRegistry) -> Optional[Path]:
    tc   = ToolConfig(tools_dir)
    path = tc.get("sysinternals", "autorunsc")
    out  = _run_tool(path, ["-accepteula", "-a", "*", "-c", "-h", "-nobanner"], registry, timeout=180) if path else None
    return save_text(case_dir / "40_autorunsc.csv", out) if out else None


def run_pslist(case_dir: Path, tools_dir: Path, registry: ToolHashRegistry) -> Optional[Path]:
    tc   = ToolConfig(tools_dir)
    path = tc.get("sysinternals", "pslist")
    out  = _run_tool(path, ["-accepteula", "-t"], registry, timeout=30) if path else None
    return save_text(case_dir / "41_pslist.txt", out) if out else None


def run_sigcheck(case_dir: Path, tools_dir: Path, registry: ToolHashRegistry) -> Optional[Path]:
    tc   = ToolConfig(tools_dir)
    path = tc.get("sysinternals", "sigcheck")
    out  = _run_tool(path, ["-accepteula", "-u", "-e", "C:\\Windows\\System32"], registry, timeout=300) if path else None
    return save_text(case_dir / "42_sigcheck.txt", out) if out else None


def run_tcpvcon(case_dir: Path, tools_dir: Path, registry: ToolHashRegistry) -> Optional[Path]:
    tc   = ToolConfig(tools_dir)
    path = tc.get("sysinternals", "tcpvcon")
    out  = _run_tool(path, ["-accepteula", "-a"], registry, timeout=30) if path else None
    return save_text(case_dir / "43_tcpvcon.txt", out) if out else None


def run_streams(case_dir: Path, tools_dir: Path, registry: ToolHashRegistry) -> Optional[Path]:
    tc   = ToolConfig(tools_dir)
    path = tc.get("sysinternals", "streams")
    out  = _run_tool(path, ["-accepteula", "-s", "C:\\"], registry, timeout=300) if path else None
    return save_text(case_dir / "44_streams.txt", out) if out else None


def run_logonsessions(case_dir: Path, tools_dir: Path, registry: ToolHashRegistry) -> Optional[Path]:
    tc   = ToolConfig(tools_dir)
    path = tc.get("sysinternals", "logonsessions")
    out  = _run_tool(path, ["-accepteula", "-p"], registry, timeout=30) if path else None
    return save_text(case_dir / "45_logonsessions.txt", out) if out else None


def run_psloggedon(case_dir: Path, tools_dir: Path, registry: ToolHashRegistry) -> Optional[Path]:
    tc   = ToolConfig(tools_dir)
    path = tc.get("sysinternals", "psloggedon")
    out  = _run_tool(path, ["-accepteula"], registry, timeout=30) if path else None
    return save_text(case_dir / "46_psloggedon.txt", out) if out else None


def run_psinfo(case_dir: Path, tools_dir: Path, registry: ToolHashRegistry) -> Optional[Path]:
    tc   = ToolConfig(tools_dir)
    path = tc.get("sysinternals", "psinfo")
    out  = _run_tool(path, ["-accepteula", "-s", "-h", "-d"], registry, timeout=30) if path else None
    return save_text(case_dir / "47_psinfo.txt", out) if out else None


def run_procdump(case_dir: Path, tools_dir: Path, registry: ToolHashRegistry, pid: Optional[int] = None) -> Optional[Path]:
    if pid is None:
        return None
    tc   = ToolConfig(tools_dir)
    path = tc.get("sysinternals", "procdump")
    if not path:
        return None
    out = _run_tool(
        path,
        ["-accepteula", "-ma", str(pid), str(case_dir / f"procdump_{pid}.dmp")],
        registry, timeout=300
    )
    dump_path = case_dir / f"procdump_{pid}.dmp"
    return dump_path if dump_path.exists() else None


# ── Entry point ───────────────────────────────────────────────────────────────

# Map tool slug to wrapper function
TOOL_MAP = {
    "autorunsc":     run_autorunsc,
    "pslist":        run_pslist,
    "sigcheck":      run_sigcheck,
    "tcpvcon":       run_tcpvcon,
    "streams":       run_streams,
    "logonsessions": run_logonsessions,
    "psloggedon":    run_psloggedon,
    "psinfo":        run_psinfo,
}


def run_sysinternals(
    case_dir: Path,
    tools_dir: Path,
    registry: ToolHashRegistry,
    profile,
    log
) -> list:
    """
    Run all enabled Sysinternals tools based on the active profile.

    Args:
        case_dir:  Path to the timestamped case output folder.
        tools_dir: Path to the tools directory.
        registry:  ToolHashRegistry for pre-run hashing.
        profile:   Active Profile instance (controls which tools run).
        log:       Callable for status logging.

    Returns:
        List of Path objects for all files written.
    """
    if not IS_WIN:
        log("  [SKIP] Sysinternals — Windows only", "INFO")
        return []

    written   = []
    tc        = ToolConfig(tools_dir)

    for slug, func in TOOL_MAP.items():
        if not profile.tool_enabled(slug):
            log(f"  [SKIP] {slug} (disabled by profile)")
            continue

        tool_path = tc.get("sysinternals", slug)
        if not tool_path:
            log(f"  [WARN] {slug} not found — check tools/tools.json", "WARN")
            continue

        log(f"Collecting: {slug} ({tool_path.name})")
        p = func(case_dir, tools_dir, registry)
        if p:
            log(f"  -> Saved: {p.name}")
            written.append(p)
        else:
            log(f"  [WARN] {slug} produced no output", "WARN")

    # procdump targeted dump
    if profile.tool_enabled("procdump"):
        pid = profile.memory.get("procdump_pid")
        if pid:
            log(f"Collecting: procdump (PID {pid})")
            p = run_procdump(case_dir, tools_dir, registry, pid)
            if p:
                log(f"  -> Saved: {p.name}")
                written.append(p)

    return written
