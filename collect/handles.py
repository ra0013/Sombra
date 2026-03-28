"""
collect/handles.py
Gulf DataStream Labs — Sombra
Open handles, loaded DLLs, and named pipes.

  Open file handles  — files locked by processes (C2 staging, exfil)
  Loaded DLLs        — DLL injection detection per process
  Named pipes        — C2 communication channel indicator
  Environment vars   — PATH hijacking detection

These artifacts sit between volatile process state and persistent
storage. They reveal what processes are actively doing right now —
what files they have open, what code they have loaded, and what
inter-process communication channels exist.
"""

from pathlib import Path
from typing import Optional

from engine.platform import IS_WIN, IS_LINUX, run, ps, save_text, save_json


# ── Open handles ─────────────────────────────────────────────────────────────

def collect_handles(case_dir: Path, tools_dir: Path) -> Optional[Path]:
    """
    Enumerate open file handles per process using Sysinternals handle.exe.

    Reveals what files each process currently has open. Key indicators:
      - Handles to files in temp directories (staging)
      - Handles to network share paths (lateral movement)
      - Handles to sensitive files (credential theft)
      - Multiple processes holding handles to the same unusual file

    Requires handle.exe from Sysinternals in the tools directory.

    Args:
        case_dir:  Path to the case output folder.
        tools_dir: Path to the tools directory.
    """
    handle_exe = tools_dir / "handle.exe"
    if not handle_exe.exists():
        return save_text(
            case_dir / "14_handles.txt",
            "[handle.exe not found in tools directory]"
        )
    out = run([str(handle_exe), "-accepteula", "-a", "-u"], timeout=120)
    return save_text(case_dir / "14_handles.txt", out)


def collect_open_files_linux(case_dir: Path) -> Path:
    """
    Enumerate open files on Linux using lsof.

    lsof provides more detail than handle.exe in some respects —
    it shows network connections, device files, and pipes alongside
    regular files. Key indicators are the same: temp paths, network
    share mounts, and suspicious file types.

    Args:
        case_dir: Path to the case output folder.
    """
    out = run(["lsof", "-nP"], timeout=30)
    return save_text(case_dir / "14_open_files.txt", out)


# ── Loaded DLLs ───────────────────────────────────────────────────────────────

def collect_loaded_dlls(case_dir: Path, tools_dir: Path) -> Optional[Path]:
    """
    Enumerate loaded DLLs per process using Sysinternals listdlls.exe.

    DLL injection is a primary code execution technique — malware
    injects a malicious DLL into a legitimate process (svchost, explorer,
    lsass) to hide under a trusted process name. Key indicators:
      - DLLs loaded from non-standard paths
      - DLLs with random-looking names
      - Unsigned DLLs in processes that should only load signed code
      - Known malicious DLL names (mimilib.dll, etc.)

    Requires listdlls.exe from Sysinternals in the tools directory.

    Args:
        case_dir:  Path to the case output folder.
        tools_dir: Path to the tools directory.
    """
    listdlls = tools_dir / "listdlls.exe"
    if not listdlls.exists():
        return save_text(
            case_dir / "15_loaded_dlls.txt",
            "[listdlls.exe not found in tools directory]"
        )
    out = run([str(listdlls), "-accepteula", "-u"], timeout=120)
    return save_text(case_dir / "15_loaded_dlls.txt", out)


# ── Named pipes ───────────────────────────────────────────────────────────────

def collect_named_pipes(case_dir: Path, tools_dir: Path) -> Optional[Path]:
    """
    Enumerate active named pipes.

    Named pipes are a common C2 communication channel — Cobalt Strike,
    Metasploit, and other frameworks use named pipes for inter-process
    communication between implants and their loaders. Key indicators:
      - Pipes with random-looking names (e.g. \\pipe\\a1b2c3d4)
      - Known malicious pipe names (\\pipe\\msagent_*, \\pipe\\postex_*)
      - Unusual pipes in the context of running processes

    Uses both pipelist.exe (if available) and PowerShell as fallback.

    Args:
        case_dir:  Path to the case output folder.
        tools_dir: Path to the tools directory.
    """
    if IS_WIN:
        pipelist = tools_dir / "pipelist.exe"
        if pipelist.exists():
            out = run([str(pipelist), "-accepteula"], timeout=30)
        else:
            # PowerShell fallback
            out = ps(
                "[System.IO.Directory]::GetFiles('\\\\.\\pipe') "
                "| ForEach-Object { $_ }",
                timeout=30
            )
        return save_text(case_dir / "16_named_pipes.txt", out)

    if IS_LINUX:
        # On Linux find named pipes (FIFOs) in the filesystem
        pipes = []
        for search_dir in ["/tmp", "/var/tmp", "/run", "/proc"]:
            out = run(["find", search_dir, "-type", "p", "-ls"], timeout=10)
            if out and "[NOT FOUND]" not in out:
                pipes.append(f"--- {search_dir} ---\n{out}")
        return save_text(
            case_dir / "16_named_pipes.txt",
            "\n\n".join(pipes) if pipes else "(no named pipes found)"
        )

    return None


# ── Environment variables ─────────────────────────────────────────────────────

def collect_environment(case_dir: Path) -> Path:
    """
    Collect system and user environment variables.

    The PATH variable is a common attack target — if an attacker can
    write to a directory that appears in PATH before system directories,
    they can hijack execution of any command by placing a malicious
    binary with the same name. Also check for unusual environment
    variables that may be used as persistence triggers.

    Args:
        case_dir: Path to the case output folder.
    """
    import os
    env = dict(os.environ)
    return save_json(case_dir / "17_environment.json", env)


# ── Entry point ───────────────────────────────────────────────────────────────

def run_handles(case_dir: Path, tools_dir: Path, log) -> list:
    """
    Run all handle, DLL, and pipe collections.

    Args:
        case_dir:  Path to the timestamped case output folder.
        tools_dir: Path to the tools directory.
        log:       Callable for status logging.

    Returns:
        List of Path objects for all files written.
    """
    written = []

    if IS_WIN:
        for label, func, args in [
            ("Open file handles",   collect_handles,     [tools_dir]),
            ("Loaded DLLs",         collect_loaded_dlls, [tools_dir]),
            ("Named pipes",         collect_named_pipes, [tools_dir]),
            ("Environment variables", collect_environment, []),
        ]:
            log(f"Collecting: {label}")
            p = func(case_dir, *args)
            if p:
                log(f"  -> Saved: {p.name}")
                written.append(p)

    elif IS_LINUX:
        for label, func, args in [
            ("Open files (lsof)",   collect_open_files_linux, []),
            ("Named pipes",         collect_named_pipes, [tools_dir]),
            ("Environment variables", collect_environment, []),
        ]:
            log(f"Collecting: {label}")
            p = func(case_dir, *args) if args else func(case_dir)
            if p:
                log(f"  -> Saved: {p.name}")
                written.append(p)

    return written
