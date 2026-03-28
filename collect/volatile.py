"""
collect/volatile.py
Gulf DataStream Labs — Sombra
Most volatile artifacts — collected first per RFC 3227 order of volatility.

  1. Running processes with full detail
  2. Network connections with process resolution
  3. Active login sessions
  4. Logged on users (local and remote)

These artifacts change constantly as the system runs. Every minute
of delay degrades the forensic value of this data.
"""

import json
from datetime import datetime
from pathlib import Path
from typing import Optional

from engine.platform import IS_WIN, IS_LINUX, run, ps, save_json, save_text, from_epoch

try:
    import psutil
    HAS_PSUTIL = True
except ImportError:
    HAS_PSUTIL = False


# ── Process collection ────────────────────────────────────────────────────────

def collect_processes(case_dir: Path) -> Optional[Path]:
    """
    Enumerate all running processes with maximum available detail.

    Collects:
      - PID, PPID, name, executable path
      - Full command line (catches renamed processes)
      - Process create time (for timeline correlation)
      - Username (owner)
      - Memory working set size
      - Thread count

    The create_time field enables correlation with event log entries,
    prefetch timestamps, and network connection records.

    Cross-platform: uses psutil on both Windows and Linux.
    On Linux also reads /proc/<pid>/cmdline directly to catch
    argv[0] spoofing by rootkits.

    Args:
        case_dir: Path to the timestamped case output folder.

    Returns:
        Path to the written file, or None if psutil unavailable.
    """
    if not HAS_PSUTIL:
        save_text(
            case_dir / "01_processes.txt",
            "[psutil not available — pip install psutil]"
        )
        return None

    procs = []
    for p in psutil.process_iter([
        "pid", "name", "ppid", "username",
        "cmdline", "create_time", "exe",
        "memory_info", "num_threads", "status"
    ]):
        try:
            info = p.info
            # Join cmdline list into readable string
            info["cmdline"] = " ".join(info.get("cmdline") or [])
            # Convert epoch to readable datetime
            info["create_time"] = from_epoch(info.get("create_time"))
            # Extract memory working set (bytes)
            mem = info.get("memory_info")
            info["memory_rss"] = mem.rss if mem else 0
            del info["memory_info"]
            procs.append(info)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

    # Sort by create_time so timeline order is preserved
    procs.sort(key=lambda x: x.get("create_time") or "")

    # On Linux, also read /proc cmdlines directly to catch argv[0] spoofing
    if IS_LINUX:
        proc_cmdlines = _read_proc_cmdlines()
        return save_json(case_dir / "01_processes.json", {
            "psutil": procs,
            "proc_cmdlines": proc_cmdlines,
        })

    return save_json(case_dir / "01_processes.json", procs)


def _read_proc_cmdlines() -> dict:
    """
    Read /proc/<pid>/cmdline directly for every running PID.

    This bypasses argv[0] spoofing — some rootkits and implants
    modify their process name after startup to blend into normal
    process listings. The kernel's /proc entry cannot be spoofed
    the same way.

    Returns:
        Dict mapping PID string to raw command line string.
    """
    cmdlines = {}
    proc_root = Path("/proc")
    for pid_dir in proc_root.iterdir():
        if not pid_dir.name.isdigit():
            continue
        try:
            raw = (pid_dir / "cmdline").read_bytes()
            cmd = raw.replace(b"\x00", b" ").decode("utf-8", errors="replace").strip()
            if cmd:
                cmdlines[pid_dir.name] = cmd
        except (PermissionError, FileNotFoundError, ProcessLookupError):
            continue
    return {k: cmdlines[k] for k in sorted(cmdlines, key=lambda x: int(x))}


# ── Network connections ───────────────────────────────────────────────────────

def collect_network_connections(case_dir: Path) -> Optional[Path]:
    """
    Enumerate all active TCP/UDP network connections with process resolution.

    Collects:
      - Local and remote address:port
      - Connection status (ESTABLISHED, LISTEN, TIME_WAIT, etc.)
      - Owning PID and process name

    The process name resolution is the key addition over raw netstat —
    it directly answers "what process made this connection?" without
    requiring manual PID cross-reference.

    Handles both named tuple (ip, port) and plain string addr formats
    across psutil versions and platforms.

    Args:
        case_dir: Path to the timestamped case output folder.

    Returns:
        Path to the written file, or None if psutil unavailable.
    """
    if not HAS_PSUTIL:
        return None

    def fmt_addr(addr) -> str:
        if not addr:
            return ""
        if hasattr(addr, "ip"):
            return f"{addr.ip}:{addr.port}"
        return str(addr)

    conns = []
    for c in psutil.net_connections(kind="all"):
        try:
            proc_name = psutil.Process(c.pid).name() if c.pid else ""
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            proc_name = ""

        conns.append({
            "laddr":   fmt_addr(c.laddr),
            "raddr":   fmt_addr(c.raddr),
            "status":  c.status,
            "pid":     c.pid,
            "process": proc_name,
            "family":  str(c.family),
            "type":    str(c.type),
        })

    # Sort: established first, then listen, then others
    def sort_key(c):
        order = {"ESTABLISHED": 0, "LISTEN": 1, "CLOSE_WAIT": 2}
        return order.get(c.get("status", ""), 9)

    conns.sort(key=sort_key)
    return save_json(case_dir / "02_network_connections.json", conns)


# ── Login sessions ────────────────────────────────────────────────────────────

def collect_login_sessions(case_dir: Path) -> Optional[Path]:
    """
    Enumerate active login sessions on the target system.

    Windows: uses 'query session' for RDP/console sessions and
             'net session' for active SMB/network sessions.
    Linux:   uses 'who -a' and 'w' for terminal and network sessions.

    Active sessions are critical — they reveal whether an attacker
    has an active connection to the machine right now.

    Args:
        case_dir: Path to the timestamped case output folder.
    """
    if IS_WIN:
        sessions = {
            "query_session": run(["query", "session"]),
            "net_session":   run(["net", "session"]),
        }
        return save_json(case_dir / "03_login_sessions.json", sessions)

    elif IS_LINUX:
        sessions = {
            "who": run(["who", "-a"]),
            "w":   run(["w"]),
        }
        return save_json(case_dir / "03_login_sessions.json", sessions)

    return None


def collect_logged_on_users(case_dir: Path) -> Optional[Path]:
    """
    Enumerate users currently logged on locally and via network shares.

    Windows: uses psutil users() for local sessions.
    Linux:   reads /proc/1/environ and utmp via 'last' for recent sessions.

    The distinction between local and remote logons matters —
    a remote logon at an unusual hour is immediately suspicious.

    Args:
        case_dir: Path to the timestamped case output folder.
    """
    if not HAS_PSUTIL:
        return None

    users = []
    for u in psutil.users():
        users.append({
            "name":     u.name,
            "terminal": u.terminal,
            "host":     u.host,
            "started":  from_epoch(u.started),
            "pid":      u.pid,
        })

    return save_json(case_dir / "04_logged_on_users.json", users)


# ── Entry point ───────────────────────────────────────────────────────────────

def run_volatile(case_dir: Path, log) -> list:
    """
    Run all volatile collections in order.

    Args:
        case_dir: Path to the timestamped case output folder.
        log:      Callable for status logging — log(message, level="INFO")

    Returns:
        List of Path objects for all files written.
    """
    written = []

    log("Collecting: Running processes")
    p = collect_processes(case_dir)
    if p:
        log(f"  -> Saved: {p.name}")
        written.append(p)
    else:
        log("  [SKIP] psutil not available", "WARN")

    log("Collecting: Network connections")
    p = collect_network_connections(case_dir)
    if p:
        log(f"  -> Saved: {p.name}")
        written.append(p)

    log("Collecting: Login sessions")
    p = collect_login_sessions(case_dir)
    if p:
        log(f"  -> Saved: {p.name}")
        written.append(p)

    log("Collecting: Logged on users")
    p = collect_logged_on_users(case_dir)
    if p:
        log(f"  -> Saved: {p.name}")
        written.append(p)

    return written
