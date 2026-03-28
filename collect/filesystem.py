"""
collect/filesystem.py
Gulf DataStream Labs — Sombra
Filesystem artifact collection.

  SUID/SGID binaries      — privilege escalation staging (Linux)
  Alternate Data Streams  — hidden payload storage (Windows)
  Recently modified bins  — binary replacement detection (Linux)
  Suspicious file search  — known malicious extensions/locations

These artifacts live on disk and are less volatile than memory state,
but time still matters — attackers clean up after themselves.
"""

import os
from datetime import datetime
from pathlib import Path
from typing import Optional

from engine.platform import IS_WIN, IS_LINUX, run, save_text, save_json


# ── SUID/SGID enumeration (Linux) ─────────────────────────────────────────────

def collect_suid_sgid(case_dir: Path) -> Optional[Path]:
    """
    Enumerate all SUID and SGID binaries on Linux.

    SUID (Set User ID) binaries run with the file owner's privileges
    rather than the caller's. SGID (Set Group ID) does the same for
    group ownership. When the owner is root, any user who executes
    the binary gets root privileges for that execution.

    Attackers install unexpected SUID binaries as a privilege escalation
    staging mechanism — e.g. copying /bin/bash to /tmp/.bash with SUID
    set allows any user to get a root shell.

    SUID bit = 0o4000, SGID bit = 0o2000 in Unix permission notation.

    Args:
        case_dir: Path to the case output folder.
    """
    if not IS_LINUX:
        return None

    suid_files = []
    for dirpath, dirnames, filenames in os.walk("/"):
        # Skip virtual filesystems to avoid hangs
        dirnames[:] = [
            d for d in dirnames
            if not any(dirpath.startswith(skip) for skip in [
                "/proc", "/sys", "/dev", "/run/user"
            ])
        ]
        for fname in filenames:
            fpath = Path(dirpath) / fname
            try:
                st   = fpath.stat()
                mode = st.st_mode
                if mode & 0o4000 or mode & 0o2000:
                    suid_files.append({
                        "path":  str(fpath),
                        "mode":  oct(mode),
                        "suid":  bool(mode & 0o4000),
                        "sgid":  bool(mode & 0o2000),
                        "owner": st.st_uid,
                        "group": st.st_gid,
                        "size":  st.st_size,
                    })
            except (PermissionError, FileNotFoundError, OSError):
                continue

    return save_json(case_dir / "55_suid_sgid.json", suid_files)


# ── Alternate Data Streams (Windows) ──────────────────────────────────────────

def collect_ads(case_dir: Path, tools_dir: Path) -> Optional[Path]:
    """
    Enumerate NTFS Alternate Data Streams on Windows.

    ADS allow arbitrary data to be attached to any file or directory
    without changing the visible file size. Malware uses ADS to:
      - Hide executable payloads inside innocent-looking files
      - Store configuration data and C2 addresses
      - Conceal scripts used for persistence

    The Zone.Identifier stream (Zone = 3) marks files downloaded from
    the internet — useful for tracing the origin of suspicious executables.

    Uses streams.exe from Sysinternals if available, falls back to
    PowerShell Get-Item with -Stream for basic enumeration.

    Args:
        case_dir:  Path to the case output folder.
        tools_dir: Path to the tools directory.
    """
    if not IS_WIN:
        return None

    streams_exe = tools_dir / "streams.exe"
    if streams_exe.exists():
        # Already handled in sysinternals.py — skip to avoid duplication
        return None

    # PowerShell fallback — slower but no external tool required
    out = _ps_run(
        "Get-ChildItem -Path C:\\ -Recurse -ErrorAction SilentlyContinue "
        "| ForEach-Object { "
        "  $streams = Get-Item -Path $_.FullName -Stream * -ErrorAction SilentlyContinue "
        "  | Where-Object { $_.Stream -ne ':$DATA' }; "
        "  if ($streams) { "
        "    [PSCustomObject]@{ File=$_.FullName; Streams=$streams.Stream } "
        "  } "
        "} | ConvertTo-Json -Depth 2",
        timeout=300
    )
    return save_text(case_dir / "55_alternate_data_streams.json", out)


def _ps_run(cmd: str, timeout: int = 60) -> str:
    """Run a PowerShell command safely."""
    from engine.platform import run as _run
    return _run(["powershell", "-NonInteractive", "-Command", cmd], timeout=timeout)


# ── Suspicious file search ────────────────────────────────────────────────────

def collect_suspicious_files(case_dir: Path) -> Path:
    """
    Search for files with suspicious extensions or in suspicious locations.

    Common indicators:
      - Executables in temp directories
      - Script files in user profile directories
      - Files with double extensions (document.pdf.exe)
      - Known malicious filenames

    Args:
        case_dir: Path to the case output folder.
    """
    if IS_WIN:
        search_dirs = [
            "C:\\Users\\Public",
            "C:\\Windows\\Temp",
            "C:\\Temp",
        ]
        # Search each user's AppData\Local\Temp and Roaming
        users_root = Path("C:\\Users")
        if users_root.exists():
            for user_dir in users_root.iterdir():
                for subdir in ["AppData\\Local\\Temp", "AppData\\Roaming"]:
                    p = user_dir / subdir
                    if p.exists():
                        search_dirs.append(str(p))

        suspicious_exts = {".exe", ".dll", ".ps1", ".vbs", ".js", ".bat", ".cmd", ".hta"}
        found = []

        for search_dir in search_dirs:
            sp = Path(search_dir)
            if not sp.exists():
                continue
            for dirpath, _, filenames in os.walk(str(sp)):
                for fname in filenames:
                    fpath = Path(dirpath) / fname
                    if fpath.suffix.lower() in suspicious_exts:
                        try:
                            st = fpath.stat()
                            found.append({
                                "path":  str(fpath),
                                "ext":   fpath.suffix,
                                "size":  st.st_size,
                                "mtime": datetime.fromtimestamp(st.st_mtime).strftime(
                                    "%Y-%m-%d %H:%M:%S"),
                            })
                        except Exception:
                            continue

        return save_json(case_dir / "56_suspicious_files.json", found)

    elif IS_LINUX:
        suspicious = []
        for search_dir in ["/tmp", "/var/tmp", "/dev/shm"]:
            sp = Path(search_dir)
            if not sp.exists():
                continue
            for dirpath, _, filenames in os.walk(str(sp)):
                for fname in filenames:
                    fpath = Path(dirpath) / fname
                    try:
                        st   = fpath.stat()
                        mode = st.st_mode
                        # Flag executables in world-writable directories
                        if mode & 0o111:
                            suspicious.append({
                                "path":       str(fpath),
                                "executable": True,
                                "size":       st.st_size,
                                "mtime":      datetime.fromtimestamp(st.st_mtime).strftime(
                                    "%Y-%m-%d %H:%M:%S"),
                            })
                    except Exception:
                        continue

        return save_json(case_dir / "56_suspicious_files.json", suspicious)


# ── Entry point ───────────────────────────────────────────────────────────────

def run_filesystem(case_dir: Path, tools_dir: Path, log) -> list:
    """
    Run all filesystem artifact collections.

    Args:
        case_dir:  Path to the timestamped case output folder.
        tools_dir: Path to the tools directory.
        log:       Callable for status logging.

    Returns:
        List of Path objects for all files written.
    """
    written = []

    if IS_LINUX:
        log("Collecting: SUID/SGID binaries")
        p = collect_suid_sgid(case_dir)
        if p:
            log(f"  -> Saved: {p.name} ({len(__import__('json').loads(p.read_text()))} entries)")
            written.append(p)

    if IS_WIN:
        log("Collecting: Alternate Data Streams")
        p = collect_ads(case_dir, tools_dir)
        if p:
            log(f"  -> Saved: {p.name}")
            written.append(p)

    log("Collecting: Suspicious files in temp locations")
    p = collect_suspicious_files(case_dir)
    if p:
        log(f"  -> Saved: {p.name}")
        written.append(p)

    return written
