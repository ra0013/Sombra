"""
collect/software.py
Gulf DataStream Labs — Sombra
Installed software inventory.

  Windows: registry uninstall keys (64-bit + 32-bit + per-user)
  Linux:   dpkg / rpm / pacman (tries all, uses what's available)

Software inventory serves two purposes:
  1. Identify attacker-installed tools (remote access software,
     credential dumpers, network scanners)
  2. Identify vulnerable software that may have been the initial
     access vector (outdated browsers, VPN clients, etc.)

Registry-based enumeration on Windows is preferred over wmic or
Get-Package because it provides installation dates, version strings,
publisher names, and install locations in a single query without
spawning additional processes.
"""

from datetime import datetime
from pathlib import Path
from typing import Optional

from engine.platform import IS_WIN, IS_LINUX, run, save_json

try:
    import winreg
    HAS_WINREG = True
except ImportError:
    HAS_WINREG = False


# ── Windows software inventory ────────────────────────────────────────────────

def collect_installed_software_win(case_dir: Path) -> Optional[Path]:
    """
    Enumerate installed software from Windows registry uninstall keys.

    Covers three locations:
      HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall
        64-bit applications installed for all users.
      HKLM\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall
        32-bit applications installed for all users.
      HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall
        Applications installed for the current user only.

    Fields collected per application:
      DisplayName, DisplayVersion, Publisher, InstallDate,
      InstallLocation, UninstallString

    The InstallDate field in YYYYMMDD format enables correlation with
    the incident timeline — software installed on or after the suspected
    compromise date warrants investigation.

    Args:
        case_dir: Path to the case output folder.
    """
    if not HAS_WINREG:
        return None

    uninstall_keys = [
        (winreg.HKEY_LOCAL_MACHINE,
         r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
         "HKLM_64bit"),
        (winreg.HKEY_LOCAL_MACHINE,
         r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
         "HKLM_32bit"),
        (winreg.HKEY_CURRENT_USER,
         r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
         "HKCU"),
    ]

    fields = [
        "DisplayName", "DisplayVersion", "Publisher",
        "InstallDate", "InstallLocation", "UninstallString",
    ]

    all_software = []

    for hive, subkey, label in uninstall_keys:
        try:
            with winreg.OpenKey(hive, subkey, 0, winreg.KEY_READ) as key:
                i = 0
                while True:
                    try:
                        app_key_name = winreg.EnumKey(key, i)
                        with winreg.OpenKey(key, app_key_name) as app_key:
                            app = {"_source": label, "_key": app_key_name}
                            for field in fields:
                                try:
                                    value, _ = winreg.QueryValueEx(app_key, field)
                                    app[field] = str(value)
                                except FileNotFoundError:
                                    app[field] = ""
                            # Only include entries with a display name
                            if app.get("DisplayName"):
                                all_software.append(app)
                        i += 1
                    except OSError:
                        break
        except (FileNotFoundError, PermissionError):
            continue

    # Sort by install date descending (most recent first)
    all_software.sort(
        key=lambda x: x.get("InstallDate", ""),
        reverse=True
    )

    return save_json(case_dir / "57_installed_software.json", all_software)


# ── Linux software inventory ──────────────────────────────────────────────────

def collect_installed_software_linux(case_dir: Path) -> Optional[Path]:
    """
    Enumerate installed packages on Linux.

    Tries package managers in order: dpkg → rpm → pacman → apk.
    Uses whichever is available on the target system — the script
    does not assume a specific distribution.

    Distribution coverage:
      dpkg    — Debian, Ubuntu, Kali, Mint, and derivatives
      rpm     — RHEL, CentOS, Fedora, Amazon Linux, and derivatives
      pacman  — Arch Linux, Manjaro, and derivatives
      apk     — Alpine Linux (common in containers)

    Also collects pip3 package list — Python packages installed
    system-wide may include attacker-installed tools.

    Args:
        case_dir: Path to the case output folder.
    """
    import shutil
    results = {}

    if shutil.which("dpkg"):
        results["package_manager"] = "dpkg"
        results["packages"] = run(["dpkg", "-l"], timeout=30)
    elif shutil.which("rpm"):
        results["package_manager"] = "rpm"
        results["packages"] = run(
            ["rpm", "-qa", "--queryformat",
             "%{NAME} %{VERSION} %{RELEASE} %{INSTALLTIME:date}\\n"],
            timeout=30
        )
    elif shutil.which("pacman"):
        results["package_manager"] = "pacman"
        results["packages"] = run(["pacman", "-Q"], timeout=30)
    elif shutil.which("apk"):
        results["package_manager"] = "apk"
        results["packages"] = run(["apk", "info", "-v"], timeout=30)
    else:
        results["package_manager"] = "unknown"
        results["packages"] = "(no supported package manager found)"

    # Python packages — attacker tools often installed via pip
    if shutil.which("pip3"):
        results["pip3_packages"] = run(["pip3", "list", "--format=columns"], timeout=15)
    elif shutil.which("pip"):
        results["pip3_packages"] = run(["pip", "list", "--format=columns"], timeout=15)

    return save_json(case_dir / "57_installed_software.json", results)


# ── Entry point ───────────────────────────────────────────────────────────────

def run_software(case_dir: Path, log) -> list:
    """
    Run software inventory collection.

    Args:
        case_dir: Path to the timestamped case output folder.
        log:      Callable for status logging.

    Returns:
        List of Path objects for all files written.
    """
    written = []

    log("Collecting: Installed software inventory")

    if IS_WIN:
        p = collect_installed_software_win(case_dir)
    elif IS_LINUX:
        p = collect_installed_software_linux(case_dir)
    else:
        p = None

    if p:
        log(f"  -> Saved: {p.name}")
        written.append(p)

    return written
