"""
collect/services.py
Gulf DataStream Labs — Sombra
Services and kernel driver enumeration.

  Running services    — executable paths reveal malicious service installs
  All services        — stopped services may be dormant persistence
  Kernel drivers      — rootkits install as drivers
  Driver signatures   — unsigned drivers are high-confidence indicators

Services are a primary persistence mechanism — malware installs as a
service to survive reboots. The executable path is the key field:
legitimate services live in System32 or Program Files, malicious ones
frequently live in temp folders, AppData, or random paths.
"""

from pathlib import Path
from typing import Optional

from engine.platform import IS_WIN, IS_LINUX, run, ps, save_text, save_json


# ── Windows services ──────────────────────────────────────────────────────────

def collect_services_win(case_dir: Path) -> Path:
    """
    Collect all Windows services via CIM with executable path detail.

    The PathName field is critical — it reveals the actual binary
    being executed. A service named 'Windows Update Helper' pointing
    to C:\\Users\\Public\\svchost32.exe is immediately suspicious.

    Also collects:
      - Service state (running, stopped, paused)
      - Start mode (auto, manual, disabled, boot)
      - Display name vs service name (mismatches are suspicious)

    Args:
        case_dir: Path to the case output folder.
    """
    out = ps(
        "Get-CimInstance Win32_Service "
        "| Select-Object Name,DisplayName,State,StartMode,PathName,StartName "
        "| Sort-Object State,Name "
        "| ConvertTo-Json -Depth 2",
        timeout=45
    )
    return save_text(case_dir / "12_services.json", out)


def collect_drivers_win(case_dir: Path) -> Path:
    """
    Collect loaded kernel drivers on Windows.

    Rootkits install as kernel drivers. Unsigned drivers are particularly
    suspicious on modern Windows where driver signing is enforced.
    A driver loaded from a temp folder or user profile directory is
    almost certainly malicious.

    Args:
        case_dir: Path to the case output folder.
    """
    out = ps(
        "Get-CimInstance Win32_SystemDriver "
        "| Select-Object Name,State,PathName,ServiceType "
        "| Sort-Object State "
        "| ConvertTo-Json -Depth 2",
        timeout=30
    )
    return save_text(case_dir / "13_drivers.json", out)


# ── Linux services ────────────────────────────────────────────────────────────

def collect_services_linux(case_dir: Path) -> Path:
    """
    Collect systemd service and timer units on Linux.

    Systemd services and timers are both persistence mechanisms.
    Timers are frequently overlooked — they function identically to
    cron jobs but are not visible in crontab output. A suspicious
    service or timer unit file in /etc/systemd/system/ or
    ~/.config/systemd/user/ warrants immediate investigation.

    Also checks for SysV init scripts for older systems.

    Args:
        case_dir: Path to the case output folder.
    """
    services = {
        "systemd_services": run(
            ["systemctl", "list-units", "--type=service", "--all", "--no-pager"],
            timeout=15
        ),
        "systemd_timers": run(
            ["systemctl", "list-timers", "--all", "--no-pager"],
            timeout=15
        ),
        "systemd_enabled": run(
            ["systemctl", "list-unit-files", "--type=service", "--no-pager"],
            timeout=15
        ),
    }

    # Check for SysV init scripts
    sysv_dir = Path("/etc/init.d")
    if sysv_dir.exists():
        try:
            services["sysv_scripts"] = [f.name for f in sorted(sysv_dir.iterdir())]
        except PermissionError:
            services["sysv_scripts"] = "(access denied)"

    return save_json(case_dir / "12_services.json", services)


def collect_kernel_modules_linux(case_dir: Path) -> Path:
    """
    Collect loaded kernel modules on Linux.

    Rootkits install as kernel modules (LKMs). A module loaded from
    a non-standard path or with an unusual name should be investigated.
    Compare against a known-good baseline if available.

    Args:
        case_dir: Path to the case output folder.
    """
    modules = {
        "lsmod": run(["lsmod"], timeout=10),
    }

    # Try to get module details including file paths
    modinfo_list = []
    lsmod_out = run(["lsmod"], timeout=10)
    for line in lsmod_out.splitlines()[1:]:  # Skip header
        mod_name = line.split()[0] if line.split() else ""
        if mod_name:
            info = run(["modinfo", mod_name], timeout=5)
            if "[NOT FOUND]" not in info and "[ERROR]" not in info:
                modinfo_list.append({"name": mod_name, "info": info})

    modules["modinfo"] = modinfo_list
    return save_json(case_dir / "13_kernel_modules.json", modules)


# ── Entry point ───────────────────────────────────────────────────────────────

def run_services(case_dir: Path, log) -> list:
    """
    Run all service and driver collections.

    Args:
        case_dir: Path to the timestamped case output folder.
        log:      Callable for status logging.

    Returns:
        List of Path objects for all files written.
    """
    written = []

    if IS_WIN:
        for label, func in [
            ("Windows services",  collect_services_win),
            ("Kernel drivers",    collect_drivers_win),
        ]:
            log(f"Collecting: {label}")
            p = func(case_dir)
            if p:
                log(f"  -> Saved: {p.name}")
                written.append(p)

    elif IS_LINUX:
        for label, func in [
            ("Systemd services and timers", collect_services_linux),
            ("Kernel modules",              collect_kernel_modules_linux),
        ]:
            log(f"Collecting: {label}")
            p = func(case_dir)
            if p:
                log(f"  -> Saved: {p.name}")
                written.append(p)

    return written
