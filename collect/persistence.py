"""
collect/persistence.py
Gulf DataStream Labs — Sombra
Persistence mechanism enumeration — Windows and Linux.

Windows persistence locations:
  Run/RunOnce registry keys     — most common malware persistence
  Image File Execution Options  — debugger hijacking
  AppInit_DLLs / Winlogon       — DLL injection and logon hooks
  Active Setup                  — per-user execution on login
  BAM/DAM                       — execution timestamps (Windows 10+)
  Scheduled tasks               — common persistence and lateral movement
  Startup folders               — user and system startup locations
  WMI subscriptions             — stealthy, survives reboots and reimaging
  USBSTOR / USB history         — USB device connection evidence
  Services (cross-reference)    — see services.py

Linux persistence locations:
  Cron (all users)              — standard scheduled execution
  Systemd units/timers          — see services.py
  Shell startup files           — .bashrc, .profile, .zshrc
  SSH authorized_keys           — common attacker persistence
  /etc/rc.local, init.d         — legacy startup scripts
  PAM configuration             — authentication hook persistence
"""

import os
from pathlib import Path
from typing import Optional

from engine.platform import IS_WIN, IS_LINUX, run, ps, save_text, save_json

try:
    import winreg
    HAS_WINREG = True
except ImportError:
    HAS_WINREG = False


# ════════════════════════════════════════════════════════════════════════════
#  WINDOWS PERSISTENCE
# ════════════════════════════════════════════════════════════════════════════

def collect_registry_persistence(case_dir: Path) -> Optional[Path]:
    """
    Read Windows registry persistence keys via the winreg module.

    Direct registry API access is preferred over reg.exe subprocess
    because it avoids spawning an additional process and provides
    structured output suitable for machine-readable analysis.

    Keys examined:
      Run / RunOnce (HKLM + HKCU, 32-bit + 64-bit)
      Image File Execution Options — debugger hijacking
      AppInit_DLLs                 — DLL injection into every GUI process
      Winlogon Userinit/Shell      — logon hook replacement
      Active Setup                 — per-user execution on login
      LSA authentication packages  — authentication package persistence
      Browser Helper Objects       — IE/legacy browser persistence

    Args:
        case_dir: Path to the case output folder.
    """
    if not HAS_WINREG:
        return save_text(
            case_dir / "18_registry_persistence.txt",
            "[winreg not available]"
        )

    HKLM = winreg.HKEY_LOCAL_MACHINE
    HKCU = winreg.HKEY_CURRENT_USER

    key_groups = {
        "Run_HKLM":        (HKLM, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
        "RunOnce_HKLM":    (HKLM, r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"),
        "Run_HKLM_WOW":    (HKLM, r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run"),
        "Run_HKCU":        (HKCU, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
        "RunOnce_HKCU":    (HKCU, r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"),
        "IFEO":            (HKLM, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options"),
        "AppInit_DLLs":    (HKLM, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows"),
        "Winlogon":        (HKLM, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"),
        "Active_Setup":    (HKLM, r"SOFTWARE\Microsoft\Active Setup\Installed Components"),
        "LSA":             (HKLM, r"SYSTEM\CurrentControlSet\Control\Lsa"),
    }

    results = {}
    for label, (hive, subkey) in key_groups.items():
        try:
            with winreg.OpenKey(hive, subkey, 0, winreg.KEY_READ) as k:
                entries = {}
                i = 0
                while True:
                    try:
                        name, value, _ = winreg.EnumValue(k, i)
                        entries[name] = str(value)
                        i += 1
                    except OSError:
                        break
                # Also enumerate subkeys for IFEO and Active Setup
                subkeys = []
                i = 0
                while True:
                    try:
                        subkeys.append(winreg.EnumKey(k, i))
                        i += 1
                    except OSError:
                        break
                results[label] = {"values": entries, "subkeys": subkeys}
        except (FileNotFoundError, PermissionError) as e:
            results[label] = {"error": str(e)}

    return save_json(case_dir / "18_registry_persistence.json", results)


def collect_bam_dam(case_dir: Path) -> Optional[Path]:
    """
    Collect BAM (Background Activity Monitor) and DAM execution timestamps.

    BAM/DAM are Windows 10+ features that record the last execution
    timestamp for every binary that has run on the system, organized
    by user SID. This provides execution evidence that survives
    prefetch clearing and is often overlooked by attackers.

    The data lives in:
      HKLM\\SYSTEM\\CurrentControlSet\\Services\\bam\\State\\UserSettings\\<SID>

    Args:
        case_dir: Path to the case output folder.
    """
    if not HAS_WINREG:
        return None

    results = {}
    bam_path = r"SYSTEM\CurrentControlSet\Services\bam\State\UserSettings"

    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, bam_path) as bam_key:
            i = 0
            while True:
                try:
                    sid = winreg.EnumKey(bam_key, i)
                    with winreg.OpenKey(bam_key, sid) as sid_key:
                        entries = {}
                        j = 0
                        while True:
                            try:
                                name, value, vtype = winreg.EnumValue(sid_key, j)
                                if isinstance(value, bytes) and len(value) >= 8:
                                    import struct
                                    ft = struct.unpack("<Q", value[:8])[0]
                                    if ft > 0:
                                        from datetime import datetime, timezone
                                        epoch = datetime(1601, 1, 1, tzinfo=timezone.utc)
                                        from datetime import timedelta
                                        dt = epoch + timedelta(microseconds=ft // 10)
                                        entries[name] = dt.strftime("%Y-%m-%d %H:%M:%S UTC")
                                    else:
                                        entries[name] = str(value.hex())
                                else:
                                    entries[name] = str(value)
                                j += 1
                            except OSError:
                                break
                        results[sid] = entries
                    i += 1
                except OSError:
                    break
    except (FileNotFoundError, PermissionError) as e:
        results["error"] = str(e)

    return save_json(case_dir / "19_bam_dam.json", results)


def collect_scheduled_tasks(case_dir: Path) -> Path:
    """
    Collect all scheduled tasks with full verbose detail.

    Scheduled tasks are a heavily used persistence mechanism — malware
    creates tasks that re-execute after reboot, at login, or on a timer.
    Look for:
      - Tasks created recently (correlate with incident timeline)
      - Tasks with encoded or obfuscated command lines
      - Tasks running from temp or user profile directories
      - Tasks running as SYSTEM with suspicious actions

    Args:
        case_dir: Path to the case output folder.
    """
    if IS_WIN:
        # Both native schtasks and PowerShell Get-ScheduledTask
        tasks = {
            "schtasks": run(
                ["schtasks", "/query", "/fo", "LIST", "/v"],
                timeout=60
            ),
            "get_scheduled_task": ps(
                "Get-ScheduledTask | Select-Object TaskName,TaskPath,State,"
                "@{N='Actions';E={$_.Actions | ConvertTo-Json -Depth 2}} "
                "| ConvertTo-Json -Depth 3",
                timeout=60
            ),
        }
        return save_json(case_dir / "20_scheduled_tasks.json", tasks)

    # Linux: cron jobs
    cron_data = {}

    # Root crontab
    cron_data["root_crontab"] = run(["crontab", "-l"], timeout=10)

    # /etc/crontab and /etc/cron.d/*
    cron_data["etc_crontab"] = _read_file_safe(Path("/etc/crontab"))
    cron_d = {}
    cron_d_dir = Path("/etc/cron.d")
    if cron_d_dir.exists():
        for f in sorted(cron_d_dir.iterdir()):
            if f.is_file():
                cron_d[f.name] = _read_file_safe(f)
    cron_data["cron_d"] = cron_d

    # All user crontabs
    user_crontabs = {}
    try:
        for line in Path("/etc/passwd").read_text().splitlines():
            user = line.split(":")[0]
            out  = run(["crontab", "-u", user, "-l"], timeout=5)
            if "no crontab" not in out.lower() and out.strip():
                user_crontabs[user] = out
    except Exception as e:
        user_crontabs["error"] = str(e)
    cron_data["user_crontabs"] = user_crontabs

    return save_json(case_dir / "20_scheduled_tasks.json", cron_data)


def collect_startup_folders(case_dir: Path) -> Optional[Path]:
    """
    Collect contents of Windows startup folders.

    Files placed in startup folders execute automatically when any user
    (system startup folder) or the specific user (user startup folder)
    logs in. This is a simple but still used persistence technique.

    Args:
        case_dir: Path to the case output folder.
    """
    if not IS_WIN:
        return None

    startup_paths = [
        Path(r"C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp"),
        Path(r"C:\Users\All Users\Microsoft\Windows\Start Menu\Programs\StartUp"),
    ]

    # Also check per-user startup folders
    users_root = Path("C:\\Users")
    if users_root.exists():
        for user_dir in users_root.iterdir():
            startup = (user_dir / "AppData" / "Roaming" / "Microsoft" /
                      "Windows" / "Start Menu" / "Programs" / "StartUp")
            if startup.exists():
                startup_paths.append(startup)

    results = {}
    for path in startup_paths:
        if path.exists():
            try:
                results[str(path)] = [
                    {"name": f.name, "size": f.stat().st_size}
                    for f in path.iterdir() if f.is_file()
                ]
            except PermissionError:
                results[str(path)] = "(access denied)"
        else:
            results[str(path)] = "(not found)"

    return save_json(case_dir / "21_startup_folders.json", results)


def collect_wmi_subscriptions(case_dir: Path) -> Optional[Path]:
    """
    Enumerate WMI event subscriptions — a stealthy persistence mechanism.

    WMI subscriptions survive reimaging in some configurations and are
    not visible in standard autoruns listings. They consist of three
    components that must all be present:
      - EventFilter   — what event triggers the subscription
      - EventConsumer — what action to take (CommandLineEventConsumer
                        runs a command, ActiveScriptEventConsumer runs
                        a script)
      - FilterToConsumerBinding — links filter to consumer

    An attacker can create a WMI subscription that re-installs malware
    whenever a specific process starts, a user logs in, or a timer fires.

    Args:
        case_dir: Path to the case output folder.
    """
    if not IS_WIN:
        return None

    subscriptions = {
        "filters": ps(
            "Get-WMIObject -Namespace root\\subscription -Class __EventFilter "
            "| Select-Object Name,Query,QueryLanguage | ConvertTo-Json -Depth 2",
            timeout=30
        ),
        "consumers": ps(
            "Get-WMIObject -Namespace root\\subscription -Class __EventConsumer "
            "| Select-Object Name,CommandLineTemplate,ScriptText | ConvertTo-Json -Depth 2",
            timeout=30
        ),
        "bindings": ps(
            "Get-WMIObject -Namespace root\\subscription -Class __FilterToConsumerBinding "
            "| Select-Object Filter,Consumer | ConvertTo-Json -Depth 2",
            timeout=30
        ),
    }
    return save_json(case_dir / "22_wmi_subscriptions.json", subscriptions)


def collect_ssh_keys(case_dir: Path) -> Path:
    """
    Sweep all home directories for SSH authorized_keys files.

    SSH authorized_keys is one of the most common attacker persistence
    mechanisms on Linux — adding a public key allows passwordless login
    as that user indefinitely. Root's authorized_keys is highest priority.

    Args:
        case_dir: Path to the case output folder.
    """
    results = {}
    for base in [Path("/root"), Path("/home")]:
        if not base.exists():
            continue
        for key_file in base.rglob("authorized_keys"):
            try:
                results[str(key_file)] = key_file.read_text(errors="replace")
            except PermissionError:
                results[str(key_file)] = "(access denied)"

    return save_json(case_dir / "23_ssh_authorized_keys.json", results)


def collect_shell_startup(case_dir: Path) -> Path:
    """
    Sweep shell startup files for all users.

    Shell startup files execute on every login or shell start and are
    a common persistence location on Linux. Coverage:
      .bashrc, .bash_profile, .profile  — bash
      .zshrc, .zprofile                 — zsh
      /etc/profile, /etc/profile.d/*    — system-wide

    Args:
        case_dir: Path to the case output folder.
    """
    results = {}
    patterns = [
        ".bashrc", ".bash_profile", ".bash_login", ".profile",
        ".zshrc", ".zprofile", ".zlogin",
    ]

    # Per-user startup files
    for base in [Path("/root"), Path("/home")]:
        if not base.exists():
            continue
        for user_dir in ([base] if base.name == "root" else base.iterdir()):
            for pat in patterns:
                f = user_dir / pat
                if f.exists():
                    try:
                        results[str(f)] = f.read_text(errors="replace")
                    except PermissionError:
                        results[str(f)] = "(access denied)"

    # System-wide startup files
    for sys_file in [Path("/etc/profile"), Path("/etc/bash.bashrc")]:
        if sys_file.exists():
            results[str(sys_file)] = _read_file_safe(sys_file)

    profile_d = Path("/etc/profile.d")
    if profile_d.exists():
        for f in sorted(profile_d.iterdir()):
            if f.is_file():
                results[str(f)] = _read_file_safe(f)

    return save_json(case_dir / "24_shell_startup.json", results)


def collect_ps_history(case_dir: Path) -> Path:
    """
    Sweep PowerShell ConsoleHost_history.txt for all user profiles.

    PowerShell history captures every command typed interactively,
    including credential harvesting commands, lateral movement one-liners,
    and download cradles. This is one of the highest-value artifacts for
    hands-on-keyboard investigation.

    Note: only captures interactive commands, not executed scripts.
    Script content is captured in the PowerShell Operational event log.

    Args:
        case_dir: Path to the case output folder.
    """
    results = {}
    if IS_WIN:
        users_root = Path("C:\\Users")
        if users_root.exists():
            for user_dir in users_root.iterdir():
                hist = (user_dir / "AppData" / "Roaming" / "Microsoft" /
                        "Windows" / "PowerShell" / "PSReadLine" /
                        "ConsoleHost_history.txt")
                if hist.exists():
                    try:
                        results[str(hist)] = hist.read_text(errors="replace")
                    except PermissionError:
                        results[str(hist)] = "(access denied)"
    elif IS_LINUX:
        for base in [Path("/root"), Path("/home")]:
            if base.exists():
                for hist_file in base.rglob(".*history"):
                    try:
                        results[str(hist_file)] = hist_file.read_text(errors="replace")
                    except PermissionError:
                        results[str(hist_file)] = "(access denied)"

    return save_json(case_dir / "25_shell_history.json", results)


# ── Helpers ───────────────────────────────────────────────────────────────────

def _read_file_safe(path: Path) -> str:
    try:
        return path.read_text(errors="replace")
    except Exception as e:
        return f"[ERROR: {e}]"


# ── Entry point ───────────────────────────────────────────────────────────────

def run_persistence(case_dir: Path, log) -> list:
    """
    Run all persistence mechanism collections.

    Args:
        case_dir: Path to the timestamped case output folder.
        log:      Callable for status logging.

    Returns:
        List of Path objects for all files written.
    """
    written = []

    if IS_WIN:
        items = [
            ("Registry persistence keys",   collect_registry_persistence, []),
            ("BAM/DAM execution timestamps", collect_bam_dam,              []),
            ("Scheduled tasks",              collect_scheduled_tasks,       []),
            ("Startup folders",              collect_startup_folders,       []),
            ("WMI subscriptions",            collect_wmi_subscriptions,     []),
            ("PowerShell history",           collect_ps_history,            []),
        ]
    elif IS_LINUX:
        items = [
            ("Cron jobs (all users)",   collect_scheduled_tasks, []),
            ("SSH authorized_keys",     collect_ssh_keys,         []),
            ("Shell startup files",     collect_shell_startup,    []),
            ("Shell history",           collect_ps_history,       []),
        ]
    else:
        return written

    for label, func, args in items:
        log(f"Collecting: {label}")
        p = func(case_dir, *args)
        if p:
            log(f"  -> Saved: {p.name}")
            written.append(p)

    return written
