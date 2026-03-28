"""
collect/artifacts.py
Gulf DataStream Labs — Sombra
Semi-volatile artifacts — execution evidence and event logs.

  Event logs         — Security, System, Application, PowerShell,
                       TaskScheduler, RDP, BITS, WMI, Firewall
  Prefetch files     — execution evidence survives binary deletion
  USB history        — device connection history from registry
  Account info       — local users, groups, password policy
  System information — OS version, hotfixes, hardware baseline

These artifacts are less volatile than process state but still
represent time-sensitive data — logs roll over, prefetch files
are overwritten, and USB history can be cleared.
"""

from pathlib import Path
from typing import Optional

from engine.platform import IS_WIN, IS_LINUX, run, ps, save_text, save_json
from datetime import datetime

try:
    import winreg
    HAS_WINREG = True
except ImportError:
    HAS_WINREG = False


# ════════════════════════════════════════════════════════════════════════════
#  EVENT LOGS
# ════════════════════════════════════════════════════════════════════════════

# Event log definitions — name, max events, output filename
WIN_EVENT_LOGS = [
    ("Security",                              500, "26_eventlog_security.json"),
    ("System",                                300, "27_eventlog_system.json"),
    ("Application",                           200, "28_eventlog_application.json"),
    ("Microsoft-Windows-PowerShell/Operational", 200, "29_eventlog_powershell.json"),
    ("Microsoft-Windows-TaskScheduler/Operational", 200, "30_eventlog_taskscheduler.json"),
    ("Microsoft-Windows-TerminalServices-LocalSessionManager/Operational", 200, "31_eventlog_rdp.json"),
    ("Microsoft-Windows-Bits-Client/Operational", 100, "32_eventlog_bits.json"),
    ("Microsoft-Windows-WMI-Activity/Operational", 100, "33_eventlog_wmi.json"),
    ("Microsoft-Windows-Windows Firewall With Advanced Security/Firewall", 100, "34_eventlog_firewall.json"),
]


def collect_event_logs(case_dir: Path, log_count: int = None) -> list:
    """
    Collect Windows event logs across all relevant channels.

    Each log channel captures different investigation-relevant activity:
      Security       — logons, account changes, process creation, privilege use
      System         — service installs, driver loads, system errors
      Application    — application crashes, WER events
      PowerShell     — script block logging, command execution (4103, 4104)
      TaskScheduler  — task creation, modification, execution
      RDP            — remote desktop session events
      BITS           — background transfer jobs (common C2/exfil channel)
      WMI Activity   — WMI query execution (lateral movement indicator)
      Firewall       — firewall rule changes

    Args:
        case_dir:  Path to the case output folder.
        log_count: Override default max events per log (None = use defaults).

    Returns:
        List of paths written.
    """
    written = []
    for log_name, max_events, filename in WIN_EVENT_LOGS:
        count = log_count or max_events
        out = ps(
            f"Get-WinEvent -LogName '{log_name}' -MaxEvents {count} -ErrorAction SilentlyContinue "
            f"| Select-Object TimeCreated,Id,LevelDisplayName,Message "
            f"| ConvertTo-Json -Depth 2",
            timeout=90
        )
        p = save_text(case_dir / filename, out)
        written.append(p)
    return written


def collect_linux_logs(case_dir: Path) -> list:
    """
    Collect authentication and system logs on Linux.

    Handles both Debian (/var/log/auth.log) and RHEL (/var/log/secure)
    path conventions. Reads last 2000 lines via Python to avoid spawning
    a tail subprocess on the target.

    Args:
        case_dir: Path to the case output folder.
    """
    written = []

    log_pairs = [
        ([Path("/var/log/auth.log"),   Path("/var/log/secure")],   "26_auth_log.txt"),
        ([Path("/var/log/syslog"),     Path("/var/log/messages")],  "27_syslog.txt"),
        ([Path("/var/log/kern.log"),   Path("/var/log/kernel")],    "28_kern_log.txt"),
    ]

    for candidates, filename in log_pairs:
        for candidate in candidates:
            if candidate.exists():
                try:
                    lines = candidate.read_text(errors="replace").splitlines()
                    p = save_text(case_dir / filename, "\n".join(lines[-2000:]))
                    written.append(p)
                    break
                except PermissionError:
                    p = save_text(case_dir / filename, "(access denied — run as root)")
                    written.append(p)
                    break
        else:
            p = save_text(case_dir / filename, "(log not found)")
            written.append(p)

    # dmesg — kernel ring buffer
    p = save_text(case_dir / "29_dmesg.txt", run(["dmesg"], timeout=10))
    written.append(p)

    return written


# ════════════════════════════════════════════════════════════════════════════
#  EXECUTION EVIDENCE
# ════════════════════════════════════════════════════════════════════════════

def collect_prefetch(case_dir: Path) -> Optional[Path]:
    """
    Inventory Windows Prefetch files as execution evidence.

    Prefetch files survive binary deletion — malware that has been
    removed from disk still leaves .pf files proving it executed.
    The filename encodes the executable name and a hash of the path.
    The file's modification time reflects the last execution time.

    Prefetch is enabled by default on workstations, may be disabled
    on servers. If disabled, this section returns an empty inventory.

    Args:
        case_dir: Path to the case output folder.
    """
    if not IS_WIN:
        return None

    prefetch_dir = Path(r"C:\Windows\Prefetch")
    entries = []

    if prefetch_dir.exists():
        for pf in sorted(prefetch_dir.glob("*.pf")):
            try:
                st = pf.stat()
                entries.append({
                    "file":  pf.name,
                    "size":  st.st_size,
                    "mtime": datetime.fromtimestamp(st.st_mtime).strftime("%Y-%m-%d %H:%M:%S"),
                    "atime": datetime.fromtimestamp(st.st_atime).strftime("%Y-%m-%d %H:%M:%S"),
                })
            except Exception:
                continue
    else:
        entries = [{"note": "Prefetch directory not found — may be disabled"}]

    return save_json(case_dir / "35_prefetch.json", entries)


def collect_recently_modified_bins(case_dir: Path) -> Optional[Path]:
    """
    Find system binaries modified more recently than /etc/passwd.

    A binary in /bin, /sbin, /usr/bin, or /usr/sbin that was modified
    after /etc/passwd (which changes infrequently) is a strong indicator
    of binary replacement — a classic rootkit technique.

    Linux only.

    Args:
        case_dir: Path to the case output folder.
    """
    if not IS_LINUX:
        return None

    try:
        ref_mtime = Path("/etc/passwd").stat().st_mtime
    except FileNotFoundError:
        ref_mtime = 0

    modified = []
    for search_dir in ["/bin", "/sbin", "/usr/bin", "/usr/sbin"]:
        for dirpath, _, filenames in __import__("os").walk(search_dir):
            for fname in filenames:
                fpath = Path(dirpath) / fname
                try:
                    st = fpath.stat()
                    if st.st_mtime > ref_mtime:
                        modified.append({
                            "path":  str(fpath),
                            "mtime": datetime.fromtimestamp(st.st_mtime).strftime("%Y-%m-%d %H:%M:%S"),
                            "size":  st.st_size,
                        })
                except (PermissionError, FileNotFoundError):
                    continue

    return save_json(case_dir / "36_recently_modified_bins.json", modified)


# ════════════════════════════════════════════════════════════════════════════
#  ACCOUNT AND SYSTEM INFO
# ════════════════════════════════════════════════════════════════════════════

def collect_accounts(case_dir: Path) -> Path:
    """
    Collect local user and group account information.

    New accounts, recently modified accounts, and accounts with
    elevated privileges are all indicators of attacker activity.
    Correlate account creation times with the incident timeline.

    Args:
        case_dir: Path to the case output folder.
    """
    if IS_WIN:
        accounts = {
            "net_user":        run(["net", "user"]),
            "net_localgroup":  run(["net", "localgroup"]),
            "net_admins":      run(["net", "localgroup", "administrators"]),
            "get_local_user":  ps(
                "Get-LocalUser | Select-Object Name,Enabled,LastLogon,"
                "PasswordLastSet,SID | ConvertTo-Json",
                timeout=20
            ),
            "get_local_group": ps(
                "Get-LocalGroup | Select-Object Name,SID | ConvertTo-Json",
                timeout=20
            ),
        }
        return save_json(case_dir / "37_accounts.json", accounts)

    # Linux
    accounts = {
        "passwd":  _read_file_safe(Path("/etc/passwd")),
        "group":   _read_file_safe(Path("/etc/group")),
        "shadow":  _read_shadow(),
        "last":    run(["last", "-F", "-n", "100"]),
        "lastb":   run(["lastb", "-F", "-n", "100"]),
        "lastlog": run(["lastlog"]),
        "who":     run(["who", "-a"]),
    }
    return save_json(case_dir / "37_accounts.json", accounts)


def _read_shadow() -> str:
    try:
        return Path("/etc/shadow").read_text(errors="replace")
    except PermissionError:
        return "(access denied — run as root)"
    except FileNotFoundError:
        return "(not found)"


def collect_system_info(case_dir: Path) -> Path:
    """
    Collect baseline system identification information.

    Establishes the system identity, patch level, and hardware configuration.
    Critical for correlating findings with vulnerability databases and
    for identifying whether known exploits could have been used.

    Args:
        case_dir: Path to the case output folder.
    """
    if IS_WIN:
        return save_text(case_dir / "38_systeminfo.txt", run(["systeminfo"]))

    info = {
        "os_release": _read_file_safe(Path("/etc/os-release")),
        "uname":      run(["uname", "-a"]),
        "uptime":     run(["uptime"]),
        "hostname":   run(["hostname", "-f"]),
        "mounts":     run(["mount"]),
        "df":         run(["df", "-h"]),
    }
    return save_json(case_dir / "38_systeminfo.json", info)


def collect_usb_history(case_dir: Path) -> Optional[Path]:
    """
    Collect USB device connection history from the registry.
    Windows only.

    The USBSTOR registry key records every USB storage device that
    has been connected to this machine, including device name, serial
    number, and connection timestamps. In an insider threat investigation
    this is often the first place to look.

    Args:
        case_dir: Path to the case output folder.
    """
    if not IS_WIN or not HAS_WINREG:
        return None

    results = {}
    try:
        with winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            r"SYSTEM\CurrentControlSet\Enum\USBSTOR"
        ) as usbstor:
            i = 0
            while True:
                try:
                    device_class = winreg.EnumKey(usbstor, i)
                    with winreg.OpenKey(usbstor, device_class) as class_key:
                        j = 0
                        while True:
                            try:
                                instance = winreg.EnumKey(class_key, j)
                                with winreg.OpenKey(class_key, instance) as inst_key:
                                    vals = {}
                                    k = 0
                                    while True:
                                        try:
                                            name, value, _ = winreg.EnumValue(inst_key, k)
                                            vals[name] = str(value)
                                            k += 1
                                        except OSError:
                                            break
                                    results[f"{device_class}\\{instance}"] = vals
                                j += 1
                            except OSError:
                                break
                    i += 1
                except OSError:
                    break
    except (FileNotFoundError, PermissionError) as e:
        results["error"] = str(e)

    return save_json(case_dir / "39_usb_history.json", results)


def _read_file_safe(path: Path) -> str:
    try:
        return path.read_text(errors="replace")
    except Exception as e:
        return f"[ERROR: {e}]"


# ── Entry point ───────────────────────────────────────────────────────────────

def run_artifacts(case_dir: Path, log) -> list:
    """
    Run all artifact collections.

    Args:
        case_dir: Path to the timestamped case output folder.
        log:      Callable for status logging.

    Returns:
        List of Path objects for all files written.
    """
    written = []

    if IS_WIN:
        log("Collecting: Windows event logs (9 channels)")
        paths = collect_event_logs(case_dir)
        for p in paths:
            log(f"  -> Saved: {p.name}")
        written.extend(paths)

        for label, func in [
            ("Prefetch inventory",  collect_prefetch),
            ("Account information", collect_accounts),
            ("System information",  collect_system_info),
            ("USB device history",  collect_usb_history),
        ]:
            log(f"Collecting: {label}")
            p = func(case_dir)
            if p:
                log(f"  -> Saved: {p.name}")
                written.append(p)

    elif IS_LINUX:
        log("Collecting: Linux logs")
        paths = collect_linux_logs(case_dir)
        for p in paths:
            log(f"  -> Saved: {p.name}")
        written.extend(paths)

        for label, func in [
            ("Recently modified binaries", collect_recently_modified_bins),
            ("Account information",        collect_accounts),
            ("System information",         collect_system_info),
        ]:
            log(f"Collecting: {label}")
            p = func(case_dir)
            if p:
                log(f"  -> Saved: {p.name}")
                written.append(p)

    return written
