"""
reports/timeline_parser.py
Gulf DataStream Labs — Sombra
Shared timeline event parsing logic.

Parses all collected artifacts into a normalized event list
that can be consumed by any of the three timeline output formats:
  - HTML (Sombra native)
  - CSV (Timeline Explorer compatible)
  - L2T (Plaso/log2timeline compatible)

Event schema:
  ts          — ISO timestamp string (YYYY-MM-DD HH:MM:SS)
  source      — artifact category (Security, Process, Prefetch, etc.)
  eid         — event ID string (empty for non-Windows-event sources)
  description — human-readable event description (max 300 chars)
  artifact    — source filename
  flagged     — bool, True if matches profile suspicious indicators
  username    — associated username if available (empty otherwise)
  hostname    — target hostname
"""

import json
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Optional


# ── Event schema ──────────────────────────────────────────────────────────────

def make_event(
    ts:          str,
    source:      str,
    description: str,
    artifact:    str,
    eid:         str = "",
    username:    str = "",
    hostname:    str = "",
    flagged:     bool = False,
) -> Dict:
    """Create a normalized event dict."""
    return {
        "ts":          ts,
        "source":      source,
        "eid":         eid,
        "description": str(description)[:300].replace("<","&lt;").replace(">","&gt;"),
        "artifact":    artifact,
        "flagged":     flagged,
        "username":    username,
        "hostname":    hostname,
    }


# ── Safe JSON loader ──────────────────────────────────────────────────────────

def _load(path: Path) -> Optional[object]:
    try:
        return json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except Exception:
        return None


def _fmt_ts(ts) -> str:
    """Normalize a timestamp to YYYY-MM-DD HH:MM:SS or empty string."""
    if not ts:
        return ""
    s = str(ts)[:19].replace("T", " ")
    return s if len(s) >= 10 else ""


# ── Parsers ───────────────────────────────────────────────────────────────────

def parse_processes(case_dir: Path, profile, hostname: str) -> List[Dict]:
    events = []
    pf = case_dir / "01_processes.json"
    if not pf.exists():
        return events

    data = _load(pf)
    if not data:
        return events

    # Handle both list (Windows) and dict with psutil/proc_cmdlines (Linux)
    proc_list = data if isinstance(data, list) else data.get("psutil", [])

    for p in proc_list:
        ts = _fmt_ts(p.get("create_time", ""))
        if not ts:
            continue
        cmd  = p.get("cmdline") or p.get("name", "")
        desc = f"PID {p.get('pid','')} [{p.get('name','')}] {cmd}"
        flagged = profile.is_suspicious(desc)
        events.append(make_event(
            ts=ts, source="Process", description=desc,
            artifact="01_processes.json", hostname=hostname,
            username=p.get("username", ""), flagged=flagged
        ))
    return events


def parse_prefetch(case_dir: Path, profile, hostname: str) -> List[Dict]:
    events = []
    pf = case_dir / "35_prefetch.json"
    if not pf.exists():
        return events

    data = _load(pf)
    if not data or not isinstance(data, list):
        return events

    for e in data:
        ts = _fmt_ts(e.get("mtime", ""))
        if not ts:
            continue
        exe = e.get("file", "").replace(".pf", "").rsplit("-", 1)[0]
        desc = f"Executed: {exe}"
        flagged = profile.is_suspicious(desc)
        events.append(make_event(
            ts=ts, source="Prefetch", description=desc,
            artifact="35_prefetch.json", hostname=hostname, flagged=flagged
        ))
    return events


def parse_windows_eventlog(
    case_dir: Path,
    filename: str,
    label: str,
    profile,
    hostname: str
) -> List[Dict]:
    events = []
    ef = case_dir / filename
    if not ef.exists():
        return events

    data = _load(ef)
    if data is None:
        return events

    if isinstance(data, dict):
        data = [data]
    if not isinstance(data, list):
        return events

    for entry in data:
        if not isinstance(entry, dict):
            continue

        ts_raw = str(entry.get("TimeCreated", ""))
        # Handle /Date(ms)/ format from older PowerShell
        if ts_raw.startswith("/Date("):
            try:
                ms = int(ts_raw[6:ts_raw.index(")")])
                ts = datetime.fromtimestamp(ms / 1000).strftime("%Y-%m-%d %H:%M:%S")
            except Exception:
                ts = ""
        else:
            ts = _fmt_ts(ts_raw)

        if not ts:
            continue

        eid = str(entry.get("Id", ""))
        msg = entry.get("Message", "")
        desc = str(msg).strip().splitlines()[0][:200] if msg else f"Event {eid}"
        flagged = profile.is_suspicious(desc, eid)

        events.append(make_event(
            ts=ts, source=label, eid=eid, description=desc,
            artifact=filename, hostname=hostname, flagged=flagged
        ))
    return events


def parse_linux_log(
    case_dir: Path,
    filename: str,
    label: str,
    profile,
    hostname: str
) -> List[Dict]:
    events = []
    lf = case_dir / filename
    if not lf.exists():
        return events

    months = {
        "Jan":"01","Feb":"02","Mar":"03","Apr":"04","May":"05","Jun":"06",
        "Jul":"07","Aug":"08","Sep":"09","Oct":"10","Nov":"11","Dec":"12"
    }
    current_year = datetime.now().year

    try:
        lines = lf.read_text(errors="replace").splitlines()
    except Exception:
        return events

    for line in lines:
        parts = line.strip().split()
        if len(parts) >= 3 and parts[0] in months:
            try:
                ts = f"{current_year}-{months[parts[0]]}-{parts[1].zfill(2)} {parts[2]}"
                desc = " ".join(parts[3:])[:200]
                flagged = profile.is_suspicious(desc)
                events.append(make_event(
                    ts=ts, source=label, description=desc,
                    artifact=filename, hostname=hostname, flagged=flagged
                ))
            except Exception:
                continue
    return events


def parse_lastactivityview(case_dir: Path, profile, hostname: str) -> List[Dict]:
    events = []
    lav = case_dir / "50_lastactivityview.csv"
    if not lav.exists():
        return events

    try:
        lines = lav.read_text(errors="replace").splitlines()
    except Exception:
        return events

    for line in lines:
        parts = [p.strip() for p in line.split(",")]
        if len(parts) < 3:
            continue
        ts = _fmt_ts(parts[0]) if parts[0] else ""
        if not ts:
            continue
        desc = parts[1] if len(parts) > 1 else ""
        action = parts[2] if len(parts) > 2 else ""
        full_desc = f"{action}: {desc}" if action else desc
        flagged = profile.is_suspicious(full_desc)
        events.append(make_event(
            ts=ts, source="LastActivityView", description=full_desc,
            artifact="50_lastactivityview.csv", hostname=hostname, flagged=flagged
        ))
    return events


# ── Main parse function ───────────────────────────────────────────────────────

# Windows event log files and their display labels
WIN_EVENT_FILES = [
    ("26_eventlog_security.json",    "Security"),
    ("27_eventlog_system.json",      "System"),
    ("28_eventlog_application.json", "Application"),
    ("29_eventlog_powershell.json",  "PowerShell"),
    ("30_eventlog_taskscheduler.json","TaskScheduler"),
    ("31_eventlog_rdp.json",         "RDP"),
    ("32_eventlog_bits.json",        "BITS"),
    ("33_eventlog_wmi.json",         "WMI"),
    ("34_eventlog_firewall.json",    "Firewall"),
]

LINUX_LOG_FILES = [
    ("26_auth_log.txt", "Auth"),
    ("27_syslog.txt",   "Syslog"),
    ("28_kern_log.txt", "Kernel"),
]


def parse_all(case_dir: Path, profile, hostname: str) -> List[Dict]:
    """
    Parse all available artifact files into a unified event list.

    Automatically detects which files exist and parses what's available.
    Missing files are silently skipped — the function works on partial
    case folders and across both Windows and Linux runs.

    Args:
        case_dir: Path to the completed case folder.
        profile:  Profile instance for suspicious indicator matching.
        hostname: Target hostname for event attribution.

    Returns:
        Chronologically sorted list of normalized event dicts.
    """
    events = []

    # Processes
    events.extend(parse_processes(case_dir, profile, hostname))

    # Prefetch (Windows)
    events.extend(parse_prefetch(case_dir, profile, hostname))

    # Windows event logs
    for filename, label in WIN_EVENT_FILES:
        events.extend(parse_windows_eventlog(case_dir, filename, label, profile, hostname))

    # Linux logs
    for filename, label in LINUX_LOG_FILES:
        events.extend(parse_linux_log(case_dir, filename, label, profile, hostname))

    # LastActivityView (Nirsoft)
    events.extend(parse_lastactivityview(case_dir, profile, hostname))

    # Sort chronologically — empty timestamps sort to beginning
    events.sort(key=lambda x: x["ts"] or "0000")

    return events
