"""
reports/timeline_plaso.py
Gulf DataStream Labs — Sombra
log2timeline (L2T) CSV export — Plaso/Timesketch compatible format.

The L2T CSV format is the interchange format for the Plaso ecosystem:
  - Plaso (log2timeline) ingests L2T CSV directly
  - Timesketch imports Plaso output for collaborative analysis
  - Other tools (Kibana with custom mappings) can consume it

L2T CSV column spec:
  date, time, timezone, MACB, source, sourcetype, type,
  user, host, short, desc, version, filename, inode, notes,
  format, extra

This is structurally similar to Timeline Explorer CSV but with
slightly different conventions for the source/type fields and
strict UTC timestamp requirements.

Reference: https://plaso.readthedocs.io/en/latest/sources/user/Output-and-formatting.html
"""

import csv
from pathlib import Path
from typing import List, Dict
from datetime import datetime, timezone


# L2T CSV column order — must match exactly
L2T_HEADERS = [
    "date", "time", "timezone", "MACB",
    "source", "sourcetype", "type",
    "user", "host", "short", "desc",
    "version", "filename", "inode",
    "notes", "format", "extra",
]


def _to_utc_parts(ts: str):
    """
    Split a YYYY-MM-DD HH:MM:SS timestamp into date and time parts.
    Returns ("", "") if the timestamp is invalid.
    """
    if not ts or len(ts) < 10:
        return "", ""
    if " " in ts:
        parts = ts.split(" ", 1)
        return parts[0], parts[1][:8] if len(parts) > 1 else "00:00:00"
    if "T" in ts:
        parts = ts.split("T", 1)
        return parts[0], parts[1][:8] if len(parts) > 1 else "00:00:00"
    return ts[:10], "00:00:00"


# Sombra source → Plaso sourcetype mapping
# Follows Plaso's EVTX, syslog, and custom source type conventions
_SOURCE_TYPE_MAP = {
    "Security":      "WinEvt",
    "System":        "WinEvt",
    "Application":   "WinEvt",
    "PowerShell":    "WinEvt",
    "TaskScheduler": "WinEvt",
    "RDP":           "WinEvt",
    "BITS":          "WinEvt",
    "WMI":           "WinEvt",
    "Firewall":      "WinEvt",
    "Auth":          "syslog",
    "Syslog":        "syslog",
    "Kernel":        "syslog",
    "Process":       "process_info",
    "Prefetch":      "prefetch",
    "LastActivityView": "lastactivityview",
}


def _event_to_l2t_row(event: Dict) -> List[str]:
    """
    Convert a normalized Sombra event to an L2T CSV row.

    Args:
        event: Normalized event dict from timeline_parser.

    Returns:
        List of strings in L2T_HEADERS order.
    """
    ts          = event.get("ts", "")
    source      = event.get("source", "")
    eid         = event.get("eid", "")
    description = event.get("description", "").replace("&lt;", "<").replace("&gt;", ">")
    artifact    = event.get("artifact", "")
    username    = event.get("username", "")
    hostname    = event.get("hostname", "")
    flagged     = event.get("flagged", False)

    date_part, time_part = _to_utc_parts(ts)
    source_type = _SOURCE_TYPE_MAP.get(source, "sombra_artifact")

    # L2T type field: more specific than sourcetype
    if eid:
        type_str = f"WinEvt: Event ID {eid}"
    else:
        type_str = source

    notes = "FLAGGED" if flagged else ""

    return [
        date_part,              # date
        time_part,              # time
        "UTC",                  # timezone
        "....",                 # MACB (not applicable)
        "SOMBRA",               # source (tool name, uppercase convention)
        source_type,            # sourcetype
        type_str,               # type
        username,               # user
        hostname,               # host
        description[:80],       # short
        description,            # desc
        "1",                    # version
        artifact,               # filename
        "-",                    # inode (not applicable)
        notes,                  # notes
        "Sombra",               # format
        eid or source,          # extra
    ]


def write_l2t_timeline(
    case_dir:     Path,
    case_name:    str,
    hostname:     str,
    profile_name: str,
    events:       List[Dict],
    log,
) -> Path:
    """
    Write the log2timeline CSV timeline for Plaso/Timesketch ingestion.

    Output is UTF-8 without BOM (Plaso expects standard UTF-8).

    Usage with Plaso:
        pinfo.py Sombra_Timeline.l2t
        psort.py -o dynamic Sombra_Timeline.l2t

    Usage with Timesketch:
        timesketch_importer --timeline_name "Sombra" Sombra_Timeline.l2t

    Args:
        case_dir:     Path to the case output folder.
        case_name:    Case name string.
        hostname:     Target hostname.
        profile_name: Profile name.
        events:       Parsed and sorted event list.
        log:          Callable for status logging.

    Returns:
        Path to the written .l2t file.
    """
    out = case_dir / "Sombra_Timeline.l2t"

    with open(out, "w", encoding="utf-8", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(L2T_HEADERS)
        for event in events:
            row = _event_to_l2t_row(event)
            if row[0]:  # Only write events with valid dates
                writer.writerow(row)

    valid = sum(1 for e in events if _to_utc_parts(e.get("ts", ""))[0])
    log(f"  -> Saved: Sombra_Timeline.l2t ({valid:,} events — Plaso/Timesketch compatible)")
    return out
