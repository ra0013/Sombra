"""
reports/timeline_csv.py
Gulf DataStream Labs — Sombra
CSV timeline export — Timeline Explorer compatible format.

Timeline Explorer (by Eric Zimmerman) is the standard tool for
reviewing timeline CSVs in the DFIR community. It supports filtering,
sorting, and coloring by column values.

Output format matches the common DFIR timeline CSV convention:
  Date,Time,Timezone,MACB,Source,SourceType,Type,User,Host,
  Short,Desc,Version,Filename,Inode,Notes,Format,Extra

Fields not applicable to Sombra events are left empty.
The file is UTF-8 encoded with BOM for Excel compatibility.
"""

import csv
import io
from datetime import datetime
from pathlib import Path
from typing import List, Dict


# Timeline Explorer compatible column headers
HEADERS = [
    "Date",
    "Time",
    "Timezone",
    "MACB",
    "Source",
    "SourceType",
    "Type",
    "User",
    "Host",
    "Short",
    "Desc",
    "Version",
    "Filename",
    "Inode",
    "Notes",
    "Format",
    "Extra",
]


def _event_to_row(event: Dict) -> List[str]:
    """
    Convert a normalized Sombra event dict to a Timeline Explorer CSV row.

    Timestamp split: "2026-03-24 14:30:00" → Date="2026-03-24", Time="14:30:00"

    Args:
        event: Normalized event dict from timeline_parser.

    Returns:
        List of strings in HEADERS order.
    """
    ts = event.get("ts", "")
    if " " in ts:
        date_part, time_part = ts.split(" ", 1)
    elif "T" in ts:
        date_part, time_part = ts.split("T", 1)
        time_part = time_part[:8]
    else:
        date_part = ts[:10] if ts else ""
        time_part = ""

    source      = event.get("source", "")
    eid         = event.get("eid", "")
    description = event.get("description", "").replace("&lt;", "<").replace("&gt;", ">")
    artifact    = event.get("artifact", "")
    username    = event.get("username", "")
    hostname    = event.get("hostname", "")
    flagged     = event.get("flagged", False)

    # Source type maps Sombra source labels to Timeline Explorer conventions
    source_type_map = {
        "Security":      "EVT",
        "System":        "EVT",
        "Application":   "EVT",
        "PowerShell":    "EVT",
        "TaskScheduler": "EVT",
        "RDP":           "EVT",
        "BITS":          "EVT",
        "WMI":           "EVT",
        "Firewall":      "EVT",
        "Auth":          "LOG",
        "Syslog":        "LOG",
        "Kernel":        "LOG",
        "Process":       "PROC",
        "Prefetch":      "PF",
        "LastActivityView": "LAV",
    }
    source_type = source_type_map.get(source, "SOMBRA")

    notes = "FLAGGED" if flagged else ""

    return [
        date_part,                          # Date
        time_part,                          # Time
        "UTC",                              # Timezone (assume UTC)
        "",                                 # MACB
        source,                             # Source
        source_type,                        # SourceType
        f"Event {eid}" if eid else source,  # Type
        username,                           # User
        hostname,                           # Host
        description[:80],                   # Short description
        description,                        # Full description
        "",                                 # Version
        artifact,                           # Filename
        "",                                 # Inode
        notes,                              # Notes
        "Sombra",                           # Format
        eid,                                # Extra (Event ID)
    ]


def write_csv_timeline(
    case_dir:     Path,
    case_name:    str,
    hostname:     str,
    profile_name: str,
    events:       List[Dict],
    log,
) -> Path:
    """
    Write the Timeline Explorer compatible CSV timeline.

    Output is UTF-8 with BOM so Excel opens it correctly without
    requiring the user to specify encoding.

    Args:
        case_dir:     Path to the case output folder.
        case_name:    Case name string.
        hostname:     Target hostname.
        profile_name: Profile name.
        events:       Parsed and sorted event list.
        log:          Callable for status logging.

    Returns:
        Path to the written CSV file.
    """
    out = case_dir / "Sombra_Timeline.csv"

    # Use UTF-8 BOM for Excel compatibility
    with open(out, "w", encoding="utf-8-sig", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(HEADERS)
        for event in events:
            writer.writerow(_event_to_row(event))

    flagged = sum(1 for e in events if e.get("flagged"))
    log(f"  -> Saved: Sombra_Timeline.csv ({len(events):,} events — Timeline Explorer compatible)")
    return out
