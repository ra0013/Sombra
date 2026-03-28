"""
engine/platform.py
Gulf DataStream Labs — Sombra
Platform detection, elevation checks, and cross-platform utilities.
"""

import ctypes
import hashlib
import json
import os
import platform
import subprocess
import sys
from datetime import datetime
from pathlib import Path
from typing import Optional

# ── Platform flags ────────────────────────────────────────────────────────────
SYSTEM    = platform.system()
IS_WIN    = SYSTEM == "Windows"
IS_LINUX  = SYSTEM == "Linux"
IS_MAC    = SYSTEM == "Darwin"
HOSTNAME  = platform.node()
PLATFORM  = f"{SYSTEM} {platform.release()}"
ARCH      = platform.machine()


# ── Elevation ─────────────────────────────────────────────────────────────────
def is_elevated() -> bool:
    """Return True if running with administrative / root privileges."""
    if IS_WIN:
        try:
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except Exception:
            return False
    return os.geteuid() == 0


def elevation_label() -> str:
    """Return a human-readable elevation status string."""
    return "Administrator" if is_elevated() else "Standard User"


# ── Subprocess helpers ────────────────────────────────────────────────────────
def run(cmd: list, timeout: int = 30) -> str:
    """
    Execute a command and return combined stdout + stderr.
    Never raises — returns an error marker string on any failure.

    Args:
        cmd:     Command as a list of strings.
        timeout: Maximum seconds to wait.

    Returns:
        Output string or error marker.
    """
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            errors="replace",
        )
        return (result.stdout + result.stderr).strip()
    except FileNotFoundError:
        return f"[NOT FOUND] {' '.join(cmd)}"
    except subprocess.TimeoutExpired:
        return f"[TIMEOUT] {' '.join(cmd)}"
    except Exception as e:
        return f"[ERROR] {e}"


def ps(cmd: str, timeout: int = 60) -> str:
    """
    Execute a PowerShell command (Windows only).
    Uses -NonInteractive to prevent hanging on prompts.

    Args:
        cmd:     PowerShell command string.
        timeout: Maximum seconds to wait.

    Returns:
        Output string or error marker.
    """
    return run(
        ["powershell", "-NonInteractive", "-Command", cmd],
        timeout=timeout,
    )


def which(name: str) -> bool:
    """Return True if a command exists on PATH."""
    import shutil
    return shutil.which(name) is not None


# ── File I/O helpers ──────────────────────────────────────────────────────────
def save_text(path: Path, content: str) -> Path:
    """Write a string to a file, creating parent directories as needed."""
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8", errors="replace")
        return path
    except OSError as e:
        print(f"[WARN] Could not write {path.name}: {e}")
        return None


def save_json(path: Path, data) -> Path:
    """Serialize data to formatted JSON and write to a file."""
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            json.dumps(data, indent=2, default=str),
            encoding="utf-8",
        )
        return path
    except OSError as e:
        print(f"[WARN] Could not write {path.name}: {e}")
        return None


def load_json(path: Path):
    """Load and parse a JSON file. Returns None on failure."""
    try:
        return json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except Exception:
        return None


# ── Timestamp helpers ─────────────────────────────────────────────────────────
def now_str() -> str:
    """Return current datetime as YYYY-MM-DD HH:MM:SS."""
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def timestamp_folder() -> str:
    """Return a timestamp string suitable for use in folder names."""
    return datetime.now().strftime("%Y%m%d_%H%M%S")


def from_epoch(ts) -> str:
    """Convert an epoch timestamp to a readable string. Returns '' on failure."""
    try:
        return datetime.fromtimestamp(float(ts)).strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        return ""


# ── System info ───────────────────────────────────────────────────────────────
def system_info() -> dict:
    """Return a dict of basic system identification values."""
    return {
        "hostname":  HOSTNAME,
        "platform":  PLATFORM,
        "arch":      ARCH,
        "system":    SYSTEM,
        "elevated":  is_elevated(),
        "python":    sys.version.split()[0],
        "collected": now_str(),
    }
