"""
engine/profile.py
Gulf DataStream Labs — Sombra
Profile loading, validation, and runtime toggle management.

Profiles define the default collection configuration for a given
investigation type. The analyst selects a profile at startup, then
optionally modifies individual toggles before running collection.
All modifications are in-memory only — the profile file is never
modified unless the analyst explicitly saves a custom profile.
"""

import copy
import json
from pathlib import Path
from typing import Optional

# Profiles directory — relative to this file's location
# Handles both development (source tree) and PyInstaller compiled exe
import sys as _sys

def _get_profiles_dir() -> Path:
    """
    Return the profiles directory path.
    Works in both development mode and PyInstaller compiled builds.
    PyInstaller extracts bundled data to sys._MEIPASS at runtime.
    """
    if getattr(_sys, 'frozen', False) and hasattr(_sys, '_MEIPASS'):
        # Running as compiled exe — data is in the temp extraction directory
        return Path(_sys._MEIPASS) / "profiles"
    # Running from source
    return Path(__file__).parent.parent / "profiles"

PROFILES_DIR = _get_profiles_dir()

# Built-in profile order for display in the menu
PROFILE_ORDER = [
    "default",
    "ransomware",
    "lateral_movement",
    "insider_threat",
    "initial_access",
    "persistence_only",
]


class Profile:
    """
    Represents a loaded and optionally modified investigation profile.

    Attributes:
        name:         Display name (e.g. "Ransomware")
        description:  One-line description of the profile's purpose
        sections:     Dict of section_name -> enabled (bool)
        sysinternals: Dict of tool_name -> enabled (bool)
        nirsoft:      Dict of tool_name -> enabled (bool)
        memory:       Dict of memory tool settings
        flag_keywords:  List of suspicious keyword strings
        flag_event_ids: List of suspicious Windows Event IDs
    """

    def __init__(self, data: dict):
        self.name          = data.get("name", "Unknown")
        self.description   = data.get("description", "")
        self.sections      = data.get("sections", {})
        self.sysinternals  = data.get("sysinternals", {})
        self.nirsoft       = data.get("nirsoft", {})
        self.memory        = data.get("memory", {})
        self.flag_keywords = data.get("flag_keywords", [])
        self.flag_event_ids= set(data.get("flag_event_ids", []))
        self._source_file: Optional[Path] = None

    # ── Toggle methods ────────────────────────────────────────────────────────

    def toggle_section(self, section: str, enabled: bool):
        """Enable or disable a collection section."""
        if section in self.sections:
            self.sections[section] = enabled

    def toggle_sysinternals(self, tool: str, enabled: bool):
        """Enable or disable a Sysinternals tool."""
        if tool in self.sysinternals:
            self.sysinternals[tool] = enabled

    def toggle_nirsoft(self, tool: str, enabled: bool):
        """Enable or disable a Nirsoft tool."""
        if tool in self.nirsoft:
            self.nirsoft[tool] = enabled

    def toggle_memory(self, tool: str, enabled: bool):
        """Enable or disable a memory acquisition tool."""
        if tool in self.memory:
            self.memory[tool] = enabled

    def set_procdump_pid(self, pid: Optional[int]):
        """Set the target PID for procdump (None = full memory)."""
        self.memory["procdump_pid"] = pid

    # ── Query methods ─────────────────────────────────────────────────────────

    def section_enabled(self, section: str) -> bool:
        """Return True if a collection section is enabled."""
        return bool(self.sections.get(section, False))

    def tool_enabled(self, tool: str) -> bool:
        """Return True if a Sysinternals tool is enabled."""
        return bool(self.sysinternals.get(tool, False))

    def nirsoft_enabled(self, tool: str) -> bool:
        """Return True if a Nirsoft tool is enabled."""
        return bool(self.nirsoft.get(tool, False))

    def memory_enabled(self, tool: str) -> bool:
        """Return True if a memory acquisition tool is enabled."""
        return bool(self.memory.get(tool, False))

    def any_memory_enabled(self) -> bool:
        """Return True if any memory acquisition is enabled."""
        return any(
            self.memory.get(t, False)
            for t in ["winpmem", "dumpit", "procdump", "hiberfil"]
        )

    def is_suspicious_keyword(self, text: str) -> bool:
        """Return True if any flag keyword appears in the text."""
        text_lower = text.lower()
        return any(kw in text_lower for kw in self.flag_keywords)

    def is_suspicious_event_id(self, eid) -> bool:
        """Return True if an event ID is in the flagged set."""
        try:
            return int(eid) in self.flag_event_ids
        except (TypeError, ValueError):
            return False

    def is_suspicious(self, description: str = "", eid=None) -> bool:
        """Return True if an event matches any suspicious indicator."""
        return (
            self.is_suspicious_keyword(description) or
            (eid is not None and self.is_suspicious_event_id(eid))
        )

    # ── Serialization ─────────────────────────────────────────────────────────

    def to_dict(self) -> dict:
        """Return the profile as a serializable dict."""
        return {
            "name":           self.name,
            "description":    self.description,
            "sections":       self.sections,
            "sysinternals":   self.sysinternals,
            "nirsoft":        self.nirsoft,
            "memory":         self.memory,
            "flag_keywords":  self.flag_keywords,
            "flag_event_ids": sorted(self.flag_event_ids),
        }

    def save_as(self, path: Path):
        """Save the current profile state to a JSON file."""
        path.write_text(
            json.dumps(self.to_dict(), indent=2),
            encoding="utf-8"
        )

    def clone(self) -> "Profile":
        """Return a deep copy of this profile for runtime modification."""
        return Profile(copy.deepcopy(self.to_dict()))

    def __repr__(self):
        return f"<Profile name={self.name!r}>"


# ── Profile loader ────────────────────────────────────────────────────────────

def load_profile(path: Path) -> Optional[Profile]:
    """
    Load a profile from a JSON file.

    Args:
        path: Path to the .json profile file.

    Returns:
        Profile instance, or None if the file cannot be loaded.
    """
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        p = Profile(data)
        p._source_file = path
        return p
    except Exception:
        return None


def load_all_profiles() -> dict:
    """
    Load all profiles from the profiles directory.

    Returns:
        Dict mapping slug (filename stem) to Profile instance.
        Built-in profiles appear first in PROFILE_ORDER, then
        any additional custom profiles alphabetically.
    """
    profiles = {}

    # Load built-in profiles in defined order
    for slug in PROFILE_ORDER:
        path = PROFILES_DIR / f"{slug}.json"
        if path.exists():
            p = load_profile(path)
            if p:
                profiles[slug] = p

    # Load any additional custom profiles not in PROFILE_ORDER
    for path in sorted(PROFILES_DIR.glob("*.json")):
        slug = path.stem
        if slug not in profiles:
            p = load_profile(path)
            if p:
                profiles[slug] = p

    return profiles


def get_profile(slug: str) -> Optional[Profile]:
    """
    Load a single profile by its slug (filename stem).

    Args:
        slug: Profile filename without extension (e.g. "ransomware")

    Returns:
        Profile instance or None if not found.
    """
    path = PROFILES_DIR / f"{slug}.json"
    if path.exists():
        return load_profile(path)
    return None
