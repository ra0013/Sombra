"""
engine/tools.py
Gulf DataStream Labs — Sombra
Tool configuration loader.

Reads tools/tools.json to resolve actual filenames for each tool slot.
This allows analysts to rename downloaded tools without editing source code —
just update tools.json to match whatever filename is on disk.

If tools.json is missing, falls back to sensible defaults so the tool
works out of the box without any configuration.
"""

import json
from pathlib import Path
from typing import Optional

# Default tool filename map — used when tools.json is absent or incomplete
_DEFAULTS = {
    "sysinternals": {
        "autorunsc":     "autorunsc.exe",
        "pslist":        "pslist.exe",
        "sigcheck":      "sigcheck.exe",
        "handle":        "handle.exe",
        "tcpvcon":       "tcpvcon.exe",
        "listdlls":      "listdlls.exe",
        "streams":       "streams.exe",
        "pipelist":      "pipelist.exe",
        "logonsessions": "logonsessions.exe",
        "psloggedon":    "PsLoggedon.exe",
        "psinfo":        "psinfo.exe",
        "procdump":      "procdump.exe",
    },
    "nirsoft": {
        "lastactivityview": "LastActivityView.exe",
        "browsinghistory":  "BrowsingHistoryView.exe",
    },
    "memory": {
        "winpmem":  "go-winpmem_amd64_1.0-rc2_signed.exe",
        "dumpit":   "DumpIt.exe",
        "procdump": "procdump.exe",
    },
}


class ToolConfig:
    """
    Resolves tool slot names to actual file paths on disk.

    Usage:
        config = ToolConfig(tools_dir)
        path = config.get("sysinternals", "autorunsc")
        # Returns Path or None if file not found
    """

    def __init__(self, tools_dir: Path):
        self.tools_dir = tools_dir
        self._config   = self._load(tools_dir / "tools.json")

    def _load(self, config_path: Path) -> dict:
        """Load tools.json, merging with defaults for any missing keys."""
        config = {}
        # Start with defaults
        for category, tools in _DEFAULTS.items():
            config[category] = dict(tools)

        # Override with tools.json if present
        if config_path.exists():
            try:
                data = json.loads(config_path.read_text(encoding="utf-8"))
                for category in ["sysinternals", "nirsoft", "memory"]:
                    if category in data and isinstance(data[category], dict):
                        config[category].update(data[category])
            except Exception:
                pass  # Malformed JSON — fall back to defaults silently

        return config

    def get(self, category: str, slug: str) -> Optional[Path]:
        """
        Return the Path for a tool if the file exists on disk.

        Args:
            category: "sysinternals", "nirsoft", or "memory"
            slug:     Tool slot name (e.g. "autorunsc", "winpmem")

        Returns:
            Path to the tool executable, or None if not found.
        """
        filename = self._config.get(category, {}).get(slug)
        if not filename:
            return None
        p = self.tools_dir / filename
        return p if p.exists() else None

    def get_all(self, category: str) -> dict:
        """
        Return a dict of slug -> Path for all tools in a category.
        Only includes tools whose files actually exist on disk.

        Args:
            category: "sysinternals", "nirsoft", or "memory"

        Returns:
            Dict mapping slug to Path for present tools.
        """
        result = {}
        for slug in self._config.get(category, {}):
            p = self.get(category, slug)
            if p:
                result[slug] = p
        return result

    def filename(self, category: str, slug: str) -> Optional[str]:
        """Return the configured filename string for a tool slot."""
        return self._config.get(category, {}).get(slug)

    def check_tools(self) -> dict:
        """
        Check all configured tools and return their status.

        Returns:
            Dict mapping "category/slug" to {"filename": str, "found": bool, "path": Path|None}
        """
        results = {}
        for category in ["sysinternals", "nirsoft", "memory"]:
            for slug, filename in self._config.get(category, {}).items():
                p = self.tools_dir / filename
                results[f"{category}/{slug}"] = {
                    "filename": filename,
                    "found":    p.exists(),
                    "path":     p if p.exists() else None,
                }
        return results

    def save(self):
        """Write the current config back to tools.json."""
        # Strip internal keys before saving
        out = {
            k: v for k, v in self._config.items()
            if not k.startswith("_")
        }
        config_path = self.tools_dir / "tools.json"
        config_path.write_text(
            json.dumps(out, indent=2),
            encoding="utf-8"
        )
