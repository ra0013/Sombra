"""
engine/hasher.py
Gulf DataStream Labs — Sombra
SHA256 hashing, trusted toolset verification, and manifest generation.

Design principles:
  - Tools are hashed before execution (pre-run baseline)
  - Tools are re-hashed after collection (post-run verification)
  - All output files are hashed after collection
  - The triage script itself is hashed at startup
  - Hash_Manifest.txt is excluded from its own hash (self-referential
    hashing is not cryptographically meaningful; integrity of the manifest
    should be verified externally upon receipt)
"""

import hashlib
from datetime import datetime
from pathlib import Path
from typing import Dict, Optional


# ── Core hash function ────────────────────────────────────────────────────────
def sha256(path: Path) -> str:
    """
    Compute SHA256 hash of a file using 64KB read buffer.
    Handles large files without loading them fully into memory.

    Args:
        path: Path to the file to hash.

    Returns:
        Lowercase hex digest string (64 characters).

    Raises:
        FileNotFoundError: If the file does not exist.
        PermissionError:   If the file cannot be read.
    """
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def sha256_safe(path: Path) -> Optional[str]:
    """
    Compute SHA256 hash of a file, returning None on any failure.
    Use when a missing or unreadable file should not abort the run.

    Args:
        path: Path to the file to hash.

    Returns:
        Hex digest string or None on failure.
    """
    try:
        return sha256(path)
    except Exception:
        return None


# ── Trusted toolset registry ──────────────────────────────────────────────────
class ToolHashRegistry:
    """
    Tracks pre-run and post-run hashes for the script and all tools.

    Usage:
        registry = ToolHashRegistry(script_path)
        registry.register_tool(tool_path)      # call before execution
        registry.verify_all()                   # call after collection
    """

    def __init__(self, script_path: Path):
        """
        Initialize registry and immediately hash the triage script.

        Args:
            script_path: Path to the main Sombra script being run.
        """
        self._pre:  Dict[str, str] = {}
        self._post: Dict[str, str] = {}
        self._paths: Dict[str, Path] = {}

        # Hash the script itself at startup
        h = sha256_safe(script_path)
        if h:
            key = script_path.name
            self._pre[key]   = h
            self._paths[key] = script_path

    def register_tool(self, tool_path: Path) -> Optional[str]:
        """
        Hash a tool executable before use and register the baseline.

        Args:
            tool_path: Path to the tool executable.

        Returns:
            The SHA256 hash string, or None if file not found.
        """
        h = sha256_safe(tool_path)
        if h:
            key = tool_path.name
            self._pre[key]   = h
            self._paths[key] = tool_path
        return h

    def verify_all(self) -> Dict[str, bool]:
        """
        Re-hash all registered tools and compare against pre-run values.

        Returns:
            Dict mapping tool name to True (PASS) or False (FAIL).
        """
        results = {}
        for name, pre_hash in self._pre.items():
            path = self._paths.get(name)
            if path and path.exists():
                post_hash = sha256_safe(path)
                self._post[name] = post_hash or ""
                results[name] = (post_hash == pre_hash)
            else:
                results[name] = False
        return results

    def pre_hash(self, name: str) -> Optional[str]:
        """Return the pre-run hash for a registered item."""
        return self._pre.get(name)

    def post_hash(self, name: str) -> Optional[str]:
        """Return the post-run hash for a registered item."""
        return self._post.get(name)

    @property
    def pre_hashes(self) -> Dict[str, str]:
        """All pre-run hashes."""
        return dict(self._pre)


# ── Output file hashing ───────────────────────────────────────────────────────
def hash_output_files(case_dir: Path, exclude: str = "Hash_Manifest.txt") -> Dict[str, str]:
    """
    Compute SHA256 for every file in the case output folder.

    Args:
        case_dir: Path to the timestamped case folder.
        exclude:  Filename to skip (the manifest itself).

    Returns:
        Dict mapping filename to SHA256 hex digest.
    """
    hashes = {}
    for f in sorted(case_dir.iterdir()):
        if f.is_file() and f.name != exclude:
            h = sha256_safe(f)
            if h:
                hashes[f.name] = h
    return hashes


# ── Manifest writer ───────────────────────────────────────────────────────────
def write_manifest(
    manifest_path: Path,
    case_name:     str,
    hostname:      str,
    profile_name:  str,
    registry:      ToolHashRegistry,
    output_hashes: Dict[str, str],
    verify_results: Dict[str, bool],
) -> bool:
    """
    Write the complete hash manifest and return overall integrity status.

    Manifest sections:
      1. Header — case metadata
      2. Pre-run hashes — script + all tools
      3. Output file hashes — every file written during the run
      4. Post-run integrity check — pass/fail per item

    Args:
        manifest_path:   Path where Hash_Manifest.txt will be written.
        case_name:       Case name string.
        hostname:        Target hostname.
        profile_name:    Profile used for this run.
        registry:        ToolHashRegistry with pre/post hashes.
        output_hashes:   Dict of output file hashes.
        verify_results:  Dict of pass/fail results from registry.verify_all().

    Returns:
        True if all integrity checks passed, False if any failed.
    """
    all_pass = all(verify_results.values()) if verify_results else True
    lines = [
        "Sombra — Hash Manifest",
        f"Generated  : {datetime.now()}",
        f"Case       : {case_name}",
        f"Host       : {hostname}",
        f"Profile    : {profile_name}",
        "=" * 72,
        "",
        "--- PRE-RUN HASHES (SCRIPT + TOOLS) ---",
        "# Script hashed at startup. Tools hashed immediately before execution.",
    ]

    for name, h in registry.pre_hashes.items():
        lines.append(f"SHA256 | {name:40s} | {h}")

    lines += [
        "",
        "--- OUTPUT FILE HASHES ---",
        "# SHA-256 of every file written during this collection run.",
        "# Hash_Manifest.txt is excluded — self-referential hashing is not",
        "# cryptographically meaningful. Verify this manifest externally.",
    ]

    for name, h in output_hashes.items():
        lines.append(f"SHA256 | {name:40s} | {h}")

    lines += [
        "",
        "--- POST-RUN INTEGRITY CHECK ---",
        "# Script and tools re-hashed after collection.",
        "# PASS = unmodified during the run.",
        "# FAIL = hash changed — treat all findings from this item with suspicion.",
    ]

    for name, passed in verify_results.items():
        result = "PASS" if passed else "FAIL — MISMATCH DETECTED"
        lines.append(f"{result:35s} | {name}")
        if not passed:
            lines.append(f"  Pre-run  : {registry.pre_hash(name)}")
            lines.append(f"  Post-run : {registry.post_hash(name)}")

    lines += [
        "",
        f"Overall integrity: {'PASS — all items verified unchanged' if all_pass else 'FAIL — review mismatches above'}",
    ]

    try:
        manifest_path.write_text("\n".join(lines), encoding="utf-8")
    except OSError as e:
        print(f"[WARN] Could not write Hash_Manifest.txt: {e}")
        return False
    return all_pass
