"""
collect/memory.py
Gulf DataStream Labs — Sombra
Memory acquisition — full system and process-level.

Memory acquisition captures volatile data that exists nowhere else:
  - Decrypted keys and credentials (Mimikatz targets this)
  - In-memory malware (fileless malware has no disk presence)
  - Active network connections at the time of acquisition
  - Running processes including those hidden from the OS
  - Encryption keys for ransomware recovery

Supported acquisition methods (in order of preference):
  WinPmem    — open source, free, court-defensible, recommended
  DumpIt     — Comae/Magnet, widely accepted, requires license
  Magnet RAM — free for LE/enterprise, GUI but has CLI mode
  procdump   — targeted single-process dump (Sysinternals)
  hiberfil   — hibernation image, zero-dep, requires reboot cycle

WARNING: Memory acquisition can take 5-30 minutes depending on
         RAM size and storage speed. Plan accordingly.

WARNING: hiberfil acquisition forces a hibernate/resume cycle.
         Do NOT use on systems where session continuity matters.
         All other work should be saved before enabling this option.
"""

import shutil
import subprocess
import time
from pathlib import Path
from typing import Optional

from engine.platform import IS_WIN, IS_LINUX, run, save_text
from engine.hasher import ToolHashRegistry
from engine.tools import ToolConfig


# ── WinPmem ───────────────────────────────────────────────────────────────────

def acquire_winpmem(
    case_dir: Path,
    tools_dir: Path,
    registry: ToolHashRegistry,
    log
) -> Optional[Path]:
    """
    Acquire full physical memory using WinPmem.

    WinPmem is the recommended memory acquisition tool for Sombra:
      - Open source (Apache 2.0)
      - Free for all use including commercial engagements
      - Outputs raw memory image (.raw or .aff4)
      - Accepted by courts and recognized by major forensic tools
      - Works on Windows 7 through Windows 11

    Download: https://github.com/Velocidex/WinPmem/releases

    Output: memory.raw in the case folder.
    Size:   Equal to installed RAM (4GB RAM = 4GB file).

    Args:
        case_dir:  Path to the case output folder.
        tools_dir: Path to the tools directory.
        registry:  ToolHashRegistry for pre-run hashing.
        log:       Callable for status logging.
    """
    if not IS_WIN:
        return None

    tc = ToolConfig(tools_dir)
    winpmem = tc.get("memory", "winpmem")
    if not winpmem:
        log(f"  [WARN] winpmem not found — check tools/tools.json", "WARN")
        log(f"         Configured as: {tc.filename('memory', 'winpmem')}")
        return None

    registry.register_tool(winpmem)
    output_path = case_dir / "memory.raw"

    log("  Acquiring full memory with WinPmem — this may take several minutes...")
    log(f"  Output: {output_path}")

    name = winpmem.name.lower()
    if "go-winpmem" in name or name.startswith("go-"):
        cmd = [str(winpmem), "acquire", str(output_path)]
    else:
        cmd = [str(winpmem), str(output_path)]

    result = run(cmd, timeout=3600)

    save_text(case_dir / "memory_winpmem_log.txt", result)

    if output_path.exists():
        size_mb = output_path.stat().st_size // (1024 * 1024)
        log(f"  -> Saved: memory.raw ({size_mb:,} MB)")
        return output_path

    log("  [WARN] WinPmem output file not found after acquisition", "WARN")
    return None


# ── DumpIt ────────────────────────────────────────────────────────────────────

def acquire_dumpit(
    case_dir: Path,
    tools_dir: Path,
    registry: ToolHashRegistry,
    log
) -> Optional[Path]:
    """
    Acquire full physical memory using DumpIt (Comae/Magnet).

    DumpIt is widely used and accepted in legal proceedings. The free
    community edition is available from Magnet Forensics. Commercial
    license required for some use cases.

    Download: https://www.magnetforensics.com/resources/magnet-dumpit-for-windows/

    Output: <hostname>_<date>_<time>.raw in the current directory.
            Sombra moves it to the case folder after acquisition.

    Args:
        case_dir:  Path to the case output folder.
        tools_dir: Path to the tools directory.
        registry:  ToolHashRegistry for pre-run hashing.
        log:       Callable for status logging.
    """
    if not IS_WIN:
        return None

    tc = ToolConfig(tools_dir)
    dumpit = tc.get("memory", "dumpit")
    if not dumpit:
        log(f"  [WARN] DumpIt not found — check tools/tools.json", "WARN")
        return None

    registry.register_tool(dumpit)
    log("  Acquiring full memory with DumpIt — this may take several minutes...")

    result = run(
        [str(dumpit), "/Q", "/O", str(case_dir / "memory_dumpit.raw")],
        timeout=3600
    )
    save_text(case_dir / "memory_dumpit_log.txt", result)

    # DumpIt may output to current directory — find and move
    output = case_dir / "memory_dumpit.raw"
    if output.exists():
        size_mb = output.stat().st_size // (1024 * 1024)
        log(f"  -> Saved: memory_dumpit.raw ({size_mb:,} MB)")
        return output

    # Search for DumpIt output in current directory
    for f in Path(".").glob("*.raw"):
        dest = case_dir / "memory_dumpit.raw"
        shutil.move(str(f), str(dest))
        size_mb = dest.stat().st_size // (1024 * 1024)
        log(f"  -> Saved: memory_dumpit.raw ({size_mb:,} MB)")
        return dest

    log("  [WARN] DumpIt output not found", "WARN")
    return None


# ── LiME (Linux Memory Extractor) ────────────────────────────────────────────

def acquire_lime(case_dir: Path, log) -> Optional[Path]:
    """
    Acquire Linux memory using LiME (Linux Memory Extractor).

    LiME is a loadable kernel module (LKM) that acquires physical memory
    with minimal footprint. It must be compiled for the specific kernel
    version running on the target — it cannot be included pre-compiled.

    This function checks if LiME is available and provides guidance
    if it is not.

    Download: https://github.com/504ensicsLabs/LiME

    Args:
        case_dir: Path to the case output folder.
        log:      Callable for status logging.
    """
    if not IS_LINUX:
        return None

    # Check if LiME .ko file exists in tools directory
    tools_dir = Path(__file__).parent.parent / "tools"
    lime_files = list(tools_dir.glob("lime*.ko"))

    if not lime_files:
        log("  [WARN] LiME kernel module not found in tools directory", "WARN")
        log("         LiME must be compiled for your specific kernel version.")
        log("         See: https://github.com/504ensicsLabs/LiME")
        save_text(
            case_dir / "memory_lime_status.txt",
            "LiME kernel module not found. Compile LiME for kernel: "
            + run(["uname", "-r"])
        )
        return None

    lime_ko = lime_files[0]
    output_path = case_dir / "memory.lime"

    log(f"  Loading LiME module: {lime_ko.name}")
    log(f"  Output: {output_path}")

    result = run(
        ["insmod", str(lime_ko), f"path={output_path}", "format=lime"],
        timeout=3600
    )
    save_text(case_dir / "memory_lime_log.txt", result)

    # Give LiME time to complete acquisition
    time.sleep(5)

    # Unload the module after acquisition
    run(["rmmod", "lime"], timeout=30)

    if output_path.exists():
        size_mb = output_path.stat().st_size // (1024 * 1024)
        log(f"  -> Saved: memory.lime ({size_mb:,} MB)")
        return output_path

    log("  [WARN] LiME output not found after acquisition", "WARN")
    return None


# ── Hiberfil ──────────────────────────────────────────────────────────────────

def acquire_hiberfil(case_dir: Path, log) -> Optional[Path]:
    """
    Acquire a compressed memory image via Windows hibernation.

    Hiberfil.sys is created when Windows hibernates and contains a
    compressed snapshot of RAM. It can be analyzed with Volatility3
    after conversion using Hibernation Recon or vol.py.

    WARNING: This forces the system into hibernation and back.
    - The system WILL shut down and restart.
    - ALL other work on this machine will be interrupted.
    - Only use when live acquisition is not possible.
    - Ensure the case folder is on an external drive before running.

    After resume, hiberfil.sys is copied to the case folder.

    Args:
        case_dir: Path to the case output folder.
        log:      Callable for status logging.
    """
    if not IS_WIN:
        return None

    hiberfil = Path(r"C:\hiberfil.sys")
    dest = case_dir / "hiberfil.sys"

    # Enable hibernation if not already enabled
    log("  Enabling hibernation...")
    run(["powercfg", "/hibernate", "on"], timeout=15)
    time.sleep(2)

    log("  !! SYSTEM WILL HIBERNATE IN 5 SECONDS !!")
    log("  !! RESUME WILL OCCUR AUTOMATICALLY    !!")
    time.sleep(5)

    # Trigger hibernation
    result = run(["shutdown", "/h"], timeout=10)

    # On resume, copy hiberfil.sys
    time.sleep(30)  # Allow system to fully resume

    if hiberfil.exists():
        log("  Copying hiberfil.sys to case folder...")
        try:
            shutil.copy2(str(hiberfil), str(dest))
            size_mb = dest.stat().st_size // (1024 * 1024)
            log(f"  -> Saved: hiberfil.sys ({size_mb:,} MB)")
            return dest
        except Exception as e:
            log(f"  [WARN] Could not copy hiberfil.sys: {e}", "WARN")
            return None

    log("  [WARN] hiberfil.sys not found after resume", "WARN")
    return None


# ── Entry point ───────────────────────────────────────────────────────────────

def run_memory(
    case_dir: Path,
    tools_dir: Path,
    registry: ToolHashRegistry,
    profile,
    log
) -> list:
    """
    Run memory acquisition based on profile settings.

    At most one full-memory acquisition method runs per session.
    Priority order: WinPmem → DumpIt → hiberfil.
    procdump runs independently if a PID is specified.

    Args:
        case_dir:  Path to the timestamped case output folder.
        tools_dir: Path to the tools directory.
        registry:  ToolHashRegistry for pre-run hashing.
        profile:   Active Profile instance.
        log:       Callable for status logging.

    Returns:
        List of Path objects for all files written.
    """
    written = []

    if not profile.any_memory_enabled():
        return written

    log("Memory acquisition enabled — starting...")

    if IS_WIN:
        if profile.memory_enabled("winpmem"):
            p = acquire_winpmem(case_dir, tools_dir, registry, log)
            if p:
                written.append(p)
                return written  # One full acquisition is enough

        if profile.memory_enabled("dumpit"):
            p = acquire_dumpit(case_dir, tools_dir, registry, log)
            if p:
                written.append(p)
                return written

        if profile.memory_enabled("hiberfil"):
            log("  [WARN] Hiberfil acquisition will force a system hibernate/resume cycle", "WARN")
            p = acquire_hiberfil(case_dir, log)
            if p:
                written.append(p)

    elif IS_LINUX:
        p = acquire_lime(case_dir, log)
        if p:
            written.append(p)

    return written
