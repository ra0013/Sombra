# Sombra
### Digital Forensics Collection Engine
**Gulf DataStream Labs**

---

## Overview

Sombra is a cross-platform incident response triage tool written in Python. It collects volatile and semi-volatile forensic artifacts from live Windows and Linux systems, following the trusted toolset methodology: every tool is hashed before execution and re-verified after collection. All output is hashed and recorded in a manifest for chain of custody.

**Designed for:**
- Solo consultants and small IR teams
- Law enforcement digital forensics units
- Internal IR teams without enterprise tooling
- Environments where KAPE, Velociraptor, or Cyber Triage are not available or appropriate

**Key differentiators:**
- Cross-platform — one script, Windows and Linux, no modification required
- Profile-driven — collection tuned to the investigation type
- No installation on target — run from USB drive (compiled exe) or existing Python
- Court-defensible chain of custody — pre/post tool integrity verification
- Three timeline output formats — HTML, Timeline Explorer CSV, Plaso L2T
- Tool filename configuration via `tools/tools.json` — no code changes required when staging tools

---

## Quick Start

### Compiled executable (recommended for engagements)
**Windows:**
```
sombra.exe
```
**Linux:**
```bash
sudo ./sombra
```
No Python required on the target. Download the latest release, verify the SHA256 against the release notes, and run from an elevated prompt.

### Python (development / lab use)
Requires Python 3.13+.
```bash
pip install rich psutil
python sombra.py          # Windows
sudo python3 sombra.py   # Linux
```

### CLI mode (scripted / automated)
```bash
python sombra.py --case "Case2025-001" --output "D:\IR" --profile ransomware
```

---

## Security Notice

Sombra is currently distributed as an unsigned executable. On first run Windows SmartScreen may display a warning — "Windows protected your PC." This is expected behavior for any unsigned executable downloaded from the internet and is not an indicator of malicious content.

**Before running, always verify the SHA256 hash against the value published in the release notes.** Hash verification is the correct way to establish trust in a forensic tool — a valid signature from an unknown vendor provides no stronger guarantee than a verified hash from a known source.

**To run on Windows after hash verification:**
1. Right-click `sombra.exe` → Properties
2. Check "Unblock" at the bottom of the General tab → Apply
3. Run from an elevated command prompt

Or from PowerShell:
```powershell
Unblock-File -Path .\sombra.exe
```

AV products may also flag PyInstaller-compiled executables generically. If your AV quarantines Sombra, add a path exclusion for your IR toolkit directory. Verify the hash first, then exclude it.

Code signing is planned for a future release.

---

## Menu

Sombra uses an interactive terminal menu. Run without arguments to enter the menu:

```
  [1]  Case setup       — set case name and output directory
  [2]  Check tools      — verify staged tool executables are present
  [3]  Run triage       — select profile, review toggles, and run
  [4]  Settings         — configure tool filenames without editing files
  [Q]  Quit
```

**Case setup (option 1)** must be completed before running triage. The case name and output directory persist across the menu session.

**Check tools (option 2)** scans the `tools/` directory and shows FOUND or MISSING for every configured tool. Use this after staging new tools to confirm they are detected correctly.

**Settings (option 4)** lets you view and update tool filenames interactively. Changes are saved immediately to `tools/tools.json`. Use this when a downloaded tool has a different filename than the default.

---

## Investigation Profiles

Profiles define which collection sections run and which indicators get flagged in the timeline. Select a profile at startup, then optionally toggle individual sections and tools before running.

| Profile | Description |
|---|---|
| `default` | Full collection — all sections enabled |
| `ransomware` | Shadow copy deletion, encryption activity, lateral staging |
| `lateral_movement` | Credential theft, remote execution, authentication anomalies |
| `insider_threat` | User activity, USB history, file access, browser history |
| `initial_access` | Phishing, macro execution, first-stage payload activity |
| `persistence_only` | Fast, lightweight — persistence mechanisms only |

Custom profiles can be created from the toggle screen and saved as JSON files in the `profiles/` directory.

---

## Collection Coverage

### Order of Volatility (RFC 3227)
Collections run in this order regardless of profile:

1. **Memory acquisition** — WinPmem, DumpIt, LiME, procdump, hiberfil (if enabled)
2. **Volatile artifacts** — running processes, network connections, login sessions
3. **Network state** — ARP cache, DNS cache, routing, firewall rules, hosts file
4. **Services and drivers** — services with executable paths, kernel drivers/modules
5. **Handles, DLLs, named pipes** — open file handles, loaded DLLs, named pipes
6. **Persistence mechanisms** — registry keys, BAM/DAM, scheduled tasks, WMI subscriptions, cron, SSH keys
7. **Artifacts** — event logs, prefetch, accounts, USB history
8. **Filesystem** — SUID/SGID binaries, Alternate Data Streams, suspicious files
9. **Software inventory** — installed packages
10. **Sysinternals tools** — profile-controlled
11. **Nirsoft tools** — profile-controlled
12. **Timeline generation** — HTML, CSV, L2T
13. **Hash manifest** — always last

### Windows Collection
| Category | Artifacts |
|---|---|
| Native commands | systeminfo, ipconfig, netstat, tasklist, net user/share/session, arp, route, schtasks |
| PowerShell/CIM | Win32_Service, firewall rules, 9 event log channels (Security, System, Application, PowerShell, TaskScheduler, RDP, BITS, WMI, Firewall) |
| Registry (winreg) | Run/RunOnce, IFEO, AppInit_DLLs, Winlogon, Active Setup, LSA, BAM/DAM, USBSTOR |
| Python | psutil processes + network, prefetch inventory, PowerShell history, startup folders |
| Sysinternals | autorunsc, pslist, sigcheck, handle, tcpvcon, listdlls, streams, pipelist, logonsessions, psloggedon, psinfo, procdump |
| Nirsoft | LastActivityView, BrowsingHistoryView |
| Memory | WinPmem, DumpIt, procdump (targeted), hiberfil |

### Linux Collection
| Category | Artifacts |
|---|---|
| System | uname, os-release, uptime, mounts, /etc/hosts |
| Network | ss/netstat, ip addr/route/neigh, arp, iptables/nftables, resolv.conf |
| Accounts | /etc/passwd, /etc/shadow, last, lastb, lastlog, who |
| Processes | psutil, ps auxf, /proc cmdline direct reads (bypasses argv[0] spoofing) |
| Persistence | cron (all users), systemd services/timers, shell startup files, SSH authorized_keys |
| Shell history | bash/zsh history sweep for all users |
| Logs | auth.log or /var/log/secure, syslog or /var/log/messages, dmesg, kern.log |
| Software | dpkg/rpm/pacman/apk package inventory, pip3 packages |
| Filesystem | SUID/SGID binary enumeration, recently modified system binaries, suspicious executables in /tmp |
| Memory | LiME (requires pre-compiled .ko for target kernel) |

---

## Trusted Toolset Methodology

Sombra implements the pre/post tool hashing methodology recommended by NIST SP 800-61r3:

1. The triage script itself is hashed at startup
2. Each third-party tool executable is hashed immediately before execution
3. After all collection completes, every item is re-hashed and compared
4. A PASS/FAIL result is recorded per item in `Hash_Manifest.txt`
5. All output files are SHA256 hashed and recorded in the manifest

`Hash_Manifest.txt` is excluded from its own hash — self-referential hashing is not cryptographically meaningful. Verify the manifest integrity externally upon receipt.

---

## Timeline Outputs

Three timeline files are generated automatically at the end of every run:

| File | Format | Use |
|---|---|---|
| `Sombra_Timeline.html` | Self-contained HTML | Open in any browser, offline |
| `Sombra_Timeline.csv` | UTF-8 CSV with BOM | Timeline Explorer, Excel |
| `Sombra_Timeline.l2t` | log2timeline CSV | Plaso, Timesketch |

The HTML timeline includes keyword search, source category filtering, and flagged event highlighting based on profile-specific suspicious indicators.

---

## Third-Party Tools

Sysinternals and Nirsoft tools must be placed in the `tools/` directory alongside the script. They are not included due to licensing terms.

Tool filenames are configured in `tools/tools.json`. If a downloaded tool has a different filename than the default, update the entry in `tools.json` or use the Settings menu (option 4) to change it without editing any files manually.

**Sysinternals** — https://learn.microsoft.com/en-us/sysinternals/downloads/
```
tools/
  autorunsc.exe       pslist.exe        sigcheck.exe      handle.exe
  tcpvcon.exe         listdlls.exe      streams.exe       pipelist.exe
  logonsessions.exe   PsLoggedon.exe    psinfo.exe        procdump.exe
```

**Nirsoft** — https://www.nirsoft.net/
```
tools/
  LastActivityView.exe      BrowsingHistoryView.exe
```

**Memory tools**
```
tools/
  go-winpmem_amd64_1.0-rc2_signed.exe    (https://github.com/Velocidex/WinPmem/releases)
  DumpIt.exe                              (copy x64\DumpIt.exe from the Comae toolkit)
                                          (https://www.magnetforensics.com/resources/magnet-dumpit-for-windows/)
```

Missing tools are flagged in the Check Tools menu and skipped gracefully during collection — the script runs without them.

---

## Dependencies

```bash
pip install rich psutil
```

| Package | Purpose | Required |
|---|---|---|
| `rich` | Terminal UI and progress display | Yes |
| `psutil` | Process and network enumeration | Recommended |

In production deployments, compile with PyInstaller to bundle all dependencies into a single executable:
```bash
pip install pyinstaller
pyinstaller sombra.spec
```
---

## Verify Release Integrity

Every release includes the SHA256 hash of the compiled executable in the release notes. Always verify before use on a target system.

**Windows:**
```powershell
Get-FileHash sombra.exe -Algorithm SHA256
```

**Linux:**
```bash
sha256sum sombra
```
---

## Usage

```
sombra.py [-h] [--case CASE] [--output OUTPUT] [--profile PROFILE]

optional arguments:
  --case     Case name (enables CLI mode, skips interactive menu)
  --output   Output directory (default: current working directory)
  --profile  Profile: default, ransomware, lateral_movement,
             insider_threat, initial_access, persistence_only
```

**Interactive mode** (no arguments): full menu with case setup, tool check, profile selection, and toggle screen

**CLI mode** (`--case` specified): runs immediately with the given profile, no interaction required

---

## Output Structure

```
<output_dir>/
  <case_name>_<YYYYMMDD_HHMMSS>/
    01_processes.json
    02_network_connections.json
    ...
    Sombra_Timeline.html
    Sombra_Timeline.csv
    Sombra_Timeline.l2t
    Hash_Manifest.txt
```

Output directory must have sufficient free space. Memory acquisition requires space equal to installed RAM. All other collections typically require a small amount of storage depending on system activity and profile selection. If the output drive runs out of space during collection, Sombra logs a warning per file and continues — the run completes gracefully with whatever could be written.

---

## Platform Support

| Platform | Versions | Notes |
|---|---|---|
| Windows | 10, 11, Server 2016+ | Full collection including Sysinternals and Nirsoft |
| Linux | Any modern distribution | Sysinternals and Nirsoft not available |
| macOS | Not supported | — |

---

## Known Limitations

- **LiME** requires pre-compilation for the specific kernel version running on the target - it cannot be included as a generic binary
- **hiberfil acquisition** forces a full hibernate/resume cycle - the system will shut down and restart; do not use when session continuity matters - disabled by default
- **Memory acquisition** requires free space on the output drive equal to installed RAM - plan accordingly
- **Sysinternals and Nirsoft** are Windows only - Linux collection uses native commands and Python
- **psutil** is optional - if not installed, process and network connection sections are skipped
- **PyInstaller executables** are unsigned and may be flagged by AV products - see Security Notice

---

## References

- Nelson, A., Rekhi, S., Souppaya, M., & Scarfone, K. (2025). *Incident response recommendations and considerations for cybersecurity risk management: A CSF 2.0 community profile* (NIST Special Publication 800-61r3). https://doi.org/10.6028/NIST.SP.800-61r3
- Sysinternals. Microsoft. https://learn.microsoft.com/en-us/sysinternals/
- Sofer, N. NirSoft utilities. https://www.nirsoft.net/
- Velocidex. (2024). *WinPmem — The multi-platform memory acquisition tool*. https://github.com/Velocidex/WinPmem

---

## License

MIT License - free for all use including commercial engagements.

---

*Raul Vallejo — Gulf DataStream Labs — Rio Grande Valley, Texas*
