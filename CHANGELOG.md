# Changelog — Sombra
Gulf DataStream Labs

All notable changes to Sombra are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

---

## [1.0.0] — 2026-03-27

### Added
- Cross-platform collection engine — Windows and Linux from a single script
- Six investigation profiles: default, ransomware, lateral_movement,
  insider_threat, initial_access, persistence_only
- Profile-driven collection — only runs sections relevant to the investigation type
- Runtime toggle screen — modify any section or tool setting before running
- Custom profile save/load — save modified configurations for reuse
- Order-of-volatility collection sequence (RFC 3227)
- Pre/post tool integrity verification (NIST SP 800-61r3 trusted toolset methodology)
- SHA256 hash manifest covering script, tools, and all output files
- Three timeline output formats: HTML (native), CSV (Timeline Explorer), L2T (Plaso)
- HTML timeline with keyword search, source filtering, and flagged event highlighting
- Rich terminal UI — works over SSH, RDP console, and PsExec sessions
- CLI mode for scripted and automated deployment

### Windows collections
- Native commands: systeminfo, ipconfig, netstat, tasklist, net user/share/session,
  arp, route, schtasks, dns cache
- PowerShell/CIM: Win32_Service, firewall rules
- Event logs: Security, System, Application, PowerShell/Operational,
  TaskScheduler, RDP, BITS, WMI Activity, Firewall (9 channels)
- Registry persistence: Run/RunOnce (HKLM + HKCU + WOW64), IFEO, AppInit_DLLs,
  Winlogon, Active Setup, LSA
- BAM/DAM execution timestamps
- Prefetch file inventory
- PowerShell ConsoleHost_history.txt sweep (all users)
- WMI event subscriptions (filter, consumer, binding)
- Startup folder enumeration
- USB device history (USBSTOR registry)
- Installed software (registry uninstall keys, 64-bit + 32-bit + per-user)
- Suspicious file search (executables in temp/AppData locations)
- Alternate Data Streams enumeration (PowerShell fallback)
- Sysinternals tool wrappers: autorunsc, pslist, sigcheck, handle, tcpvcon,
  listdlls, streams, pipelist, logonsessions, psloggedon, psinfo, procdump
- Nirsoft tool wrappers: LastActivityView, BrowsingHistoryView
- Memory acquisition: WinPmem, DumpIt, procdump (targeted), hiberfil

### Linux collections
- System: uname, os-release, uptime, hostname, mounts, df, /etc/hosts
- Network: ss/netstat, ip addr/route/neigh, arp, iptables/nftables, resolv.conf
- Accounts: /etc/passwd, /etc/shadow, /etc/group, last, lastb, lastlog, who, w
- Processes: psutil, ps auxf, /proc cmdline direct reads (bypasses argv[0] spoofing)
- Persistence: cron (all users + /etc/cron.d), systemd services/timers,
  shell startup files (.bashrc/.zshrc/etc.), SSH authorized_keys sweep
- Shell history: bash/zsh history sweep for all users including root
- Logs: auth.log or /var/log/secure, syslog or /var/log/messages, dmesg, kern.log
- Software: dpkg/rpm/pacman/apk inventory, pip3 packages
- Filesystem: SUID/SGID binary enumeration, recently modified system binaries,
  executable files in world-writable directories
- Memory: LiME kernel module (requires pre-compiled .ko for target kernel)
- Kernel modules: lsmod + modinfo for all loaded modules

---

## Planned — [1.1.0]

- Registry hive acquisition (SAM, SYSTEM, SOFTWARE, SECURITY, NTUSER.dat)
- Prefetch binary parsing (not just inventory — execution counts, load order)
- SRUM database (srudb.dat) — execution and network usage history
- AmCache.hve — gold standard execution evidence
- Browser history collection (Chrome, Firefox, Edge SQLite databases)
- LNK file and Jump List collection
- Windows Search database (Windows.db)
- Shellbag enumeration
- Container environment detection (Docker/LXC artifacts)
- auditd log collection (Linux)
- PAM configuration sweep (Linux)
- PyInstaller build pipeline with automated SHA256 release notes

---

## Planned — [2.0.0]

- KAPE-compatible target definitions (YAML) for interoperability
- Automated suspicious indicator scoring
- SIEM output format (JSON-LD / Elastic Common Schema)
- Volatility3 integration for automated memory analysis
- Remote collection mode (agent-free, over SSH/WinRM)
