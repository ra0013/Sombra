"""
collect/network.py
Gulf DataStream Labs — Sombra
Network state artifacts — collected second per order of volatility.

  ARP cache       — recently communicated hosts (changes frequently)
  DNS cache       — recently resolved domains (C2 indicators)
  Routing table   — unexpected routes indicate traffic redirection
  Firewall rules  — unauthorized allow rules indicate attacker access
  Network config  — adapter config, DHCP state, DNS suffix

These change less rapidly than process state but still represent
volatile data that will be lost on reboot or after time passes.
"""

from pathlib import Path
from typing import Optional

from engine.platform import IS_WIN, IS_LINUX, run, ps, save_text, save_json


# ── ARP cache ────────────────────────────────────────────────────────────────

def collect_arp(case_dir: Path) -> Path:
    """
    Collect the ARP cache — recently communicated hosts on the local network.

    The ARP cache reveals other machines this host has communicated with
    recently. In a lateral movement scenario, attacker-touched machines
    will appear here even if no active connections remain.

    Args:
        case_dir: Path to the case output folder.
    """
    if IS_WIN:
        return save_text(case_dir / "05_arp.txt", run(["arp", "-a"]))
    return save_text(case_dir / "05_arp.txt", run(["arp", "-n"]))


# ── DNS cache ─────────────────────────────────────────────────────────────────

def collect_dns_cache(case_dir: Path) -> Path:
    """
    Collect the DNS resolver cache.

    Malware frequently connects to C2 domains. Even after the connection
    closes, the resolved IP remains in the DNS cache. This is one of the
    fastest ways to identify C2 infrastructure from a live system.

    Windows only — Linux does not maintain a local DNS cache by default
    unless nscd or systemd-resolved is running.

    Args:
        case_dir: Path to the case output folder.
    """
    if IS_WIN:
        return save_text(
            case_dir / "06_dns_cache.txt",
            run(["ipconfig", "/displaydns"])
        )
    # Linux: try systemd-resolved first, then nscd
    if IS_LINUX:
        out = run(["resolvectl", "statistics"], timeout=5)
        if "[NOT FOUND]" not in out and "[ERROR]" not in out:
            return save_text(case_dir / "06_dns_cache.txt", out)
        return save_text(
            case_dir / "06_dns_cache.txt",
            "(DNS cache not available — systemd-resolved or nscd not running)"
        )
    return save_text(case_dir / "06_dns_cache.txt", "[UNSUPPORTED PLATFORM]")


# ── Routing table ─────────────────────────────────────────────────────────────

def collect_routing(case_dir: Path) -> Path:
    """
    Collect the IP routing table.

    Attackers may add routes to redirect traffic through a compromised
    gateway or to route specific subnets through their infrastructure.
    Comparing against a known-good baseline is ideal but not always
    possible — look for unexpected gateway entries.

    Args:
        case_dir: Path to the case output folder.
    """
    if IS_WIN:
        return save_text(case_dir / "07_routing.txt", run(["route", "print"]))
    return save_text(case_dir / "07_routing.txt", run(["ip", "route"]))


# ── Network configuration ─────────────────────────────────────────────────────

def collect_network_config(case_dir: Path) -> Path:
    """
    Collect full network adapter configuration.

    Includes MAC addresses, DHCP state, IP addresses, subnet masks,
    default gateway, and DNS suffix search list. A modified DNS suffix
    search list can silently redirect internal domain lookups.

    Args:
        case_dir: Path to the case output folder.
    """
    if IS_WIN:
        return save_text(
            case_dir / "08_network_config.txt",
            run(["ipconfig", "/all"])
        )
    # Linux: ip addr gives full config
    config = {
        "ip_addr":    run(["ip", "addr"]),
        "ip_neigh":   run(["ip", "neigh"]),
        "resolv_conf": _read_resolv_conf(),
    }
    return save_json(case_dir / "08_network_config.json", config)


def _read_resolv_conf() -> str:
    """Read /etc/resolv.conf safely."""
    try:
        return (Path("/etc/resolv.conf")).read_text(errors="replace")
    except Exception as e:
        return f"[ERROR] {e}"


# ── Firewall rules ────────────────────────────────────────────────────────────

def collect_firewall(case_dir: Path) -> Path:
    """
    Collect firewall configuration.

    Attackers commonly add inbound allow rules to maintain access or
    remove outbound block rules to enable C2 communication. On Windows,
    enabled rules only is the default view — also collect disabled rules
    since attackers may disable existing block rules.

    Args:
        case_dir: Path to the case output folder.
    """
    if IS_WIN:
        # Enabled rules for quick review
        enabled = ps(
            "Get-NetFirewallRule -Enabled True "
            "| Select-Object Name,Direction,Action,DisplayName "
            "| ConvertTo-Json -Depth 2",
            timeout=30
        )
        # All rules including disabled (attackers may have disabled blocks)
        all_rules = ps(
            "Get-NetFirewallRule "
            "| Select-Object Name,Enabled,Direction,Action "
            "| ConvertTo-Json -Depth 2",
            timeout=60
        )
        return save_json(case_dir / "09_firewall.json", {
            "enabled_rules": enabled,
            "all_rules":     all_rules,
        })

    if IS_LINUX:
        rules = {
            "iptables":  run(["iptables",  "-L", "-n", "-v"], timeout=10),
            "ip6tables": run(["ip6tables", "-L", "-n", "-v"], timeout=10),
        }
        # Also try nftables on modern systems
        nft = run(["nft", "list", "ruleset"], timeout=10)
        if "[NOT FOUND]" not in nft:
            rules["nftables"] = nft
        return save_json(case_dir / "09_firewall.json", rules)

    return save_text(case_dir / "09_firewall.txt", "[UNSUPPORTED PLATFORM]")


# ── NetBIOS / SMB sessions ────────────────────────────────────────────────────

def collect_netbios(case_dir: Path) -> Optional[Path]:
    """
    Collect active NetBIOS sessions and file transfer information.
    Windows only.

    Active NetBIOS sessions can reveal remote hosts accessing this
    machine's shares, which may indicate lateral movement staging.

    Args:
        case_dir: Path to the case output folder.
    """
    if not IS_WIN:
        return None

    sessions = {
        "net_session": run(["net", "session"]),
        "net_use":     run(["net", "use"]),
        "net_share":   run(["net", "share"]),
    }
    return save_json(case_dir / "10_smb_sessions.json", sessions)


# ── Hosts file ────────────────────────────────────────────────────────────────

def collect_hosts_file(case_dir: Path) -> Path:
    """
    Collect the hosts file.

    Attackers commonly modify the hosts file to redirect traffic —
    pointing security update domains to 0.0.0.0 or redirecting
    internal domains to attacker-controlled IP addresses.

    Args:
        case_dir: Path to the case output folder.
    """
    if IS_WIN:
        hosts_path = Path(r"C:\Windows\System32\drivers\etc\hosts")
    else:
        hosts_path = Path("/etc/hosts")

    try:
        content = hosts_path.read_text(errors="replace")
    except Exception as e:
        content = f"[ERROR reading hosts file: {e}]"

    return save_text(case_dir / "11_hosts_file.txt", content)


# ── Entry point ───────────────────────────────────────────────────────────────

def run_network(case_dir: Path, log) -> list:
    """
    Run all network state collections in order.

    Args:
        case_dir: Path to the timestamped case output folder.
        log:      Callable for status logging.

    Returns:
        List of Path objects for all files written.
    """
    written = []

    for label, func in [
        ("ARP cache",             collect_arp),
        ("DNS cache",             collect_dns_cache),
        ("Routing table",         collect_routing),
        ("Network configuration", collect_network_config),
        ("Firewall rules",        collect_firewall),
        ("NetBIOS / SMB sessions",collect_netbios),
        ("Hosts file",            collect_hosts_file),
    ]:
        log(f"Collecting: {label}")
        p = func(case_dir)
        if p:
            log(f"  -> Saved: {p.name}")
            written.append(p)

    return written
