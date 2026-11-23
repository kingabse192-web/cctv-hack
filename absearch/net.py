"""Network discovery: interfaces, gateway, ARP table, and nmap parsing.

The scanner is deliberately conservative.  It uses nmap host discovery when
nmap is available, merges the kernel's neighbour table for MAC addresses, and
falls back to a small ping sweep only when nmap is missing.  Port probing is
kept in :mod:`absearch.services`.
"""

from __future__ import annotations

import ipaddress
import os
import re
import shutil
import socket
import struct
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from pathlib import Path

try:  # psutil is a hard dependency, but keep imports friendly for tests.
    import psutil
except Exception:  # pragma: no cover
    psutil = None  # type: ignore[assignment]

from .oui import is_valid_mac, lookup_vendor, normalize_mac

_MAC_RE = re.compile(
    r"(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}"
)
_NMAP_HOST_RE = re.compile(r"^Nmap scan report for (?P<target>.+)$")
_NMAP_MAC_RE = re.compile(
    r"^MAC Address:\s+(?P<mac>(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2})"
    r"(?:\s+\((?P<vendor>[^)]*)\))?",
    re.IGNORECASE,
)
_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


@dataclass
class Interface:
    name: str
    ip: str
    netmask: str
    cidr: str
    is_up: bool = True
    is_wireless: bool = False
    gateway: str = ""

    @property
    def display(self) -> str:
        kind = "Wi-Fi" if self.is_wireless else "Ethernet"
        return f"{self.name}  {self.ip}/{self.netmask}  ({kind})"


@dataclass
class HostRecord:
    ip: str
    mac: str = ""
    vendor: str = ""
    hostname: str = ""
    source: str = "nmap"
    notes: list[str] = field(default_factory=list)


def _prefix_from_netmask(netmask: str) -> int | None:
    try:
        return ipaddress.IPv4Network(f"0.0.0.0/{netmask}").prefixlen
    except ValueError:
        return None


def is_wireless_interface(name: str) -> bool:
    if Path(f"/sys/class/net/{name}/wireless").exists():
        return True
    try:
        wireless = Path("/proc/net/wireless").read_text(encoding="utf-8")
        return any(line.split(":")[0].strip() == name for line in wireless.splitlines())
    except OSError:
        return False


def default_gateway() -> tuple[str, str]:
    """Return ``(gateway_ip, interface_name)`` from the kernel route table."""

    try:
        lines = Path("/proc/net/route").read_text(encoding="utf-8").splitlines()
    except OSError:
        lines = []
    for line in lines[1:]:
        parts = line.split()
        if len(parts) < 3 or parts[1] != "00000000":
            continue
        try:
            gateway = socket.inet_ntoa(struct.pack("<L", int(parts[2], 16)))
        except (ValueError, OSError):
            continue
        if gateway != "0.0.0.0":
            return gateway, parts[0]

    # Fallback for systems without /proc/net/route.
    try:
        output = subprocess.run(
            ["ip", "route", "show", "default"],
            capture_output=True,
            text=True,
            timeout=3,
            check=False,
        ).stdout
    except (OSError, subprocess.SubprocessError):
        return "", ""
    match = re.search(r"default via (\S+)(?: dev (\S+))?", output)
    if match:
        return match.group(1), match.group(2) or ""

    # Windows: "route print 0.0.0.0" has numeric columns in every locale.
    if os.name == "nt":
        try:
            output = subprocess.run(
                ["route", "print", "0.0.0.0"],
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
            ).stdout
        except (OSError, subprocess.SubprocessError):
            return "", ""
        for line in output.splitlines():
            parts = line.split()
            if len(parts) >= 5 and parts[0] == "0.0.0.0" and parts[2] != "0.0.0.0":
                try:
                    ipaddress.ip_address(parts[2])
                except ValueError:
                    continue
                return parts[2], parts[3]
    return "", ""


def detect_interfaces() -> list[Interface]:
    """Return non-loopback IPv4 interfaces, up interfaces first."""

    if psutil is None:
        return []
    stats = psutil.net_if_stats()
    gateway, gateway_iface = default_gateway()
    interfaces: dict[str, Interface] = {}
    for name, addresses in psutil.net_if_addrs().items():
        if name in {"lo", "loopback"} or name.startswith("lo"):
            continue
        for address in addresses:
            if address.family != socket.AF_INET:
                continue
            ip = address.address
            netmask = address.netmask or "255.255.255.255"
            if ip.startswith("127.") or ip == "0.0.0.0":
                continue
            try:
                network = ipaddress.ip_network(f"{ip}/{netmask}", strict=False)
            except ValueError:
                continue
            if network.prefixlen == 32 and not ip.startswith("169.254."):
                # A /32 alias is rarely a useful inventory target.  Keep it
                # only when it is the interface that owns the default route.
                if name != gateway_iface:
                    continue
            if network.network_address.is_link_local:
                continue
            stat = stats.get(name)
            interfaces[name] = Interface(
                name=name,
                ip=ip,
                netmask=netmask,
                cidr=str(network),
                is_up=bool(stat.isup) if stat else True,
                is_wireless=is_wireless_interface(name),
                gateway=gateway if (name == gateway_iface or not gateway_iface) else "",
            )
    return sorted(interfaces.values(), key=lambda item: (not item.is_up, item.name))


def choose_interface(interfaces: list[Interface], requested: str = "") -> Interface:
    if requested:
        for interface in interfaces:
            if interface.name == requested:
                return interface
        raise ValueError(f"Interface {requested!r} was not found or has no IPv4 address.")
    if not interfaces:
        raise ValueError(
            "No non-loopback IPv4 interface found. Connect to Wi-Fi/Ethernet "
            "and install psutil, or pass --network explicitly."
        )
    for interface in interfaces:
        if interface.gateway:
            return interface
    return interfaces[0]


def parse_network(value: str) -> ipaddress.IPv4Network:
    try:
        network = ipaddress.ip_network(value, strict=False)
    except ValueError as exc:
        raise ValueError(f"Invalid IPv4 network {value!r}: {exc}") from exc
    if network.version != 4:
        raise ValueError("Only IPv4 networks are supported.")
    return network


def network_hosts(network: ipaddress.IPv4Network, limit: int | None = None) -> list[str]:
    hosts = [str(host) for host in network.hosts()]
    if limit is not None:
        return hosts[:limit]
    return hosts


def is_private(network: ipaddress.IPv4Network) -> bool:
    return network.is_private and not network.is_loopback


def parse_arp_a(text: str) -> dict[str, HostRecord]:
    """Parse Windows/BSD ``arp -a`` output into MAC records."""

    records: dict[str, HostRecord] = {}
    for line in text.splitlines():
        ip_match = _IPV4_RE.search(line)
        mac_match = _MAC_RE.search(line)
        if not ip_match or not mac_match:
            continue
        mac = normalize_mac(mac_match.group(0))
        if not mac:
            continue
        ip = ip_match.group(0)
        records[ip] = HostRecord(
            ip=ip,
            mac=mac,
            vendor=lookup_vendor(mac),
            source="arp",
        )
    return records


def arp_table() -> dict[str, HostRecord]:
    """Read the kernel neighbour table (no packets are sent)."""

    records: dict[str, HostRecord] = {}
    try:
        output = subprocess.run(
            ["ip", "neigh", "show"],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        ).stdout
    except (OSError, subprocess.SubprocessError):
        output = ""

    if output:
        for line in output.splitlines():
            parts = line.split()
            if not parts:
                continue
            ip = parts[0]
            try:
                ipaddress.ip_address(ip)
            except ValueError:
                continue
            mac = ""
            for index, part in enumerate(parts):
                if part == "lladdr" and index + 1 < len(parts):
                    mac = normalize_mac(parts[index + 1])
                    break
            if mac:
                records[ip] = HostRecord(
                    ip=ip,
                    mac=mac,
                    vendor=lookup_vendor(mac),
                    source="arp",
                )
        if records:
            return records

    # Portable fallback for systems without iproute2.
    try:
        lines = Path("/proc/net/arp").read_text(encoding="utf-8").splitlines()
    except OSError:
        lines = []
    for line in lines[1:]:
        parts = line.split()
        if len(parts) < 6:
            continue
        ip, flags = parts[0], parts[2]
        mac = normalize_mac(parts[3])
        if flags == "0x0" or not mac:
            continue
        records[ip] = HostRecord(
            ip=ip,
            mac=mac,
            vendor=lookup_vendor(mac),
            source="arp",
        )
    if records:
        return records

    # Windows (and some BSDs): parse "arp -a" output.  Both Windows and Linux
    # syntaxes contain an IPv4 address and a MAC on the same data line.
    try:
        output = subprocess.run(
            ["arp", "-a"],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        ).stdout
    except (OSError, subprocess.SubprocessError):
        return records
    records.update(parse_arp_a(output))
    return records


def parse_nmap_discovery(output: str) -> list[HostRecord]:
    """Parse the subset of ``nmap -sn`` output we care about."""

    records: list[HostRecord] = []
    current: HostRecord | None = None
    for raw_line in output.splitlines():
        line = raw_line.strip()
        match = _NMAP_HOST_RE.match(line)
        if match:
            target = match.group("target").strip()
            hostname = ""
            ip = ""
            paren = re.search(r"^(?P<hostname>.*?)\s*\((?P<ip>[^)]+)\)\s*$", target)
            if paren:
                hostname = paren.group("hostname").strip()
                ip = paren.group("ip").strip()
            else:
                ip = target
            try:
                ipaddress.ip_address(ip)
            except ValueError:
                ip_match = _IPV4_RE.search(target)
                if not ip_match:
                    current = None
                    continue
                ip = ip_match.group(0)
                hostname = target[: ip_match.start()].strip()
            current = HostRecord(ip=ip, hostname="" if hostname == ip else hostname, source="nmap")
            records.append(current)
            continue
        if current is None:
            continue
        mac_match = _NMAP_MAC_RE.match(line)
        if mac_match:
            current.mac = normalize_mac(mac_match.group("mac"))
            current.vendor = (mac_match.group("vendor") or "").strip()
            if not current.vendor and current.mac:
                current.vendor = lookup_vendor(current.mac)
    return records


def nmap_available() -> bool:
    return shutil.which("nmap") is not None


def nmap_discover(network: ipaddress.IPv4Network, timeout: int = 120) -> list[HostRecord]:
    if not nmap_available():
        return []
    command = [
        "nmap",
        "-sn",
        "-T2",
        "--max-retries",
        "1",
        "--host-timeout",
        "20s",
        str(network),
    ]
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return []
    return parse_nmap_discovery(result.stdout)


def ping_sweep(
    network: ipaddress.IPv4Network,
    max_hosts: int = 256,
    workers: int = 64,
) -> list[str]:
    """Best-effort fallback host discovery when nmap is unavailable."""

    ping = shutil.which("ping")
    if not ping:
        return []
    hosts = network_hosts(network, limit=max_hosts)
    found: list[str] = []

    ping_args = (
        [ping, "-n", "1", "-w", "1000", ip]
        if os.name == "nt"
        else [ping, "-c", "1", "-W", "1", ip]
    )

    def probe(ip: str) -> str | None:
        try:
            result = subprocess.run(
                ping_args[:-1] + [ip],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=2,
                check=False,
            )
        except (OSError, subprocess.SubprocessError):
            return None
        return ip if result.returncode == 0 else None

    with ThreadPoolExecutor(max_workers=min(workers, max(1, len(hosts)))) as pool:
        futures = {pool.submit(probe, ip): ip for ip in hosts}
        for future in as_completed(futures):
            result = future.result()
            if result:
                found.append(result)
    return sorted(found, key=ipaddress.ip_address)


def reverse_dns(ip: str, timeout: float = 0.8) -> str:
    """Resolve a hostname with a hard timeout; never raise."""

    def resolve() -> str:
        try:
            hostname, _, _ = socket.gethostbyaddr(ip)
            return hostname.rstrip(".")
        except (OSError, socket.herror, socket.gaierror):
            return ""

    pool = ThreadPoolExecutor(max_workers=1)
    future = pool.submit(resolve)
    try:
        return future.result(timeout=timeout)
    except Exception:
        return ""
    finally:
        pool.shutdown(wait=False, cancel_futures=True)


def merge_hosts(
    primary: list[HostRecord],
    neighbours: dict[str, HostRecord],
    network: ipaddress.IPv4Network | None = None,
) -> list[HostRecord]:
    merged: dict[str, HostRecord] = {}
    for record in primary:
        if network is not None and ipaddress.ip_address(record.ip) not in network:
            continue
        merged[record.ip] = record

    for ip, record in neighbours.items():
        if network is not None and ipaddress.ip_address(ip) not in network:
            continue
        if ip in merged:
            if not merged[ip].mac:
                merged[ip].mac = record.mac
            if not merged[ip].vendor:
                merged[ip].vendor = record.vendor
            if not merged[ip].source:
                merged[ip].source = record.source
        else:
            merged[ip] = record

    for record in merged.values():
        if record.mac and not record.vendor:
            record.vendor = lookup_vendor(record.mac)
        if record.vendor:
            # nmap sometimes returns a long IEEE legal name; keep it readable.
            record.vendor = " ".join(record.vendor.split())
    return sorted(merged.values(), key=lambda item: ipaddress.ip_address(item.ip))


def discover_hosts(
    network: ipaddress.IPv4Network,
    timeout: int = 120,
    resolve_names: bool = True,
    allow_ping_fallback: bool = True,
) -> list[HostRecord]:
    """Discover hosts, merging nmap output with the ARP table."""

    records = nmap_discover(network, timeout=timeout)
    neighbours = arp_table()

    if not records and allow_ping_fallback and network.num_addresses <= 258:
        pinged = ping_sweep(network)
        # Re-read the neighbour table after the sweep so MACs are available.
        neighbours = arp_table()
        records = [HostRecord(ip=ip, source="ping") for ip in pinged]

    hosts = merge_hosts(records, neighbours, network=network)

    if resolve_names:
        missing = [host for host in hosts if not host.hostname]
        if missing:
            with ThreadPoolExecutor(max_workers=min(16, len(missing))) as pool:
                futures = {pool.submit(reverse_dns, host.ip): host for host in missing}
                for future in as_completed(futures):
                    host = futures[future]
                    try:
                        host.hostname = future.result(timeout=1.5)
                    except Exception:
                        host.hostname = ""

    return hosts


def gateway_for_network(network: ipaddress.IPv4Network, interface: Interface | None = None) -> str:
    gateway, _ = default_gateway()
    if gateway and ipaddress.ip_address(gateway) in network:
        return gateway
    if interface and interface.gateway:
        return interface.gateway
    return ""
