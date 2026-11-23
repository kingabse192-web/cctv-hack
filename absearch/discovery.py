"""Advanced, authentication-free service discovery.

These probes speak standard discovery protocols on the local link:

* **mDNS/DNS-SD** (UDP 5353) — service names and addresses
* **SSDP/UPnP** (UDP 1900) — `M-SEARCH`, reading only advertised headers
* **ONVIF WS-Discovery** (UDP 3702) — the standard camera discovery protocol

Nothing here logs in, downloads firmware, or opens a stream.  The probes are
only used in ``--deep`` mode on networks the operator has authorized.
"""

from __future__ import annotations

import re
import socket
import struct
import time
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field

MDNS_GROUP = "224.0.0.251"
SSDP_GROUP = "239.255.255.250"
_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


@dataclass
class DiscoveryHint:
    ip: str
    name: str = ""
    service: str = ""
    source: str = ""
    details: dict[str, str] = field(default_factory=dict)

    def to_text(self) -> str:
        parts = [self.source or "discovery"]
        if self.service:
            parts.append(self.service)
        if self.name:
            parts.append(self.name)
        if self.details.get("vendor"):
            parts.append(f"vendor={self.details['vendor']}")
        return " → ".join(parts)


# ---------------------------------------------------------------------------
# Minimal DNS/mDNS parser (PTR, SRV, TXT, A)


def _read_name(data: bytes, offset: int) -> tuple[str, int]:
    labels: list[str] = []
    seen: set[int] = set()
    jumped = False
    end = offset
    while offset < len(data):
        length = data[offset]
        if length & 0xC0 == 0xC0:
            if offset + 1 >= len(data):
                break
            pointer = ((length & 0x3F) << 8) | data[offset + 1]
            if not jumped:
                end = offset + 2
            jumped = True
            if pointer in seen or pointer >= len(data):
                break
            seen.add(pointer)
            offset = pointer
            continue
        offset += 1
        if length == 0:
            if not jumped:
                end = offset
            break
        if length > 63 or offset + length > len(data):
            break
        labels.append(data[offset : offset + length].decode("utf-8", errors="replace"))
        offset += length
    return ".".join(labels).rstrip("."), end


def _encode_name(name: str) -> bytes:
    out = bytearray()
    for label in name.rstrip(".").split("."):
        encoded = label.encode("utf-8")[:63]
        out.append(len(encoded))
        out.extend(encoded)
    out.append(0)
    return bytes(out)


def _mdns_query(names: list[str]) -> bytes:
    header = struct.pack("!HHHHHH", 0xAB12, 0, len(names), 0, 0, 0)
    questions = b"".join(_encode_name(name) + struct.pack("!HH", 12, 1) for name in names)
    return header + questions


def _parse_mdns_response(data: bytes) -> list[DiscoveryHint]:
    if len(data) < 12:
        return []
    try:
        _, _, qdcount, ancount, _, _ = struct.unpack("!HHHHHH", data[:12])
    except struct.error:
        return []
    offset = 12
    for _ in range(qdcount):
        _, offset = _read_name(data, offset)
        offset += 4

    ips: list[str] = []
    ptrs: list[str] = []
    targets: list[str] = []
    texts: list[str] = []
    for _ in range(ancount):
        if offset + 10 > len(data):
            break
        _, offset = _read_name(data, offset)
        rtype, _, _, rdlength = struct.unpack("!HHIH", data[offset : offset + 10])
        offset += 10
        rdata = data[offset : offset + rdlength]
        offset += rdlength
        if rtype == 1 and len(rdata) == 4:
            ip = socket.inet_ntoa(rdata)
            if ip not in {"0.0.0.0"}:
                ips.append(ip)
        elif rtype == 12:
            name, _ = _read_name(rdata, 0)
            if name:
                ptrs.append(name)
        elif rtype == 33 and len(rdata) >= 8:
            target, _ = _read_name(rdata, 6)
            if target:
                targets.append(target)
        elif rtype == 16:
            cursor = 0
            while cursor < len(rdata):
                size = rdata[cursor]
                cursor += 1
                if cursor + size > len(rdata):
                    break
                value = rdata[cursor : cursor + size].decode("utf-8", errors="replace")
                cursor += size
                if value:
                    texts.append(value)

    if not ips:
        return []
    service = ""
    for ptr in ptrs:
        parts = ptr.split(".")
        for index, label in enumerate(parts):
            if label.startswith("_"):
                service = ".".join(parts[index:])
                break
        if service:
            break
    name = ""
    for candidate in targets + [p for p in ptrs if not p.startswith("_")] + texts:
        if candidate and len(candidate) < 120:
            name = candidate
            break
    details: dict[str, str] = {}
    if len(ptrs) > 1:
        details["services"] = ", ".join(dict.fromkeys(ptrs))[:180]
    if texts:
        details["txt"] = ", ".join(texts[:3])[:180]
    return [
        DiscoveryHint(ip=ip, name=name, service=service, source="mdns", details=details)
        for ip in dict.fromkeys(ips)
    ]


def mdns_probe(timeout: float = 2.5) -> list[DiscoveryHint]:
    names = [
        "_services._dns-sd._udp.local",
        "_http._tcp.local",
        "_https._tcp.local",
        "_onvif._tcp.local",
        "_ipp._tcp.local",
        "_airplay._tcp.local",
    ]
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, struct.pack("B", 2))
        try:
            sock.bind(("", 5353))
            sock.setsockopt(
                socket.IPPROTO_IP,
                socket.IP_ADD_MEMBERSHIP,
                socket.inet_aton(MDNS_GROUP) + socket.inet_aton("0.0.0.0"),
            )
        except OSError:
            pass  # Another responder owns the port; sending still works.
        sock.settimeout(0.4)
        sock.sendto(_mdns_query(names), (MDNS_GROUP, 5353))
        hints: list[DiscoveryHint] = []
        deadline = time.monotonic() + max(0.5, timeout)
        while time.monotonic() < deadline:
            try:
                data, _ = sock.recvfrom(9000)
            except socket.timeout:
                continue
            except OSError:
                break
            hints.extend(_parse_mdns_response(data))
        return hints
    finally:
        sock.close()


# ---------------------------------------------------------------------------
# SSDP / UPnP


def ssdp_probe(timeout: float = 2.5) -> list[DiscoveryHint]:
    request = (
        "M-SEARCH * HTTP/1.1\r\n"
        f"HOST: {SSDP_GROUP}:1900\r\n"
        'MAN: "ssdp:discover"\r\n'
        "MX: 2\r\n"
        "ST: ssdp:all\r\n"
        "\r\n"
    ).encode("ascii")
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, struct.pack("B", 2))
    sock.settimeout(0.4)
    hints: list[DiscoveryHint] = []
    try:
        sock.sendto(request, (SSDP_GROUP, 1900))
        deadline = time.monotonic() + max(0.5, timeout)
        while time.monotonic() < deadline:
            try:
                data, addr = sock.recvfrom(8192)
            except socket.timeout:
                continue
            except OSError:
                break
            text = data.decode("latin-1", errors="replace")
            headers: dict[str, str] = {}
            for line in text.splitlines()[1:]:
                if ":" in line:
                    key, value = line.split(":", 1)
                    headers[key.strip().lower()] = value.strip()
            location = headers.get("location", "")
            name = headers.get("server", "")
            if not name and location:
                hostmatch = re.match(r"https?://([^/:]+)", location)
                name = hostmatch.group(1) if hostmatch else ""
            service = headers.get("st", "ssdp")
            hints.append(
                DiscoveryHint(
                    ip=addr[0],
                    name=name[:120],
                    service=service[:80],
                    source="ssdp",
                    details={"location": location[:200], "usn": headers.get("usn", "")[:120]},
                )
            )
        return hints
    finally:
        sock.close()


# ---------------------------------------------------------------------------
# ONVIF WS-Discovery


_WSDL_PROBE = """<?xml version="1.0" encoding="UTF-8"?>
<e:Envelope xmlns:e="http://www.w3.org/2003/05/soap-envelope"
 xmlns:w="http://schemas.xmlsoap.org/ws/2004/09/discovery"
 xmlns:a="http://www.w3.org/2005/08/addressing"
 xmlns:tds="http://www.onvif.org/ver10/device/wsdl">
 <e:Header>
  <a:Action>http://schemas.xmlsoap.org/ws/2004/09/discovery/Probe</a:Action>
  <a:To>urn:schemas-xmlsoap-org:ws:2005:04:discovery</a:To>
  <a:MessageID>uuid:{message_id}</a:MessageID>
 </e:Header>
 <e:Body><w:Probe><w:Types>tds:Device</w:Types></w:Probe></e:Body>
</e:Envelope>"""


def _first(pattern: str, text: str, flags: int = re.I | re.S) -> str:
    match = re.search(pattern, text, flags)
    return match.group(1).strip() if match else ""


def _parse_onvif_response(text: str) -> DiscoveryHint | None:
    addresses = re.findall(r"<[^>]*Address[^>]*>([^<]+)</[^>]*Address>", text, re.I | re.S)
    address = next((value for value in addresses if _IPV4_RE.search(value)), "")
    ip_match = _IPV4_RE.search(address)
    if not ip_match:
        return None
    name = (
        _first(r"<[^>]*(?:FriendlyName|friendlyName)[^>]*>([^<]+)</", text)
        or _first(r"<[^>]*Model[^>]*>([^<]+)</", text)
    )
    vendor = (
        _first(r"<[^>]*Manufacturer[^>]*>([^<]+)</", text)
        or _first(r"<[^>]*ManufacturerStr[^>]*>([^<]+)</", text)
    )
    service = _first(r"<[^>]*Types[^>]*>([^<]+)</", text) or "onvif"
    details = {"endpoint": address[:200]}
    if vendor:
        details["vendor"] = vendor[:120]
    return DiscoveryHint(
        ip=ip_match.group(0),
        name=name[:120],
        service="onvif",
        source="onvif",
        details=details,
    )


def onvif_probe(timeout: float = 2.5) -> list[DiscoveryHint]:
    probe = _WSDL_PROBE.format(message_id=uuid.uuid4()).encode("utf-8")
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, struct.pack("B", 2))
    sock.settimeout(0.4)
    hints: list[DiscoveryHint] = []
    try:
        sock.sendto(probe, (SSDP_GROUP, 3702))
        deadline = time.monotonic() + max(0.5, timeout)
        while time.monotonic() < deadline:
            try:
                data, _ = sock.recvfrom(32768)
            except socket.timeout:
                continue
            except OSError:
                break
            hint = _parse_onvif_response(data.decode("utf-8", errors="replace"))
            if hint:
                hints.append(hint)
        return hints
    finally:
        sock.close()


SOURCES = {"mdns": mdns_probe, "ssdp": ssdp_probe, "onvif": onvif_probe}


def discover_hints(
    timeout: float = 2.5,
    sources: tuple[str, ...] = ("mdns", "ssdp", "onvif"),
) -> list[DiscoveryHint]:
    """Run enabled discovery probes and return deduplicated hints."""

    all_hints: list[DiscoveryHint] = []
    with ThreadPoolExecutor(max_workers=max(1, len(sources))) as pool:
        futures = {
            pool.submit(SOURCES[name], timeout): name
            for name in sources
            if name in SOURCES
        }
        for future in as_completed(futures):
            try:
                all_hints.extend(future.result())
            except Exception:
                # Discovery is best-effort; never break the whole scan.
                continue

    seen: set[tuple[str, str, str]] = set()
    unique: list[DiscoveryHint] = []
    for hint in all_hints:
        key = (hint.ip, hint.service, hint.name)
        if key in seen:
            continue
        seen.add(key)
        unique.append(hint)
    return unique[:200]


def hints_by_ip(hints: list[DiscoveryHint]) -> dict[str, list[DiscoveryHint]]:
    grouped: dict[str, list[DiscoveryHint]] = {}
    for hint in hints:
        grouped.setdefault(hint.ip, []).append(hint)
    return grouped
