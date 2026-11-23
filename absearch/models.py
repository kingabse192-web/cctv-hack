"""Dataclasses shared by the scanner, report writer, and dashboard."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


ROUTER = "Router"
COMPUTER = "Computer"
PHONE = "Phone"
CAMERA = "Possible CCTV camera"
UNKNOWN = "Unknown device"

CATEGORIES = [CAMERA, ROUTER, COMPUTER, PHONE, UNKNOWN]


@dataclass
class PortInfo:
    port: int
    protocol: str = "tcp"
    service: str = ""
    state: str = "open"
    banner: str = ""
    # Optional structured evidence collected in --deep mode (TLS certificate
    # subject/SAN/issuer, protocol notes, etc.).
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class CredentialPair:
    username: str
    password: str

    def to_dict(self) -> dict[str, Any]:
        return {"username": self.username, "password": self.password}

    @property
    def display_password(self) -> str:
        return "<blank>" if self.password == "" else self.password


@dataclass
class Device:
    ip: str
    mac: str = ""
    vendor: str = ""
    hostname: str = ""
    category: str = UNKNOWN
    confidence: float = 0.0
    ports: list[PortInfo] = field(default_factory=list)
    web: list[str] = field(default_factory=list)
    rtsp: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    credential_vendor: str = "default"
    credentials: list[CredentialPair] = field(default_factory=list)
    is_gateway: bool = False
    # Passive/active discovery evidence (mDNS, SSDP, ONVIF) as short strings.
    hints: list[str] = field(default_factory=list)
    # Filled in by report.build_report() after risk assessment and diffing.
    risk: dict[str, Any] = field(default_factory=dict)
    diff: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["ports"] = [p.to_dict() for p in self.ports]
        data["credentials"] = [c.to_dict() for c in self.credentials]
        return data

    @property
    def open_ports(self) -> list[int]:
        return sorted({p.port for p in self.ports if p.state == "open"})

    @property
    def port_summary(self) -> str:
        ports = self.open_ports
        return ", ".join(str(p) for p in ports) if ports else "none detected"

    @property
    def primary_web(self) -> str:
        return self.web[0] if self.web else ""

    @property
    def primary_rtsp(self) -> str:
        return self.rtsp[0] if self.rtsp else ""
