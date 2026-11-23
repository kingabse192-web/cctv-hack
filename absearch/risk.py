"""Explainable risk scoring for discovered devices.

This is *not* a vulnerability scanner.  The score only highlights services
and facts that a human should review first: exposed management ports, RTSP
endpoints, cleartext protocols, and devices with a relevant default-credential
reference.  No exploitation or authentication is performed.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .models import Device

LEVELS = ("Info", "Low", "Medium", "High", "Critical")

_CLEARTEXT = {21: "FTP", 23: "Telnet", 80: "HTTP", 139: "NetBIOS", 445: "SMB"}
_RTSP = {554, 8554}
_CAMERA_MGMT = {8000, 8899, 34567, 37777}
_DESKTOP_REMOTE = {3389, 5900}


@dataclass
class RiskAssessment:
    level: str
    score: int
    findings: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, object]:
        return {"level": self.level, "score": self.score, "findings": self.findings}

    @property
    def css_class(self) -> str:
        return self.level.lower()


def assess(device: Device) -> RiskAssessment:
    score = 0
    findings: list[str] = []
    open_ports = device.open_ports

    for port in open_ports:
        if port in _CLEARTEXT:
            service = _CLEARTEXT[port]
            points = 35 if port in {21, 23} else 12
            score += points
            findings.append(f"{service} ({port}) is cleartext or legacy management")
        elif port in _RTSP:
            score += 30
            findings.append(f"RTSP stream endpoint exposed on {port}")
        elif port in _CAMERA_MGMT:
            score += 25
            findings.append(f"camera management/service port {port} is open")
        elif port in _DESKTOP_REMOTE:
            score += 20
            findings.append(f"remote desktop port {port} is open")
        elif port == 22:
            score += 8
            findings.append("SSH is open (verify key-only authentication)")
        elif port in {443, 8443}:
            score += 6
            findings.append("HTTPS management interface is reachable")

    if device.category == "Possible CCTV camera" and any(port in _RTSP for port in open_ports):
        score += 12
        findings.append("camera classified with a reachable RTSP endpoint")

    if device.credential_vendor not in {"", "default", "unknown"}:
        score += 8
        findings.append(
            f"factory-default credentials are documented for "
            f"'{device.credential_vendor}' (manual review only)"
        )

    if len(open_ports) >= 8:
        score += 8
        findings.append(f"{len(open_ports)} open ports detected")

    score = max(0, min(100, score))
    if score >= 85:
        level = "Critical"
    elif score >= 60:
        level = "High"
    elif score >= 35:
        level = "Medium"
    elif score >= 12:
        level = "Low"
    else:
        level = "Info"

    if not findings:
        findings.append("no high-signal exposure observed")

    return RiskAssessment(level=level, score=score, findings=findings[:8])


def summary_counts(assessments: list[RiskAssessment]) -> dict[str, int]:
    counts = {level: 0 for level in LEVELS}
    for assessment in assessments:
        counts[assessment.level] = counts.get(assessment.level, 0) + 1
    return counts
