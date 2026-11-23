"""Report construction and export (JSON, CSV, and the offline dashboard)."""

from __future__ import annotations

import csv
import datetime as dt
import html
import json
import os
import platform
from pathlib import Path
from typing import Any

from . import __version__
from .bluetooth import BluetoothScan
from .credentials import CredentialReference, CredentialStore
from .models import CATEGORIES, Device
from .risk import assess as assess_risk
from .risk import summary_counts as risk_counts

SCHEMA = "absearch.report.v1"


def _timestamp() -> str:
    return dt.datetime.now().astimezone().isoformat(timespec="seconds")


def _top_ports(devices: list[Device], limit: int = 8) -> list[dict[str, Any]]:
    counts: dict[int, int] = {}
    for device in devices:
        for port in set(device.open_ports):
            counts[port] = counts.get(port, 0) + 1
    top = sorted(counts.items(), key=lambda item: (-item[1], item[0]))[:limit]
    return [{"port": port, "devices": count} for port, count in top]


def build_report(
    *,
    network: str,
    interface: str = "",
    gateway: str = "",
    devices: list[Device],
    bluetooth: BluetoothScan | None = None,
    credential_store: CredentialStore | None = None,
    authorization: str = "confirmed by operator",
    mode: str = "live",
    options: dict[str, Any] | None = None,
    diff: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Build the JSON-serialisable report consumed by the CLI and dashboard."""

    bluetooth = bluetooth or BluetoothScan(supported=False, error="not requested")
    credential_store = credential_store or CredentialStore()

    counts = {category: 0 for category in CATEGORIES}
    for device in devices:
        counts[device.category] = counts.get(device.category, 0) + 1

    references: list[dict[str, Any]] = []
    assessments = []
    for device in devices:
        reference: CredentialReference = credential_store.for_device(device)
        device.credential_vendor = reference.vendor
        device.credentials = reference.pairs
        assessment = assess_risk(device)
        device.risk = assessment.to_dict()
        assessments.append(assessment)
        references.append(
            {
                "ip": device.ip,
                "vendor_key": reference.vendor,
                "note": reference.note,
            }
        )

    all_credentials = [
        {"username": pair.username, "password": pair.password}
        for pair in credential_store.all_pairs(limit=200)
    ]

    return {
        "schema": SCHEMA,
        "meta": {
            "generated_at": _timestamp(),
            "tool": "AB Search",
            "version": __version__,
            "mode": mode,
            "network": network,
            "interface": interface,
            "gateway": gateway,
            "authorization": authorization,
            "scanner_host": platform.node(),
            "python": platform.python_version(),
            "platform": platform.platform(),
            "options": options or {},
        },
        "summary": {
            "total": len(devices),
            "categories": counts,
            "cameras": counts.get("Possible CCTV camera", 0),
            "routers": counts.get("Router", 0),
            "computers": counts.get("Computer", 0),
            "phones": counts.get("Phone", 0),
            "unknown": counts.get("Unknown device", 0),
            "bluetooth_devices": len(bluetooth.devices),
            "risk": risk_counts(assessments),
            "top_ports": _top_ports(devices),
        },
        "devices": [device.to_dict() for device in devices],
        "diff": diff,
        "bluetooth": {
            "supported": bluetooth.supported,
            "error": bluetooth.error,
            "devices": [device.to_dict() for device in bluetooth.devices],
        },
        "credential_reference": {
            "note": (
                "Public factory-default pairs for manual login only. "
                "AB Search never sends credentials or attempts authentication."
            ),
            "sources": credential_store.sources,
            "pairs": all_credentials,
            "per_device": references,
        },
        "safety": {
            "credential_attempts": 0,
            "stream_access": False,
            "bluetooth_connections": 0,
            "note": "Authorized networks only. No login attempts, no brute force, no camera streams.",
        },
    }


def safe_json(data: Any, indent: int | None = 2) -> str:
    """JSON with characters that can break out of a <script> tag escaped."""

    text = json.dumps(data, indent=indent, ensure_ascii=False, sort_keys=False)
    return (
        text.replace("&", "\\u0026")
        .replace("<", "\\u003c")
        .replace(">", "\\u003e")
        .replace("\u2028", "\\u2028")
        .replace("\u2029", "\\u2029")
    )


def _csv_safe(value: Any) -> str:
    text = "" if value is None else str(value)
    if text and text[0] in {"=", "+", "-", "@"}:
        text = "'" + text
    return text


def devices_csv(devices: list[dict[str, Any]]) -> str:
    from io import StringIO

    buffer = StringIO()
    writer = csv.writer(buffer, lineterminator="\n")
    writer.writerow(
        [
            "ip", "mac", "vendor", "hostname", "category", "confidence",
            "risk_level", "risk_score", "ports", "services", "web_urls",
            "rtsp_urls", "discovery_hints", "notes",
        ]
    )
    for device in devices:
        ports = device.get("ports", [])
        writer.writerow(
            [
                _csv_safe(device.get("ip", "")),
                _csv_safe(device.get("mac", "")),
                _csv_safe(device.get("vendor", "")),
                _csv_safe(device.get("hostname", "")),
                _csv_safe(device.get("category", "")),
                _csv_safe(device.get("confidence", "")),
                _csv_safe(device.get("risk", {}).get("level", "")),
                _csv_safe(device.get("risk", {}).get("score", "")),
                _csv_safe(" ".join(str(port.get("port", "")) for port in ports)),
                _csv_safe(
                    " ".join(
                        f"{port.get('port')}={port.get('service', '')}"
                        for port in ports
                        if port.get("service")
                    )
                ),
                _csv_safe(" ".join(device.get("web", []))),
                _csv_safe(" ".join(device.get("rtsp", []))),
                _csv_safe("; ".join(device.get("hints", []))),
                _csv_safe("; ".join(device.get("notes", []))),
            ]
        )
    return buffer.getvalue()


def _template_text() -> str:
    try:
        from importlib.resources import files

        resource = files("absearch").joinpath("web").joinpath("template.html")
        return resource.read_text(encoding="utf-8")
    except (OSError, ModuleNotFoundError, FileNotFoundError):  # pragma: no cover
        return (
            "<!doctype html><html><head><meta charset='utf-8'>"
            "<title>AB Search</title></head><body><pre>__REPORT_JSON__</pre></body></html>"
        )


def render_dashboard(report: dict[str, Any]) -> str:
    template = _template_text()
    meta = report.get("meta", {})
    mode = str(meta.get("mode", "live"))
    title = "AB Search — Demo inventory" if mode == "demo" else "AB Search — Network inventory"
    payload = safe_json(report, indent=None)
    # Replace the small placeholders first: if a device hostname happened to
    # contain one of those tokens, replacing it after the JSON was embedded
    # could corrupt the report payload.
    return (
        template.replace("__PAGE_TITLE__", html.escape(title))
        .replace("__MODE_BADGE__", "Demo data" if mode == "demo" else "Live scan")
        .replace("__REPORT_JSON__", payload)
    )


def write_reports(
    report: dict[str, Any],
    output_dir: Path,
    formats: tuple[str, ...] = ("json", "csv", "html"),
) -> dict[str, Path]:
    """Write selected report formats and return a mapping of name to path."""

    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    written: dict[str, Path] = {}

    if "json" in formats:
        path = output_dir / "report.json"
        path.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        written["json"] = path

    if "csv" in formats:
        path = output_dir / "devices.csv"
        path.write_text(devices_csv(report.get("devices", [])), encoding="utf-8")
        written["csv"] = path

    if "html" in formats:
        path = output_dir / "index.html"
        path.write_text(render_dashboard(report), encoding="utf-8")
        written["html"] = path

    return written


def report_path(base_dir: Path, stamp: str | None = None) -> Path:
    stamp = stamp or dt.datetime.now().strftime("%Y%m%d-%H%M%S")
    return Path(base_dir) / f"scan-{stamp}"


def load_report(path: Path) -> dict[str, Any]:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def print_report_paths(paths: dict[str, Path]) -> None:
    print("\nReports written:")
    for name, path in paths.items():
        print(f"  {name.upper():<4}  {path}")


def environment_summary() -> dict[str, str]:
    return {
        "python": platform.python_version(),
        "platform": platform.platform(),
        "user": os.environ.get("USER", ""),
    }
