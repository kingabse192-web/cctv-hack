"""Scan-to-scan comparison for baselines and watch mode."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def _device_index(report: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {device.get("ip", ""): device for device in report.get("devices", []) if device.get("ip")}


def _brief(device: dict[str, Any]) -> dict[str, Any]:
    return {
        "ip": device.get("ip", ""),
        "hostname": device.get("hostname", ""),
        "vendor": device.get("vendor", ""),
        "category": device.get("category", ""),
        "ports": [port.get("port") for port in device.get("ports", [])],
    }


def compare_reports(previous: dict[str, Any], current: dict[str, Any]) -> dict[str, Any]:
    """Return a compact, human-readable diff between two reports."""

    before = _device_index(previous)
    after = _device_index(current)

    new_ips = sorted(set(after) - set(before))
    missing_ips = sorted(set(before) - set(after))
    changed: list[dict[str, Any]] = []

    for ip in sorted(set(before) & set(after)):
        old, new = before[ip], after[ip]
        old_ports = {item.get("port") for item in old.get("ports", [])}
        new_ports = {item.get("port") for item in new.get("ports", [])}
        added = sorted(new_ports - old_ports)
        removed = sorted(old_ports - new_ports)
        category_changed = old.get("category") != new.get("category")
        if added or removed or category_changed:
            changed.append(
                {
                    "ip": ip,
                    "hostname": new.get("hostname", ""),
                    "added_ports": added,
                    "removed_ports": removed,
                    "category_before": old.get("category", ""),
                    "category_after": new.get("category", ""),
                }
            )

    return {
        "baseline_generated_at": previous.get("meta", {}).get("generated_at", ""),
        "current_generated_at": current.get("meta", {}).get("generated_at", ""),
        "new": [_brief(after[ip]) for ip in new_ips],
        "missing": [_brief(before[ip]) for ip in missing_ips],
        "changed": changed,
        "summary": {
            "new": len(new_ips),
            "missing": len(missing_ips),
            "changed": len(changed),
        },
    }


def load_baseline(path: str | Path) -> dict[str, Any]:
    path = Path(path)
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict) or "devices" not in data:
        raise ValueError(f"{path} does not look like an AB Search report")
    return data


def format_diff(diff: dict[str, Any]) -> str:
    summary = diff.get("summary", {})
    lines = [
        "Changes since baseline: "
        f"{summary.get('new', 0)} new, "
        f"{summary.get('missing', 0)} missing, "
        f"{summary.get('changed', 0)} changed"
    ]
    for item in diff.get("new", []):
        lines.append(f"  + {item['ip']}  {item.get('hostname') or item.get('vendor') or ''}")
    for item in diff.get("missing", []):
        lines.append(f"  - {item['ip']}  {item.get('hostname') or item.get('vendor') or ''}")
    for item in diff.get("changed", []):
        detail = []
        if item.get("added_ports"):
            detail.append("+" + ",".join(str(p) for p in item["added_ports"]))
        if item.get("removed_ports"):
            detail.append("-" + ",".join(str(p) for p in item["removed_ports"]))
        if item.get("category_before") != item.get("category_after"):
            detail.append("category changed")
        lines.append(f"  ~ {item['ip']}  {' '.join(detail)}")
    return "\n".join(lines)
