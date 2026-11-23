"""End-to-end test of the live pipeline with all network I/O mocked."""

import json

from absearch import cli, net
from absearch.bluetooth import BluetoothDevice, BluetoothScan
from absearch.discovery import DiscoveryHint
from absearch.models import PortInfo
from absearch.net import HostRecord, Interface


def test_full_live_pipeline_with_mocked_io(tmp_path, monkeypatch):
    hosts = [
        HostRecord(ip="192.0.2.1", mac="50:C7:BF:12:34:56", vendor="TP-Link", hostname="gateway"),
        HostRecord(ip="192.0.2.64", mac="4C:BD:8F:AA:10:20", vendor="Hikvision", hostname="IPC-64"),
        HostRecord(ip="192.0.2.23", mac="F0:18:98:11:22:33", vendor="Apple", hostname="iPhone"),
    ]
    probed = {
        "192.0.2.1": [PortInfo(53, service="dns"), PortInfo(80, service="http")],
        "192.0.2.64": [PortInfo(80, service="http"), PortInfo(554, service="rtsp", banner="RTSP/1.0 200 OK")],
        "192.0.2.23": [PortInfo(62078, service="phone-sync")],
    }
    hints = [
        DiscoveryHint(
            ip="192.0.2.64", name="Front Door", service="onvif", source="onvif",
            details={"vendor": "Hikvision"},
        )
    ]
    bluetooth = BluetoothScan(devices=[BluetoothDevice("AA:BB:CC:00:11:22", "Buds", -60)], supported=True)
    interface = Interface(
        name="eth0", ip="192.0.2.10", netmask="255.255.255.0",
        cidr="192.0.2.0/24", is_up=True, gateway="192.0.2.1",
    )

    monkeypatch.setattr(net, "gateway_for_network", lambda *a, **k: "192.0.2.1")
    monkeypatch.setattr(cli, "discover_hosts", lambda *a, **k: hosts)
    monkeypatch.setattr(cli, "probe_ports", lambda *a, **k: probed)
    monkeypatch.setattr(cli, "scan_bluetooth", lambda *a, **k: bluetooth)
    monkeypatch.setattr(cli, "discover_hints", lambda *a, **k: hints)
    monkeypatch.setattr(cli, "detect_interfaces", lambda *a, **k: [interface])

    out = tmp_path / "reports"
    code = cli.main([
        "--network", "192.0.2.0/24", "--yes", "--deep", "--no-open",
        "--no-color", "--quiet", "--output", str(out),
    ])
    assert code == 0

    paths = list(out.glob("scan-*/report.json"))
    assert len(paths) == 1
    report = json.loads(paths[0].read_text(encoding="utf-8"))

    assert report["summary"]["total"] == 3
    assert report["summary"]["cameras"] == 1
    assert report["summary"]["routers"] == 1
    assert report["summary"]["phones"] == 1
    assert report["summary"]["bluetooth_devices"] == 1
    assert report["meta"]["options"]["deep"] is True
    assert report["safety"]["credential_attempts"] == 0

    by_ip = {device["ip"]: device for device in report["devices"]}
    assert by_ip["192.0.2.64"]["category"] == "Possible CCTV camera"
    assert any("onvif" in hint for hint in by_ip["192.0.2.64"]["hints"])
    assert by_ip["192.0.2.64"]["risk"]["level"] in {"High", "Critical", "Medium"}
    assert by_ip["192.0.2.1"]["is_gateway"] is True
    assert (paths[0].parent / "index.html").exists()
    assert (paths[0].parent / "devices.csv").exists()
