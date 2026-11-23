import csv
import io
import json

from absearch.bluetooth import BluetoothDevice, BluetoothScan
from absearch.demo import demo_bluetooth, demo_devices
from absearch.models import Device
from absearch.report import (
    SCHEMA,
    build_report,
    devices_csv,
    load_report,
    render_dashboard,
    safe_json,
    write_reports,
)


def make_report():
    return build_report(
        network="192.168.1.0/24",
        interface="wlan0",
        gateway="192.168.1.1",
        devices=demo_devices(),
        bluetooth=BluetoothScan(devices=demo_bluetooth(), supported=True),
        mode="demo",
    )


def test_build_report_summary_and_safety():
    report = make_report()
    assert report["schema"] == SCHEMA
    assert report["summary"]["total"] == 8
    assert report["summary"]["cameras"] == 2
    assert report["safety"]["credential_attempts"] == 0
    assert report["safety"]["stream_access"] is False
    assert report["meta"]["mode"] == "demo"


def test_write_reports_and_reload(tmp_path):
    report = make_report()
    paths = write_reports(report, tmp_path)
    assert set(paths) == {"json", "csv", "html"}
    loaded = load_report(paths["json"])
    assert loaded["summary"]["total"] == 8
    csv_text = paths["csv"].read_text(encoding="utf-8")
    rows = list(csv.DictReader(io.StringIO(csv_text)))
    assert len(rows) == 8
    assert rows[0]["ip"] == "192.168.1.1"
    html_text = paths["html"].read_text(encoding="utf-8")
    assert "AB Search" in html_text
    assert "Demo data" in html_text
    assert "report.json" in html_text


def test_html_escapes_device_supplied_values():
    device = Device(ip="192.0.2.5", hostname="<img src=x onerror=alert(1)>", vendor="<script>x</script>")
    report = build_report(
        network="192.0.2.0/24", devices=[device],
        bluetooth=BluetoothScan(devices=[BluetoothDevice("AA:BB", "<b>bt</b>")], supported=True),
    )
    rendered = render_dashboard(report)
    assert "<img src=x" not in rendered
    assert "<script>x</script>" not in rendered
    assert "\\u003cimg" in rendered
    assert "\\u003cscript" in rendered


def test_safe_json_escapes_script_breakout():
    text = safe_json({"value": "</script><script>alert(1)</script>"}, indent=None)
    assert "</script>" not in text
    assert "\\u003c/script" in text
    assert json.loads(text)["value"] == "</script><script>alert(1)</script>"
