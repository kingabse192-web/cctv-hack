from absearch.models import Device, PortInfo
from absearch.risk import assess, summary_counts


def test_risk_for_camera_with_rtsp_is_high():
    device = Device(
        ip="192.0.2.64", category="Possible CCTV camera", credential_vendor="hikvision",
        ports=[PortInfo(80, service="http"), PortInfo(554, service="rtsp")],
    )
    result = assess(device)
    assert result.score >= 60
    assert result.level in {"High", "Critical"}
    assert any("RTSP" in finding for finding in result.findings)


def test_risk_for_quiet_device_is_info():
    result = assess(Device(ip="192.0.2.9", category="Unknown device"))
    assert result.level == "Info"
    assert result.score == 0
    assert result.findings


def test_risk_counts():
    high = assess(Device(ip="1", ports=[PortInfo(23)]))
    low = assess(Device(ip="2", ports=[PortInfo(22)]))
    counts = summary_counts([high, low])
    assert sum(counts.values()) == 2
    assert counts["High"] >= 1 or counts["Medium"] >= 1
