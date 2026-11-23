import pytest

from absearch.models import PortInfo
from absearch.services import (
    CAMERA_PORTS,
    rtsp_urls,
    service_name,
    split_ports,
    web_urls,
)


def test_split_ports_handles_ranges_and_junk():
    assert split_ports("22, 80, 8000-8002, 70000") == [22, 80, 8000, 8001, 8002]
    with pytest.raises(ValueError):
        split_ports("abc")


def test_service_name_detects_protocols():
    assert service_name(554, "RTSP/1.0 200 OK") == "rtsp"
    assert service_name(22, "SSH-2.0-OpenSSH_9.8") == "ssh"
    assert service_name(80, "HTTP/1.1 200 OK") == "http"
    assert service_name(8443, "HTTP/1.1 200 OK", tls=True) == "https"
    assert 554 in CAMERA_PORTS


def test_web_urls_prefer_standard_ports_and_require_http_banner_on_8000():
    ports = [
        PortInfo(80, service="http", banner="HTTP/1.1 200 OK"),
        PortInfo(443, service="https"),
        PortInfo(8000, service="camera-sdk", banner=""),
        PortInfo(8080, service="http", banner="HTTP/1.1 200 OK"),
    ]
    urls = web_urls("192.168.1.64", ports)
    assert "http://192.168.1.64" in urls
    assert "https://192.168.1.64" in urls
    assert "http://192.168.1.64:8080" in urls
    assert not any(":8000" in url for url in urls)


def test_rtsp_urls():
    ports = [PortInfo(554, service="rtsp"), PortInfo(8554, service="rtsp")]
    assert rtsp_urls("192.168.1.64", ports) == [
        "rtsp://192.168.1.64:554/",
        "rtsp://192.168.1.64:8554/",
    ]
