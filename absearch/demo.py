"""Deterministic demo inventory.

``absearch --demo`` uses this data so the CLI and dashboard can be evaluated
without scanning a real network.  It is intentionally labelled as demo data
in every report.
"""

from __future__ import annotations

from .bluetooth import BluetoothDevice
from .classify import apply_classification
from .models import Device, PortInfo
from .services import rtsp_urls, web_urls

DEMO_NETWORK = "192.168.1.0/24"
DEMO_GATEWAY = "192.168.1.1"
DEMO_INTERFACE = "wlan0 (demo)"


def _port(port: int, service: str = "", banner: str = "") -> PortInfo:
    return PortInfo(port=port, service=service, state="open", banner=banner)


def demo_devices() -> list[Device]:
    devices = [
        Device(
            ip="192.168.1.1",
            mac="50:C7:BF:12:34:56",
            vendor="TP-Link",
            hostname="archer-ax55",
            ports=[
                _port(53, "dns"),
                _port(80, "http", "HTTP/1.1 200 OK Server: Archer AX55"),
                _port(443, "https"),
                _port(1900, "ssdp"),
            ],
            notes=["demo router"],
        ),
        Device(
            ip="192.168.1.64",
            mac="4C:BD:8F:AA:10:20",
            vendor="Hikvision",
            hostname="IPC-64",
            ports=[
                _port(80, "http", "HTTP/1.1 200 OK Server: webs"),
                _port(554, "rtsp", "RTSP/1.0 200 OK"),
                _port(8000, "camera-sdk"),
                _port(8899, "camera-web"),
            ],
            notes=["demo camera"],
        ),
        Device(
            ip="192.168.1.65",
            mac="EC:71:DB:0A:0B:0C",
            vendor="Reolink",
            hostname="Reolink-E1",
            ports=[
                _port(80, "http", "HTTP/1.1 200 OK Server: Reolink"),
                _port(554, "rtsp", "RTSP/1.0 200 OK"),
                _port(9000, "http-alt"),
            ],
            notes=["demo camera"],
        ),
        Device(
            ip="192.168.1.23",
            mac="F0:18:98:11:22:33",
            vendor="Apple",
            hostname="iPhone",
            ports=[_port(62078, "phone-sync")],
            notes=["demo phone"],
        ),
        Device(
            ip="192.168.1.34",
            mac="A4:83:E7:44:55:66",
            vendor="Apple",
            hostname="macbook-pro",
            ports=[
                _port(22, "ssh", "SSH-2.0-OpenSSH_9.8"),
                _port(445, "smb"),
                _port(5000, "upnp"),
            ],
            notes=["demo computer"],
        ),
        Device(
            ip="192.168.1.41",
            mac="B8:2A:72:77:88:99",
            vendor="Dell",
            hostname="DESKTOP-7F2A",
            ports=[_port(445, "smb"), _port(3389, "rdp")],
            notes=["demo computer"],
        ),
        Device(
            ip="192.168.1.77",
            mac="9C:B6:54:AB:CD:EF",
            vendor="HP",
            hostname="HP-LaserJet",
            ports=[_port(80, "http"), _port(631, "ipp")],
            notes=["demo printer"],
        ),
        Device(
            ip="192.168.1.90",
            mac="DA:A1:19:00:00:90",
            vendor="",
            hostname="",
            ports=[_port(8080, "http-alt")],
            notes=["demo unknown device"],
        ),
    ]
    for device in devices:
        apply_classification(device, gateway_ip=DEMO_GATEWAY)
        device.web = web_urls(device.ip, device.ports)
        device.rtsp = rtsp_urls(device.ip, device.ports)
    return devices


def demo_bluetooth() -> list[BluetoothDevice]:
    return [
        BluetoothDevice(
            address="D4:36:39:00:11:22",
            name="Galaxy Buds3",
            rssi=-58,
            vendor="Samsung Electronics",
            services=["0000110b-0000-1000-8000-00805f9b34fb"],
        ),
        BluetoothDevice(
            address="F8:4D:89:33:44:55",
            name="Tile Mate",
            rssi=-74,
            vendor="Tile, Inc.",
            services=[],
        ),
        BluetoothDevice(
            address="60:AB:D2:66:77:88",
            name="BLE Sensor",
            rssi=-83,
            vendor="Unknown",
            services=["0000180f-0000-1000-8000-00805f9b34fb"],
        ),
    ]
