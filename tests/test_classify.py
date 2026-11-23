from absearch.classify import CAMERA, COMPUTER, PHONE, ROUTER, UNKNOWN, classify_device
from absearch.demo import DEMO_GATEWAY, demo_devices
from absearch.models import Device, PortInfo


def test_demo_devices_are_classified():
    devices = {device.ip: device for device in demo_devices()}
    assert devices["192.168.1.1"].category == ROUTER
    assert devices["192.168.1.1"].is_gateway is True
    assert devices["192.168.1.64"].category == CAMERA
    assert devices["192.168.1.65"].category == CAMERA
    assert devices["192.168.1.23"].category == PHONE
    assert devices["192.168.1.34"].category == COMPUTER
    assert devices["192.168.1.41"].category == COMPUTER
    assert devices["192.168.1.77"].category == UNKNOWN  # printer peripheral
    assert devices["192.168.1.90"].category == UNKNOWN


def test_camera_port_alone_is_enough():
    device = Device(ip="10.0.0.5", vendor="", hostname="", ports=[PortInfo(554, service="rtsp")])
    result = classify_device(device)
    assert result.category == CAMERA
    assert result.confidence >= 0.75


def test_unknown_device_has_low_confidence_and_reason():
    device = Device(ip="10.0.0.9")
    result = classify_device(device)
    assert result.category == UNKNOWN
    assert result.reasons


def test_gateway_overrides_other_weak_signals():
    device = Device(
        ip="192.168.5.1",
        hostname="gateway",
        vendor="TP-Link",
        ports=[PortInfo(80, service="http")],
    )
    result = classify_device(device, gateway_ip="192.168.5.1")
    assert result.category == ROUTER
    assert device.is_gateway is True
