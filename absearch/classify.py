"""Heuristic device classification.

The categories are intentionally the five requested by the project brief:
Router, Computer, Phone, Possible CCTV camera, and Unknown device.  The
classifier combines independent signals (gateway address, vendor/OUI,
hostname, open ports, and safe service banners) and records the reasons so a
human can audit every guess.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .models import CAMERA, COMPUTER, PHONE, ROUTER, UNKNOWN, Device

CAMERA_VENDOR_HINTS = (
    "hikvision", "dahua", "axis", "reolink", "amcrest", "foscam",
    "uniview", "sunell", "vivotek", "hanwha", "wisenet", "ezviz",
    "annke", "lorex", "swann", "avigilon", "pelco", "mobotix",
    "geovision", "tapo", "wyze", "arlo", "bosch security",
)

ROUTER_VENDOR_HINTS = (
    "tp-link", "netgear", "asus", "linksys", "d-link", "dlink",
    "cisco", "ubiquiti", "unifi", "huawei", "zte", "fritz", "avm",
    "arris", "motorola", "belkin", "tenda", "mercusys", "mikrotik",
    "juniper", "fortinet", "sophos", "pfsense", "opnsense", "eero",
    "google nest", "nest", "orbi", "deco", "gl.inet", "gl-inet",
)

PHONE_VENDOR_HINTS = (
    "samsung", "xiaomi", "oneplus", "oppo", "vivo", "realme",
    "motorola mobility", "nothing technology", "fairphone",
)

COMPUTER_VENDOR_HINTS = (
    "apple", "intel", "dell", "lenovo", "hp", "hewlett", "asus",
    "acer", "micro-star", "msi", "gigabyte", "microsoft", "razer",
    "framework", "system76", "raspberry pi", "vmware", "qemu",
    "parallels", "toshiba", "sony", "fujitsu", "ibm",
)

CAMERA_HOST_HINTS = (
    "cam", "ipcam", "ipc", "nvr", "dvr", "hik", "dahua", "reolink",
    "axis", "foscam", "amcrest", "onvif", "cctv", "doorbell",
)

ROUTER_HOST_HINTS = (
    "router", "gateway", "gw", "fritz", "archer", "orbi", "deco",
    "unifi", "dream-machine", "dream router", "openwrt", "dd-wrt",
    "pfsense", "opnsense", "edgerouter", "amplifi", "eero",
)

PHONE_HOST_HINTS = (
    "iphone", "android", "phone", "pixel", "galaxy", "redmi",
    "oneplus", "huawei-p", "mate-", "moto-", "nothing-phone",
)

COMPUTER_HOST_HINTS = (
    "laptop", "desktop", "macbook", "imac", "thinkpad", "surface",
    "ubuntu", "fedora", "debian", "windows", "linux", "workstation",
    "pc-", "-pc", "raspberrypi", "raspberry-pi",
)

CAMERA_BANNER_HINTS = (
    "hikvision", "dahua", "reolink", "axis", "rtsp/", "onvif",
    "ip camera", "network camera", "nvr", "dvr",
)

# Port evidence.  A single strong camera port is enough to flag a device as
# "possible" CCTV, but we keep confidence below 1.0 because a non-camera
# device can occasionally expose a media port.
_CAMERA_PORT_SCORES = {
    554: 0.80,
    8554: 0.75,
    8899: 0.65,
    34567: 0.75,
    37777: 0.75,
    3702: 0.40,
    8000: 0.20,
    8080: 0.08,
    80: 0.03,
    443: 0.03,
}

_ROUTER_PORT_SCORES = {53: 0.35, 1900: 0.15, 5000: 0.15, 80: 0.08, 443: 0.08, 22: 0.08}
_PHONE_PORT_SCORES = {62078: 0.90}
_COMPUTER_PORT_SCORES = {
    445: 0.40,
    3389: 0.40,
    5900: 0.35,
    22: 0.15,
    139: 0.15,
    631: 0.10,
    5000: 0.05,
}


@dataclass
class Classification:
    category: str
    confidence: float
    reasons: list[str] = field(default_factory=list)

    @property
    def slug(self) -> str:
        return category_slug(self.category)


def _contains(haystack: str, needles: tuple[str, ...]) -> str:
    lowered = haystack.lower()
    for needle in needles:
        if needle in lowered:
            return needle
    return ""


def _port_set(device: Device) -> set[int]:
    return {port.port for port in device.ports if port.state == "open"}


def _banner_text(device: Device) -> str:
    return " ".join(port.banner for port in device.ports if port.banner)


def classify_device(device: Device, gateway_ip: str = "") -> Classification:
    scores = {CAMERA: 0.0, ROUTER: 0.0, PHONE: 0.0, COMPUTER: 0.0}
    reasons: dict[str, list[str]] = {key: [] for key in scores}
    ports = _port_set(device)
    vendor = device.vendor or ""
    hostname = device.hostname or ""
    banners = _banner_text(device)

    # Camera evidence -----------------------------------------------------
    for port in ports:
        if port in _CAMERA_PORT_SCORES:
            points = _CAMERA_PORT_SCORES[port]
            scores[CAMERA] += points
            if points >= 0.4:
                reasons[CAMERA].append(f"camera/media port {port}")
    camera_vendor = _contains(vendor, CAMERA_VENDOR_HINTS)
    if camera_vendor:
        scores[CAMERA] += 0.85
        reasons[CAMERA].append(f"camera vendor ({camera_vendor})")
    camera_host = _contains(hostname, CAMERA_HOST_HINTS)
    if camera_host:
        scores[CAMERA] += 0.55
        reasons[CAMERA].append(f"camera-like hostname ({camera_host})")
    camera_banner = _contains(banners, CAMERA_BANNER_HINTS)
    if camera_banner:
        scores[CAMERA] += 0.35
        reasons[CAMERA].append(f"camera service banner ({camera_banner})")

    # Router evidence -----------------------------------------------------
    if gateway_ip and device.ip == gateway_ip:
        scores[ROUTER] += 1.0
        device.is_gateway = True
        reasons[ROUTER].append("default gateway address")
    for port in ports:
        if port in _ROUTER_PORT_SCORES:
            scores[ROUTER] += _ROUTER_PORT_SCORES[port]
            if port in {53, 1900}:
                reasons[ROUTER].append(f"router service port {port}")
    router_vendor = _contains(vendor, ROUTER_VENDOR_HINTS)
    if router_vendor:
        scores[ROUTER] += 0.65
        reasons[ROUTER].append(f"router vendor ({router_vendor})")
    router_host = _contains(hostname, ROUTER_HOST_HINTS)
    if router_host:
        scores[ROUTER] += 0.55
        reasons[ROUTER].append(f"router-like hostname ({router_host})")
    if not gateway_ip and device.ip.endswith(".1") and ports & {80, 443}:
        scores[ROUTER] += 0.25
        reasons[ROUTER].append("first-address web interface")

    # Phone evidence ------------------------------------------------------
    for port in ports:
        if port in _PHONE_PORT_SCORES:
            scores[PHONE] += _PHONE_PORT_SCORES[port]
            reasons[PHONE].append(f"phone sync port {port}")
    phone_vendor = _contains(vendor, PHONE_VENDOR_HINTS)
    if phone_vendor:
        scores[PHONE] += 0.55
        reasons[PHONE].append(f"phone vendor ({phone_vendor})")
    phone_host = _contains(hostname, PHONE_HOST_HINTS)
    if phone_host:
        scores[PHONE] += 0.65
        reasons[PHONE].append(f"phone-like hostname ({phone_host})")

    # Computer evidence ---------------------------------------------------
    for port in ports:
        if port in _COMPUTER_PORT_SCORES:
            scores[COMPUTER] += _COMPUTER_PORT_SCORES[port]
            if port in {445, 3389, 5900, 22}:
                reasons[COMPUTER].append(f"desktop service port {port}")
    computer_vendor = _contains(vendor, COMPUTER_VENDOR_HINTS)
    if computer_vendor:
        scores[COMPUTER] += 0.45
        reasons[COMPUTER].append(f"computer vendor ({computer_vendor})")
    computer_host = _contains(hostname, COMPUTER_HOST_HINTS)
    if computer_host:
        scores[COMPUTER] += 0.45
        reasons[COMPUTER].append(f"computer-like hostname ({computer_host})")

    # A printer that only speaks IPP is a peripheral, not a computer.  Keep
    # the Computer score low unless there is other desktop evidence.
    if 631 in ports and not (ports & {445, 3389, 5900, 22, 139}) and not computer_host:
        scores[COMPUTER] = min(scores[COMPUTER], 0.20)

    if not any(scores.values()):
        return Classification(
            UNKNOWN,
            0.25,
            ["no strong router, computer, phone, or camera signals"],
        )

    best_category = max(scores, key=lambda key: scores[key])
    best_score = scores[best_category]
    if best_score < 0.45:
        return Classification(
            UNKNOWN,
            round(min(0.54, 0.30 + best_score), 2),
            ["weak signals only; manual verification recommended"],
        )

    confidence = round(min(0.99, best_score), 2)
    category_reasons = reasons[best_category] or ["matched heuristic"]
    return Classification(best_category, confidence, category_reasons)


def apply_classification(device: Device, gateway_ip: str = "") -> Device:
    result = classify_device(device, gateway_ip=gateway_ip)
    device.category = result.category
    device.confidence = result.confidence
    existing = set(device.notes)
    for reason in result.reasons:
        if reason not in existing:
            device.notes.append(reason)
            existing.add(reason)
    return device


def category_slug(category: str) -> str:
    return {
        CAMERA: "camera",
        ROUTER: "router",
        COMPUTER: "computer",
        PHONE: "phone",
        UNKNOWN: "unknown",
    }.get(category, "unknown")


def category_label(slug: str) -> str:
    return {
        "camera": CAMERA,
        "router": ROUTER,
        "computer": COMPUTER,
        "phone": PHONE,
        "unknown": UNKNOWN,
    }.get(slug, UNKNOWN)


def camera_likely(device: Device) -> bool:
    """Return True when a device has explicit camera evidence."""

    return device.category == CAMERA


def summarize_reasons(device: Device, limit: int = 3) -> str:
    reasons = [note for note in device.notes if not note.startswith("matched ")]
    return "; ".join(reasons[:limit]) if reasons else "No strong signature"
