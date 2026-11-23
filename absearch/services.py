"""Safe TCP service checks used by the inventory scanner.

Only a TCP connect and, optionally, a harmless protocol greeting are sent:

* HTTP: ``HEAD / HTTP/1.0``
* RTSP: ``OPTIONS rtsp://... RTSP/1.0`` (no DESCRIBE, SETUP, or PLAY)
* Other services: read the banner the server volunteers

No credentials are sent, no authentication is attempted, and no video stream
is requested.
"""

from __future__ import annotations

import re
import socket
import ssl
from concurrent.futures import ThreadPoolExecutor, as_completed
from .models import PortInfo

COMMON_PORTS: tuple[int, ...] = (
    21, 22, 23, 25, 53, 80, 110, 139, 143, 443,
    445, 554, 631, 1883, 1900, 3389, 3702, 5000,
    5900, 8000, 8080, 8081, 8443, 8554, 8888, 8899,
    9000, 34567, 37777,
)

CAMERA_PORTS: tuple[int, ...] = (
    80, 443, 554, 8000, 8080, 8443, 8554, 8899, 34567, 37777,
)

WEB_PORTS: tuple[int, ...] = (80, 443, 8000, 8080, 8081, 8443, 8888, 9000)
RTSP_PORTS: tuple[int, ...] = (554, 8554)

SERVICE_BY_PORT: dict[int, str] = {
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    53: "dns",
    80: "http",
    110: "pop3",
    139: "netbios",
    143: "imap",
    443: "https",
    445: "smb",
    554: "rtsp",
    631: "ipp",
    1883: "mqtt",
    1900: "ssdp",
    3389: "rdp",
    3702: "onvif",
    5000: "upnp",
    5900: "vnc",
    8000: "http-alt",
    8080: "http-alt",
    8081: "http-alt",
    8443: "https-alt",
    8554: "rtsp",
    8888: "http-alt",
    8899: "camera-web",
    9000: "http-alt",
    34567: "camera-sdk",
    37777: "dahua-sdk",
}

_CAMERA_HINTS = (
    "hikvision", "dahua", "axis", "reolink", "amcrest", "foscam",
    "uniview", "sunell", "vivotek", "bosch security", "hanwha",
    "wisenet", "tapo", "wyze", "arlo", "ezviz", "annke", "lorex",
    "swann", "avigilon", "pelco", "mobotix", "geovision",
)

_TLS_PORTS = {443, 8443}
_HTTP_PORTS = {80, 8000, 8080, 8081, 8888, 9000}


def _safe_snippet(value: bytes | str, limit: int = 180) -> str:
    if isinstance(value, bytes):
        text = value.decode("latin-1", errors="replace")
    else:
        text = value
    text = re.sub(r"\x1b\[[0-9;]*[A-Za-z]", "", text)
    text = "".join(char if char.isprintable() or char in "\r\n\t" else " " for char in text)
    text = " ".join(text.split())
    return text[:limit]


def _server_header(banner: str) -> str:
    match = re.search(r"(?i)\bserver\s*:\s*([^\r\n]+)", banner)
    return match.group(1).strip() if match else ""


def service_name(port: int, banner: str = "", tls: bool = False) -> str:
    base = SERVICE_BY_PORT.get(port, "unknown")
    lowered = banner.lower()
    if "rtsp/" in lowered or "rtsp" in lowered and port in RTSP_PORTS:
        return "rtsp"
    if lowered.startswith("ssh-"):
        return "ssh"
    if lowered.startswith("220") or "ftp" in lowered and port == 21:
        return "ftp"
    if "http/" in lowered:
        return "https" if tls or port in _TLS_PORTS else "http"
    if port in _TLS_PORTS:
        return "https" if not banner else base
    return base


def is_camera_service(port: int, service: str, banner: str) -> bool:
    if port in CAMERA_PORTS and port not in {80, 443, 8080, 8443}:
        return True
    if service == "rtsp":
        return True
    lowered = (service + " " + banner).lower()
    return any(hint in lowered for hint in _CAMERA_HINTS)


def _http_probe(host: str, port: int, timeout: float, tls: bool) -> tuple[str, str]:
    request = f"HEAD / HTTP/1.0\r\nHost: {host}\r\nUser-Agent: absearch\r\nConnection: close\r\n\r\n".encode()
    raw = b""
    if tls:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            with context.wrap_socket(sock, server_hostname=host) as tls_sock:
                tls_sock.sendall(request)
                raw = tls_sock.recv(1024)
    else:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            sock.sendall(request)
            raw = sock.recv(1024)
    banner = _safe_snippet(raw)
    service = "https" if tls or banner.startswith("HTTP/") and port in _TLS_PORTS else "http"
    if not banner.startswith("HTTP/"):
        service = "https" if tls else SERVICE_BY_PORT.get(port, "http-alt")
    return service, banner


def _rtsp_probe(host: str, port: int, timeout: float) -> tuple[str, str]:
    request = (
        f"OPTIONS rtsp://{host}:{port}/ RTSP/1.0\r\n"
        "CSeq: 1\r\n"
        "User-Agent: absearch\r\n"
        "\r\n"
    ).encode()
    with socket.create_connection((host, port), timeout=timeout) as sock:
        sock.settimeout(timeout)
        sock.sendall(request)
        raw = sock.recv(1024)
    banner = _safe_snippet(raw)
    return ("rtsp" if banner.startswith("RTSP/") else "rtsp-ish"), banner


def _passive_banner(host: str, port: int, timeout: float) -> str:
    with socket.create_connection((host, port), timeout=timeout) as sock:
        sock.settimeout(min(timeout, 0.6))
        try:
            return _safe_snippet(sock.recv(512))
        except socket.timeout:
            return ""


def probe_port(
    host: str,
    port: int,
    timeout: float = 0.7,
    grab_banner: bool = False,
) -> PortInfo | None:
    """Check one TCP port.  Returns ``None`` when the port is closed/filtered."""

    try:
        with socket.create_connection((host, port), timeout=timeout):
            pass
    except (OSError, socket.timeout):
        return None

    service = SERVICE_BY_PORT.get(port, "unknown")
    banner = ""
    tls = port in _TLS_PORTS

    if grab_banner:
        try:
            if port in _HTTP_PORTS or port in _TLS_PORTS:
                service, banner = _http_probe(host, port, timeout, tls)
            elif port in RTSP_PORTS:
                service, banner = _rtsp_probe(host, port, timeout)
            elif port in {21, 22, 23, 25, 110, 143}:
                banner = _passive_banner(host, port, timeout)
                service = service_name(port, banner, tls)
        except (OSError, socket.timeout, ssl.SSLError):
            # The port is open even if it did not answer our polite probe.
            banner = ""
            service = SERVICE_BY_PORT.get(port, "unknown")

    return PortInfo(
        port=port,
        protocol="tcp",
        service=service,
        state="open",
        banner=banner,
    )


def probe_ports(
    hosts: list[str],
    ports: tuple[int, ...] | list[int] = COMMON_PORTS,
    timeout: float = 0.7,
    grab_banners: bool = False,
    workers: int = 48,
) -> dict[str, list[PortInfo]]:
    """Probe many host/port pairs concurrently."""

    results: dict[str, list[PortInfo]] = {host: [] for host in hosts}
    tasks = [(host, int(port)) for host in hosts for port in ports]
    if not tasks:
        return results

    with ThreadPoolExecutor(max_workers=max(1, min(workers, len(tasks)))) as pool:
        futures = {
            pool.submit(probe_port, host, port, timeout, grab_banners): (host, port)
            for host, port in tasks
        }
        for future in as_completed(futures):
            host, port = futures[future]
            try:
                info = future.result()
            except Exception:
                info = None
            if info is not None:
                results[host].append(info)

    for host in results:
        results[host].sort(key=lambda item: item.port)
    return results


def web_urls(ip: str, ports: list[PortInfo]) -> list[str]:
    urls: list[str] = []
    for info in ports:
        if info.state != "open":
            continue
        if not (
            info.port in _HTTP_PORTS
            or info.port in _TLS_PORTS
            or info.service in {"http", "https", "http-alt", "https-alt"}
        ):
            continue
        # Port 8000/9000 is often a vendor SDK port.  Include it only when
        # the HTTP probe actually saw a web server.
        if info.port in {8000, 9000} and not info.banner.startswith("HTTP/"):
            continue
        scheme = "https" if info.port in _TLS_PORTS or info.service.startswith("https") else "http"
        default_port = (scheme == "https" and info.port == 443) or (scheme == "http" and info.port == 80)
        url = f"{scheme}://{ip}" if default_port else f"{scheme}://{ip}:{info.port}"
        if url not in urls:
            urls.append(url)
    # Prefer standard ports first, then nicer-looking URLs.
    urls.sort(key=lambda value: (":443" in value, ":80" in value, len(value)))
    return urls


def rtsp_urls(ip: str, ports: list[PortInfo]) -> list[str]:
    urls: list[str] = []
    for info in ports:
        if info.state != "open":
            continue
        if info.port in RTSP_PORTS or info.service == "rtsp":
            url = f"rtsp://{ip}:{info.port}/"
            if url not in urls:
                urls.append(url)
    return urls


def split_ports(value: str) -> list[int]:
    """Parse ``22,80,8000-8010`` into a sorted list of valid ports."""

    ports: set[int] = set()
    for chunk in value.split(","):
        chunk = chunk.strip()
        if not chunk:
            continue
        if "-" in chunk:
            start_text, end_text = chunk.split("-", 1)
            try:
                start, end = int(start_text), int(end_text)
            except ValueError as exc:
                raise ValueError(f"Invalid port range {chunk!r}") from exc
            if start > end:
                start, end = end, start
            ports.update(range(max(1, start), min(65535, end) + 1))
        else:
            try:
                port = int(chunk)
            except ValueError as exc:
                raise ValueError(f"Invalid port {chunk!r}") from exc
            if 1 <= port <= 65535:
                ports.add(port)
    return sorted(ports)
