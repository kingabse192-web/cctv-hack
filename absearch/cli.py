"""Command-line interface for AB Search."""

from __future__ import annotations

import argparse
import os
import sys
import time
import webbrowser
from pathlib import Path

from . import __version__
from .banner import print_banner
from .bluetooth import BluetoothScan, scan_bluetooth
from .classify import apply_classification, category_slug
from .credentials import load_credential_store
from .demo import DEMO_GATEWAY, DEMO_INTERFACE, DEMO_NETWORK, demo_bluetooth, demo_devices
from .discovery import discover_hints, hints_by_ip
from .history import compare_reports, format_diff, load_baseline
from .models import Device
from .net import (
    choose_interface,
    detect_interfaces,
    discover_hosts,
    network_hosts,
    parse_network,
)
from .oui import clean_vendor
from .report import build_report, print_report_paths, report_path, write_reports
from .services import (
    CAMERA_PORTS,
    COMMON_PORTS,
    probe_ports,
    rtsp_urls,
    split_ports,
    web_urls,
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="absearch",
        description=(
            "Inventory devices on a local Wi-Fi/Ethernet network, identify "
            "possible CCTV cameras, and generate an offline dashboard. "
            "Authorized networks only."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "examples:\n"
            "  absearch --demo --web          # safe demo dashboard\n"
            "  absearch --yes                 # scan detected LAN without prompts\n"
            "  absearch --network 192.168.1.0/24 --services --open\n"
            "  absearch --deep --camera-ports --yes     # ONVIF/mDNS + TLS evidence\n"
            "  absearch --baseline reports/old/report.json --yes\n"
            "  absearch --watch 60 --yes --quiet        # rescan every 60 seconds\n"
        ),
    )
    parser.add_argument("--version", action="version", version=f"AB Search {__version__}")
    parser.add_argument("--demo", action="store_true", help="use sample data; performs no scan")
    parser.add_argument("--network", metavar="CIDR", help="IPv4 network to scan (default: detect)")
    parser.add_argument("--interface", metavar="NAME", help="network interface to use")
    parser.add_argument("--ports", metavar="LIST", help="TCP ports: 22,80,8000-8010")
    parser.add_argument("--camera-ports", action="store_true", help="include common CCTV ports")
    parser.add_argument("--no-ports", action="store_true", help="skip TCP port checks")
    service_group = parser.add_mutually_exclusive_group()
    service_group.add_argument("--services", dest="services", action="store_true", default=True,
                               help="grab safe service banners (default)")
    service_group.add_argument("--no-services", dest="services", action="store_false",
                               help="only check whether ports are open")
    parser.add_argument("--timeout", type=float, default=0.7, metavar="SEC",
                        help="per-connection timeout (default: 0.7)")
    parser.add_argument("--workers", type=int, default=48, help="concurrent port checks (default: 48)")
    bt_group = parser.add_mutually_exclusive_group()
    bt_group.add_argument("--bluetooth", dest="bluetooth", action="store_true", default=True,
                          help="scan BLE advertisements (default)")
    bt_group.add_argument("--no-bluetooth", dest="bluetooth", action="store_false",
                          help="skip Bluetooth discovery")
    parser.add_argument("--bt-timeout", type=float, default=6.0, metavar="SEC",
                        help="Bluetooth scan duration (default: 6)")
    parser.add_argument("--deep", action="store_true",
                        help="advanced discovery (mDNS/SSDP/ONVIF) + TLS certificate evidence")
    parser.add_argument("--discovery-timeout", type=float, default=2.5, metavar="SEC",
                        help="duration of each advanced discovery probe (default: 2.5)")
    parser.add_argument("--baseline", metavar="FILE",
                        help="compare this scan against a previous report.json")
    parser.add_argument("--watch", type=float, default=0.0, metavar="SEC",
                        help="repeat the scan every SEC seconds (0 = single scan)")
    parser.add_argument("--output", default="inventory_reports", metavar="DIR",
                        help="base report directory (default: ./inventory_reports)")
    parser.add_argument("--format", default="json,csv,html", metavar="LIST",
                        help="report formats: json,csv,html (default: all)")
    parser.add_argument("--web", action="store_true", help="serve the dashboard on localhost")
    parser.add_argument("--web-port", type=int, default=8765, help="dashboard port (default: 8765)")
    parser.add_argument("--no-open", action="store_true", help="do not open a browser or management page")
    parser.add_argument("--open", dest="open_page", action="store_true",
                        help="interactively open a device management page")
    parser.add_argument("--yes", action="store_true", help="confirm authorization without a prompt")
    parser.add_argument("--allow-public", action="store_true", help="allow a non-private network (use with care)")
    parser.add_argument("--allow-large", action="store_true", help="allow networks with more than 1024 hosts")
    parser.add_argument("--max-hosts", type=int, default=1024, help="refuse larger networks (default: 1024)")
    parser.add_argument("--credentials", action="append", default=[], metavar="FILE",
                        help="additional credential reference file (repeatable)")
    parser.add_argument("--no-color", action="store_true", help="disable coloured output")
    parser.add_argument("--quiet", action="store_true", help="print only the report paths")
    return parser


def _console(no_color: bool = False):
    try:
        from rich.console import Console

        return Console(no_color=no_color, highlight=False, soft_wrap=False)
    except Exception:  # pragma: no cover - rich is optional
        return None


def _say(text: str, console=None, style: str = "") -> None:
    if console is not None:
        console.print(text, style=style or None)
    else:
        print(text)


def require_authorization(assume_yes: bool, demo: bool, console=None) -> bool:
    if demo:
        return True
    _say(
        "Authorized use only: scan networks and devices you own or are "
        "explicitly permitted to test.",
        console,
        "bold red",
    )
    if assume_yes or os.environ.get("AUTHORIZED", "").strip() == "1":
        return True
    try:
        answer = input("Type 'I AUTHORIZE' to continue: ").strip()
    except (EOFError, OSError):
        return False
    return answer.upper() == "I AUTHORIZE"


def _select_network(args, console=None):
    if args.network:
        network = parse_network(args.network)
        gateway = ""
    else:
        interfaces = detect_interfaces()
        if not interfaces and not args.interface:
            raise ValueError(
                "No local network detected. Use --network 192.168.1.0/24 or "
                "install psutil and connect to Wi-Fi/Ethernet."
            )
        if interfaces and not args.quiet:
            _say("Detected local networks:", console, "bold")
            for interface in interfaces:
                marker = "*" if interface.gateway else " "
                _say(f"  {marker} {interface.display}", console)
        interface = choose_interface(interfaces, args.interface or "")
        network = parse_network(interface.cidr)
        gateway = interface.gateway

    from .net import gateway_for_network

    if not gateway:
        gateway = gateway_for_network(network)
    host_count = len(network_hosts(network))
    if host_count > args.max_hosts and not args.allow_large:
        raise ValueError(
            f"Network {network} has {host_count} usable addresses, above the "
            f"--max-hosts limit of {args.max_hosts}. Narrow it to a smaller "
            "subnet or pass --allow-large if you are authorized."
        )
    if not args.allow_public and not network.is_private:
        raise ValueError(
            f"Network {network} is not private. Pass --allow-public only if "
            "you are explicitly authorized to scan it."
        )
    return network, gateway


def _selected_ports(args) -> list[int]:
    if args.no_ports:
        return []
    if args.ports:
        ports = set(split_ports(args.ports))
    else:
        ports = set(COMMON_PORTS)
    if args.camera_ports:
        ports.update(CAMERA_PORTS)
    return sorted(ports)


def _collect_devices(args, network, gateway, store, console=None) -> list[Device]:
    hosts = discover_hosts(network, timeout=max(30, args.timeout * 40), resolve_names=True)
    devices = [
        Device(
            ip=host.ip,
            mac=host.mac,
            vendor=clean_vendor(host.vendor),
            hostname=host.hostname,
            notes=list(host.notes),
        )
        for host in hosts
    ]
    ports = _selected_ports(args)
    probed: dict[str, list] = {device.ip: [] for device in devices}
    if devices and ports:
        if not args.quiet:
            _say(
                f"Checking {len(ports)} TCP ports on {len(devices)} device(s)…",
                console,
                "dim",
            )
        probed = probe_ports(
            [device.ip for device in devices],
            ports,
            timeout=args.timeout,
            grab_banners=args.services,
            workers=args.workers,
            deep=args.deep,
        )

    grouped_hints: dict[str, list] = {}
    if args.deep and not args.quiet:
        _say("Running advanced discovery (mDNS, SSDP, ONVIF)…", console, "dim")
    if args.deep:
        grouped_hints = hints_by_ip(discover_hints(timeout=args.discovery_timeout))

    for device in devices:
        info = probed.get(device.ip, [])
        device.ports = info
        device.web = web_urls(device.ip, info)
        device.rtsp = rtsp_urls(device.ip, info)
        for hint in grouped_hints.get(device.ip, []):
            device.hints.append(hint.to_text())
            if not device.hostname and hint.name:
                device.hostname = hint.name
            if not device.vendor and hint.details.get("vendor"):
                device.vendor = clean_vendor(hint.details["vendor"])
        apply_classification(device, gateway_ip=gateway)
        store.for_device(device)
    return devices


def _print_devices(devices: list[Device], console=None) -> None:
    if not devices:
        _say("No devices were discovered on this network.", console, "yellow")
        return
    if console is not None:
        try:
            from rich.table import Table

            table = Table(title="Discovered devices", show_lines=False, header_style="bold")
            table.add_column("Category", style="bold")
            table.add_column("IP", style="cyan", no_wrap=True)
            table.add_column("Hostname", style="white")
            table.add_column("Vendor", style="magenta")
            table.add_column("MAC", style="cyan")
            table.add_column("Ports", style="green")
            table.add_column("Links")
            styles = {
                "camera": "bold red", "router": "bold blue",
                "computer": "bold green", "phone": "bold magenta",
                "unknown": "dim",
            }
            short_category = {
                "camera": "CCTV", "router": "Router", "computer": "Computer",
                "phone": "Phone", "unknown": "Unknown",
            }
            for device in devices:
                links = []
                if device.web:
                    links.append("web")
                if device.rtsp:
                    links.append("rtsp")
                table.add_row(
                    short_category.get(category_slug(device.category), device.category),
                    device.ip,
                    device.hostname or "—",
                    device.vendor or "—",
                    device.mac or "—",
                    device.port_summary,
                    ", ".join(links) or "—",
                    style=styles.get(category_slug(device.category)),
                )
            console.print(table)
            return
        except Exception:  # pragma: no cover
            pass

    header = f"{'CATEGORY':<22} {'IP':<16} {'HOSTNAME':<24} {'VENDOR':<20} PORTS"
    print(header)
    print("-" * len(header))
    for device in devices:
        print(
            f"{device.category:<22} {device.ip:<16} {(device.hostname or '-'):<24} "
            f"{(device.vendor or '-'):<20} {device.port_summary}"
        )


def _show_credential_reference(device: Device, store, console=None) -> None:
    reference = store.for_device(device)
    _say(f"\nDefault credential reference for {device.ip} ({reference.vendor}):", console, "bold yellow")
    for pair in reference.pairs:
        password = pair.display_password
        _say(f"  {pair.username:<18} {password}", console)
    _say("Manual login only — AB Search never sends credentials.", console, "dim")


def open_management_page(devices: list[Device], store, console=None) -> None:
    choices = [(device, url) for device in devices for url in device.web]
    if not choices:
        _say("No HTTP/HTTPS management pages were detected.", console, "yellow")
        return
    _say("\nDevices with a management page:", console, "bold")
    for index, (device, url) in enumerate(choices, 1):
        _say(f"  {index}. {device.ip}  {device.hostname or device.vendor or ''}  {url}", console)
    try:
        answer = input("Choose a number (or press Enter to cancel): ").strip()
    except (EOFError, OSError):
        return
    if not answer:
        return
    try:
        device, url = choices[int(answer) - 1]
    except (ValueError, IndexError):
        _say("Invalid choice.", console, "red")
        return
    _show_credential_reference(device, store, console)
    _say(f"Opening {url} — log in manually.", console, "green")
    try:
        webbrowser.open(url)
    except Exception:
        _say("Could not open a browser; copy the URL above instead.", console, "yellow")


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    console = _console(args.no_color)
    if not args.quiet:
        print_banner(console=console, color=not args.no_color)

    if not require_authorization(args.yes, args.demo, console):
        _say("Authorization not confirmed. Nothing was scanned.", console, "red")
        return 2

    base_dir = Path(__file__).resolve().parent.parent
    extra_paths = [Path(path).expanduser() for path in args.credentials]
    store = load_credential_store(base_dir=base_dir, extra_paths=extra_paths)

    formats = tuple(
        item.strip().lower()
        for item in args.format.split(",")
        if item.strip() in {"json", "csv", "html"}
    ) or ("json", "csv", "html")

    baseline = None
    if args.baseline:
        try:
            baseline = load_baseline(Path(args.baseline).expanduser())
        except (OSError, ValueError) as exc:
            _say(f"Error: could not load baseline: {exc}", console, "red")
            return 2

    authorization = (
        "demo data — no scan"
        if args.demo
        else ("confirmed by operator" if args.yes else "confirmed interactively")
    )
    options = {
        "ports_scanned": _selected_ports(args),
        "service_banners": args.services and not args.no_ports,
        "bluetooth": args.bluetooth,
        "bluetooth_timeout": args.bt_timeout,
        "deep": args.deep,
        "discovery_timeout": args.discovery_timeout if args.deep else 0,
        "baseline": str(args.baseline) if args.baseline else "",
        "watch_interval": args.watch,
    }
    serve_web = args.web and args.watch <= 0
    if args.web and not serve_web:
        _say("Note: --web is ignored in --watch mode; run a single scan for the dashboard.", console, "yellow")

    def emit(devices, bluetooth, network, gateway, interface_name, previous):
        report = build_report(
            network=str(network),
            interface=interface_name,
            gateway=gateway or "",
            devices=devices,
            bluetooth=bluetooth,
            credential_store=store,
            authorization=authorization,
            mode="demo" if args.demo else "live",
            options=options,
        )
        diff = None
        if previous is not None:
            diff = compare_reports(previous, report)
            report["diff"] = diff
        output_dir = report_path(Path(args.output).expanduser())
        paths = write_reports(report, output_dir, formats=formats)
        _print_devices(devices, console)
        print_report_paths(paths)
        if diff is not None and not args.quiet:
            _say("\n" + format_diff(diff), console, "bold")
        return report, output_dir

    if args.demo:
        network = parse_network(DEMO_NETWORK)
        gateway = DEMO_GATEWAY
        devices = demo_devices()
        bluetooth = BluetoothScan(devices=demo_bluetooth(), supported=True)
        if not args.quiet:
            _say(
                "Demo mode: using sample devices. No network or Bluetooth scan was performed.",
                console,
                "bold green",
            )
        report, output_dir = emit(devices, bluetooth, network, gateway, DEMO_INTERFACE, baseline)
        if serve_web:
            from .web import serve_report

            serve_report(output_dir, port=args.web_port, open_browser=not args.no_open)
        return 0

    try:
        network, gateway = _select_network(args, console)
        if not args.quiet:
            _say(f"Target network: {network}   Gateway: {gateway or 'unknown'}", console, "bold")
            if args.no_ports:
                _say("Port checks disabled.", console, "dim")
            else:
                _say(f"TCP ports: {len(_selected_ports(args))} selected", console, "dim")
        interfaces = detect_interfaces()
        interface_name = args.interface or (interfaces[0].name if interfaces else "")
    except ValueError as exc:
        _say(f"Error: {exc}", console, "red")
        return 2

    previous = baseline
    first = True
    while True:
        try:
            devices = _collect_devices(args, network, gateway, store, console)
            if args.bluetooth:
                if first and not args.quiet:
                    _say("Scanning Bluetooth advertisements…", console, "dim")
                bluetooth = scan_bluetooth(args.bt_timeout)
            else:
                bluetooth = BluetoothScan(supported=False, error="skipped by user")
        except ValueError as exc:
            _say(f"Error: {exc}", console, "red")
            return 2

        if bluetooth.error and first and not args.quiet:
            _say(f"Note: {bluetooth.error}", console, "yellow")

        report, output_dir = emit(devices, bluetooth, network, gateway, interface_name, previous)
        previous = report

        if first and serve_web:
            from .web import serve_report

            serve_report(output_dir, port=args.web_port, open_browser=not args.no_open)
            return 0

        if first and not args.no_open:
            if args.open_page:
                open_management_page(devices, store, console)
            elif sys.stdin.isatty():
                try:
                    answer = input("\nOpen a device management page now? [y/N] ").strip().lower()
                except (EOFError, OSError):
                    answer = ""
                if answer in {"y", "yes"}:
                    open_management_page(devices, store, console)
        elif first and args.open_page:
            open_management_page(devices, store, console)

        first = False
        if args.watch <= 0:
            break
        if not args.quiet:
            _say(f"\nWaiting {args.watch:g}s before the next scan (Ctrl+C to stop)…", console, "dim")
        time.sleep(args.watch)

    return 0


if __name__ == "__main__":  # pragma: no cover
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        print("\nInterrupted.")
        raise SystemExit(130)
