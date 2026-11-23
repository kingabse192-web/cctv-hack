#!/usr/bin/env python3
"""
Authorized Local Device Inventory with Default Credential Reference

Purpose:
- Discover devices on the current local network that you own or are authorized to test.
- Categorize results as Wi-Fi/LAN, possible CCTV, or Bluetooth.
- Collect basic information and save JSON/CSV reports.
- Open an HTTP/HTTPS management page only after the user explicitly chooses a device.
- Display a list of common default credentials (from try.txt/try1.txt) as a reference
  for manual login — no automatic attempts are ever made.

Safety:
- No password guessing, brute force, default admin/admin attempts, or camera-stream access.
- Credentials are never collected or stored by this program.
- Use only on networks and devices for which you have permission.

Requirements:
  Linux: sudo apt install nmap bluez
  Python: pip install psutil bleak
  Run: python3 authorized_inventory.py

  and pusing it on to git hub so that any one can use it 
"""

from __future__ import annotations

import argparse
import asyncio
import csv
import datetime as dt
import ipaddress
import json
import platform
import re
import shutil
import socket
import subprocess
import sys
import webbrowser
from pathlib import Path

try:
    import psutil
except ImportError:
    psutil = None

try:
    from bleak import BleakScanner
except ImportError:
    BleakScanner = None

OUTPUT_DIR = Path("inventory_reports")
COMMON_PORTS = "80,443,554,8000,8080,8899,1900"
CAMERA_PORTS = {554, 8000, 8899}
WEB_PORTS = {80, 443, 8000, 8080}

# ----------------------------------------------------------------------
# Embedded default credentials from try.txt and try1.txt
# Combined and deduplicated, organised by vendor where possible.
# Source: common default username/password pairs for routers, cameras, etc.
# ----------------------------------------------------------------------
# Embedded defaults (fallback values baked into the script)
EMBEDDED_DEFAULTS = {
    # Generic / unknown vendor
    "default": [
        ("admin", "admin"),
        ("admin", "password"),
        ("admin", ""),          # blank password
        ("root", "root"),
        ("root", "admin"),
        ("admin", "1234"),
        ("admin", "12345"),
        ("admin", "default"),
        ("user", "user"),
        ("user", "password"),
        ("guest", "guest"),
        ("administrator", ""),
        ("root", "pass"),
        ("admin", "123456"),
        ("admin", "888888"),
        ("admin", "9999"),
        ("admin", "admin123"),
        ("admin", "admin1234"),
        ("useradmin", "useradmin"),
        ("tech", "tech"),
        ("support", "support"),
        ("service", "service"),
        ("supervisor", "supervisor"),
        ("root", "system"),
        ("root", "passw"),
    ],
    # Vendor-specific (based on common defaults)
    "cisco": [("cisco", "cisco")],
    "ubnt": [("ubnt", "ubnt")],
    "motorola": [("motorola", "motorola")],
    "smc": [("admin", "smcadmin")],
    "epic": [("admin", "epicrouter")],
    "ttnet": [("admin", "ttnet")],
    "flir": [("admin", "fliradmin")],
    "mein": [("admin", "meinsm")],
    "juan": [("admin", "juantest")],
    "tlm": [("admin", "tlm_admin")],
    "telecom": [("telecomadmin", "admintelecom")],
    "sky": [("admin", "sky")],
    "msn": [("admin", "msn")],
    "zte": [("admin", "zteoem")],
    # CCTV / camera specific
    "hikvision": [("admin", "12345")],
    "dahua": [("admin", "admin")],
    "onvif": [("admin", "admin")],
}


def _load_creds_from_file(path: Path):
    """Read credential pairs from a text file. Supports pipe-separated, tab, or whitespace-separated pairs.
    Lines beginning with '#' or empty lines are ignored.
    """
    creds = []
    try:
        text = path.read_text(encoding="utf-8")
    except Exception:
        return creds
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        # Try pipe-separated first: "user | pass"
        if "|" in line:
            parts = [p.strip() for p in line.split("|", 1)]
        else:
            parts = line.split()
        if not parts:
            continue
        user = parts[0]
        pwd = parts[1] if len(parts) > 1 else ""
        creds.append((user, pwd))
    return creds


def _merge_external_defaults():
    """Merge embedded defaults with any external credentials found in try.txt and try1.txt.
    External credentials are appended to the generic 'default' list unless a vendor prefix is detected
    in the filename (not used here). This keeps external files simple for the user.
    """
    merged = {k: list(v) for k, v in EMBEDDED_DEFAULTS.items()}
    base_dir = Path(__file__).resolve().parent
    candidates = [base_dir / "try.txt", base_dir / "try1.txt"]
    for path in candidates:
        if not path.exists():
            continue
        ext_creds = _load_creds_from_file(path)
        for user, pwd in ext_creds:
            pair = (user, pwd)
            if pair not in merged["default"]:
                merged["default"].append(pair)
    return merged


# Final runtime DEFAULT_CREDENTIALS built from embedded defaults + external files
DEFAULT_CREDENTIALS = _merge_external_defaults()

def get_vendor_key(device):
    """Return a vendor key based on hostname or MAC vendor string."""
    text = f"{device.get('hostname', '')} {device.get('vendor', '')}".lower()
    for key in DEFAULT_CREDENTIALS.keys():
        if key != "default" and key in text:
            return key
    return "default"

def display_default_credentials(device):
    """Print a list of default credentials relevant to the device."""
    vendor_key = get_vendor_key(device)
    creds = DEFAULT_CREDENTIALS.get(vendor_key, DEFAULT_CREDENTIALS["default"])
    # Also include generic defaults if not already present (avoid duplication)
    all_creds = list(creds)
    if vendor_key != "default":
        for pair in DEFAULT_CREDENTIALS["default"]:
            if pair not in all_creds:
                all_creds.append(pair)
    print("\n--- Default credentials for manual login (try these) ---")
    for user, pwd in all_creds:
        display_pwd = "<blank>" if pwd == "" else pwd
        print(f"  Username: {user:<12} Password: {display_pwd}")
    print("--- End of default credentials ---\n")

# ----------------------------------------------------------------------
# Rest of the original script (unchanged except open_management_page)
# ----------------------------------------------------------------------

def require_authorization():
    # Allow non-interactive runs by setting environment variable AUTHORIZED=1 or passing --yes on the command line.
    if os.environ.get("AUTHORIZED") in ("1", "true", "True") or "--yes" in sys.argv:
        return
    print("AUTHORIZED USE ONLY")
    print("This scans only networks/devices that you own or are authorized to test.")
    answer = input("Type AUTHORIZED to continue: ").strip()
    if answer != "AUTHORIZED":
        raise SystemExit("Cancelled.")


def local_networks():
    if psutil is None:
        return []
    networks = []
    for _, addresses in psutil.net_if_addrs().items():
        for address in addresses:
            if address.family != socket.AF_INET or address.address.startswith("127."):
                continue
            if not address.netmask:
                continue
            try:
                network = ipaddress.ip_network(
                    f"{address.address}/{address.netmask}", strict=False
                )
                # Use the network address for address-level checks to avoid relying on
                # attributes that may only exist on addresses rather than network objects.
                addr = network.network_address
                if not addr.is_loopback and not addr.is_link_local:
                    networks.append(str(network))
            except ValueError:
                pass
    return sorted(set(networks))


def choose_network():
    networks = local_networks()
    if not networks:
        raise SystemExit("Could not determine a local IPv4 network. Install psutil or enter --network.")
    print("Detected local networks:")
    for index, network in enumerate(networks, 1):
        print(f"  {index}. {network}")
    if len(networks) == 1:
        return networks[0]
    choice = input("Choose a network number: ").strip()
    try:
        return networks[int(choice) - 1]
    except (ValueError, IndexError):
        raise SystemExit("Invalid network choice.")


def run_nmap(network, service_scan=False):
    if shutil.which("nmap") is None:
        raise SystemExit("Nmap is required. Install it with: sudo apt install nmap")
    command = ["nmap", "-sn", "-T2", network]
    if service_scan:
        command = ["nmap", "-sV", "--version-light", "-T2", "-p", COMMON_PORTS, network]
    try:
        return subprocess.check_output(command, text=True, stderr=subprocess.STDOUT)
    except subprocess.CalledProcessError as error:
        raise SystemExit(error.output)


def parse_nmap(output, service_scan=False):
    devices = []
    current = None
    for line in output.splitlines(): 
        match = re.match(r"Nmap scan report for (.+)", line)
        if match:
            if current:
                devices.append(current)
            target = match.group(1).strip()
            ip_match = re.search(r"\((\d+\.\d+\.\d+\.\d+)\)$", target)
            current = {
                "address": ip_match.group(1) if ip_match else target,
                "hostname": target.split(" (")[0] if ip_match else "",
                "mac": "",
                "vendor": "",
                "ports": [],
            }
            continue
        if not current:
            continue
        if "MAC Address:" in line:
            value = line.split("MAC Address:", 1)[1].strip()
            parts = value.split(maxsplit=1)
            current["mac"] = parts[0]
            current["vendor"] = parts[1].strip("()") if len(parts) > 1 else ""
        if service_scan:
            port_match = re.match(r"(\d+)/(tcp|udp)\s+open\s+(.+)", line.strip())
            if port_match:
                current["ports"].append({
                    "port": int(port_match.group(1)),
                    "protocol": port_match.group(2),
                    "service": port_match.group(3).strip(),
                })
    if current:
        devices.append(current)
    return devices


def classify(device):
    ports = {item["port"] for item in device.get("ports", [])}
    text = f"{device.get('hostname', '')} {device.get('vendor', '')}".lower()
    camera_words = ("camera", "cctv", "ipc", "nvr", "dvr", "hikvision", "dahua", "onvif")
    if ports & CAMERA_PORTS or any(word in text for word in camera_words):
        return "Possible CCTV/IP camera"
    if ports & WEB_PORTS:
        return "Wi-Fi/LAN device with web interface"
    return "Wi-Fi/LAN device"


def add_web_links(device):
    address = device.get("address", "")
    ports = {item["port"] for item in device.get("ports", [])}
    links = []
    if 443 in ports:
        links.append(f"https://{address}")
    if ports & {80, 8000, 8080}:
        port = 80 if 80 in ports else (8000 if 8000 in ports else 8080)
        links.append(f"http://{address}" if port == 80 else f"http://{address}:{port}")
    device["web_interfaces"] = links


def bluetooth_scan():
    if BleakScanner is None:
        return [{"error": "Bluetooth scan unavailable. Install bleak: pip install bleak"}]
    async def scan():
        found = await BleakScanner.discover(timeout=6)
        return [
            {
                "address": item.address,
                "name": item.name or "Unknown",
                "rssi": getattr(item, "rssi", None),
                "category": "Bluetooth device",
            }
            for item in found
        ]
    try:
        return asyncio.run(scan())
    except RuntimeError:
        # Running inside an existing event loop (e.g., interactive environment). Provide a clear error.
        try:
            loop = asyncio.get_event_loop()
            if loop.is_running():
                return [{"error": "Bluetooth scan unavailable: event loop is already running in this environment."}]
            return loop.run_until_complete(scan())
        except Exception as error:
            return [{"error": f"Bluetooth scan failed: {error}"}]
    except Exception as error:
        return [{"error": f"Bluetooth scan failed: {error}"}]


def save_reports(network, lan_devices, bluetooth_devices):
    try:
        OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    except OSError as e:
        raise SystemExit(f"Could not create output directory {OUTPUT_DIR}: {e}")
    timestamp = dt.datetime.now().astimezone().isoformat()
    for device in lan_devices:
        device["category"] = classify(device)
        add_web_links(device)
        device["credentials"] = "Not tested; enter credentials manually in the official interface"
    report = {
        "created": timestamp,
        "network_scanned": network,
        "authorization": "User confirmed authorized use",
        "lan_wifi_devices": lan_devices,
        "bluetooth_devices": bluetooth_devices,
        "security_note": "No login attempts or password testing were performed.",
    }
    json_path = OUTPUT_DIR / "device_inventory.json"
    json_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    csv_path = OUTPUT_DIR / "lan_devices.csv"
    with csv_path.open("w", newline="", encoding="utf-8") as file:
        fields = ["category", "address", "hostname", "mac", "vendor", "ports", "web_interfaces", "credentials"]
        writer = csv.DictWriter(file, fieldnames=fields)
        writer.writeheader()
        for device in lan_devices:
            row = device.copy()
            row["ports"] = "; ".join(
                f"{p['port']}/{p['protocol']} {p['service']}" for p in device.get("ports", [])
            )
            row["web_interfaces"] = "; ".join(device.get("web_interfaces", []))
            writer.writerow({field: row.get(field, "") for field in fields})
    return json_path, csv_path


def print_results(lan_devices, bluetooth_devices):
    print("\nLAN/Wi-Fi devices")
    if not lan_devices:
        print("  No devices found.")
    for index, device in enumerate(lan_devices, 1):
        ports = ", ".join(str(p["port"]) for p in device.get("ports", [])) or "none detected"
        print(f"  {index}. {device['address']} | {device.get('category')} | {device.get('vendor') or 'Unknown'} | ports: {ports}")
        for link in device.get("web_interfaces", []):
            print(f"     Management page: {link}")
    print("\nBluetooth devices")
    for device in bluetooth_devices:
        if "error" in device:
            print(f"  {device['error']}")
        else:
            print(f"  {device['address']} | {device['name']} | RSSI: {device.get('rssi', 'unknown')}")


def open_management_page(devices):
    choices = [(i, link) for i, device in enumerate(devices, 1) for link in device.get("web_interfaces", [])]
    if not choices:
        print("No detected HTTP/HTTPS management pages.")
        return
    print("\nAvailable management pages:")
    for number, (device_index, link) in enumerate(choices, 1):
        print(f"  {number}. Device {device_index}: {link}")
    choice = input("Enter a number to open, or press Enter to skip: ").strip()
    if not choice:
        return
    try:
        idx = int(choice) - 1
        device_index, link = choices[idx]
        device = devices[device_index - 1]  # because device_index is 1-based
    except (ValueError, IndexError):
        print("Invalid choice.")
        return

    # Show default credentials as a reference before opening
    display_default_credentials(device)

    print("Opening the official page. Log in manually; this program will not guess passwords.")
    webbrowser.open(link)


def main():
    parser = argparse.ArgumentParser(description="Authorized Wi-Fi, CCTV, and Bluetooth inventory")
    parser.add_argument("--network", help="Authorized IPv4 network, for example 192.168.1.0/24")
    parser.add_argument("--services", action="store_true", help="Safely inspect selected common service ports")
    parser.add_argument("--no-bluetooth", action="store_true")
    args = parser.parse_args()
    require_authorization()
    network = args.network or choose_network()
    ipaddress.ip_network(network, strict=False)
    print(f"\nScanning authorized local network: {network}")
    output = run_nmap(network, service_scan=args.services)
    lan_devices = parse_nmap(output, service_scan=args.services)
    bluetooth_devices = [] if args.no_bluetooth else bluetooth_scan()
    json_path, csv_path = save_reports(network, lan_devices, bluetooth_devices)
    print_results(lan_devices, bluetooth_devices)
    print(f"\nReports saved to: {json_path} and {csv_path}")
    open_management_page(lan_devices)


if __name__ == "__main__":
    main()