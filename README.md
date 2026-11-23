# AB Search — Authorized Network & CCTV Inventory

```
 █████╗ ██████╗    ███████╗███████╗ █████╗ ██████╗  ██████╗██╗  ██╗
██╔══██╗██╔══██╗   ██╔════╝██╔════╝██╔══██╗██╔══██╗██╔════╝██║  ██║
███████║██████╔╝   ███████╗█████╗  ███████║██████╔╝██║     ███████║
██╔══██║██╔══██╗   ╚════██║██╔══╝  ██╔══██║██╔══██╗██║     ██╔══██║
██║  ██║██████╔╝   ███████║███████╗██║  ██║██║  ██║╚██████╗██║  ██║
╚═╝  ╚═╝╚═════╝    ╚══════╝╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝
```

AB Search is a clean, offline-friendly tool for taking inventory of a local
Wi-Fi/Ethernet network. It finds devices, resolves IPs/MACs/hostnames/vendors,
checks which services are listening, flags **possible CCTV cameras**, and
writes JSON/CSV reports plus a polished single-page dashboard.

> **Authorized use only.** Scan only networks and devices you own or are
> explicitly permitted to test. AB Search never guesses passwords, never
> attempts a login, never performs brute force, and never opens a camera
> stream. Credential notes are displayed for *manual* login only.

## Features

- Detects local Wi-Fi/Ethernet interfaces and the default gateway
- Host discovery with `nmap` (with ARP-table and ping-sweep fallbacks)
- Offline OUI vendor lookup from nmap's MAC-prefix database
- Safe TCP checks for HTTP, HTTPS, RTSP, SSH, SMB, RDP, and common CCTV ports
- Categorises every device as **Router**, **Computer**, **Phone**,
  **Possible CCTV camera**, or **Unknown device**
- Records why each classification was made (port, vendor, hostname, gateway)
- Optional Bluetooth LE advertisement scan (`bleak`)
- **Advanced mode**: mDNS/DNS-SD, SSDP/UPnP, and ONVIF WS-Discovery evidence
- **Advanced mode**: TLS certificate subject/SAN/issuer fingerprinting
- Explainable **risk scoring** with review hints (RTSP exposure, cleartext management, etc.)
- **Baseline comparison** and `--watch` mode for change detection
- Manual default-credential reference from `try.txt` / `try1.txt` (never sent)
- JSON, CSV, and a responsive, offline HTML dashboard with search/filters
- Dashboard card/table views, theme switch, top-port chart, and diff panel
- Optional localhost dashboard server (`--web`)
- `--demo` mode for a realistic preview without touching a real network
- Content-Security-Policy hardened dashboard; all device strings rendered safely

## Quick start

```bash
# Preview with sample data (no scanning at all)
python -m absearch --demo --web

# Scan the detected local network, with confirmation
python -m absearch

# Non-interactive scan of a specific subnet
python -m absearch --network 192.168.1.0/24 --yes --services

# Fast check: discovery and open ports only
python -m absearch --no-services --no-bluetooth --yes

# Advanced: ONVIF/mDNS/SSDP discovery plus TLS certificate evidence
python -m absearch --deep --camera-ports --yes

# Compare against an earlier scan, or watch for changes every 60 seconds
python -m absearch --baseline inventory_reports/scan-.../report.json --yes
python -m absearch --watch 60 --yes --quiet
```

The first command opens the dashboard at `http://127.0.0.1:8765/` and writes
a timestamped folder under `inventory_reports/`.

## Installation

Requirements:

- Python 3.10+
- Linux with `nmap` for best host discovery
  (`sudo apt install nmap bluez`)
- `psutil` (installed automatically)
- Optional: `bleak` for Bluetooth LE, `rich` for the prettier CLI table

```bash
pip install -e .                 # core tool
pip install -e '.[bluetooth,ui]' # optional Bluetooth + rich table
pip install -e '.[dev]'          # tests
```

On most Linux systems `nmap -sn` discovers hosts without root. MAC addresses
from nmap may require elevated privileges; AB Search also reads the kernel
neighbour table, which usually provides MACs for local devices without root.

## Usage

```
absearch [--demo] [--network CIDR] [--interface NAME]
         [--ports LIST] [--camera-ports | --no-ports]
         [--services | --no-services] [--timeout SEC] [--workers N]
         [--bluetooth | --no-bluetooth] [--bt-timeout SEC]
         [--output DIR] [--format json,csv,html]
         [--web] [--web-port PORT] [--no-open] [--open]
         [--yes] [--allow-public] [--allow-large] [--max-hosts N]
         [--credentials FILE] [--no-color] [--quiet]
```

Common options:

| Option | Meaning |
| --- | --- |
| `--demo` | Use bundled sample devices; no network or Bluetooth scan |
| `--network` | Scan a specific IPv4 CIDR instead of auto-detecting |
| `--interface` | Choose a detected interface by name |
| `--camera-ports` | Add CCTV ports such as 554, 8000, 8899, 34567, 37777 |
| `--no-services` | Only check whether ports are open (faster, quieter) |
| `--bluetooth` / `--no-bluetooth` | Enable or skip BLE advertisement scan |
| `--deep` | mDNS/SSDP/ONVIF discovery + TLS certificate evidence |
| `--discovery-timeout SEC` | Duration of each advanced discovery probe |
| `--baseline FILE` | Diff this scan against a previous `report.json` |
| `--watch SEC` | Repeat the scan every SEC seconds (single scan by default) |
| `--format` | Any combination of `json,csv,html` |
| `--web` | Serve the generated dashboard on localhost until Ctrl+C |
| `--open` | Interactively choose a device and open its management page |
| `--yes` | Confirm authorization non-interactively |
| `--allow-large` | Permit networks above `--max-hosts` (default 1024) |
| `--credentials FILE` | Add another default-credential reference file |

For a large subnet, scan a smaller slice first, for example
`--network 192.168.1.0/25`.

## Dashboard

The generated `index.html` is completely self-contained — no CDN, no external
fonts, no tracking. Open it directly in a browser or use `--web`. It includes:

- summary tiles for each device category
- live search across IP, MAC, hostname, vendor, ports, and links
- category filters, cameras-only toggle, and sorting
- a device detail panel with classification confidence and evidence
- explainable risk badges and review hints per device
- discovery evidence (mDNS/SSDP/ONVIF) and TLS certificate details
- card/table views with sortable columns, copy-all-IPs, `/` to search
- top-open-ports chart and a changes-since-baseline panel
- open-port table and web-management links
- copyable RTSP URLs (no stream is opened)
- a collapsed **manual login reference** with a clear safety warning
- responsive light/dark layout, theme switch, and keyboard-accessible controls
- a Content-Security-Policy meta tag and no external network requests

All device-provided strings are inserted with `textContent`, and the report is
JSON-escaped before being embedded, so hostnames or vendor strings containing
HTML cannot execute script.

## Credential reference

The files `try.txt`, `try1.txt`, and the packaged `absearch/data/defaults.txt`
contain public factory-default username/password pairs. AB Search parses them,
removes header/separator lines, maps `(leave blank)` to an empty password, and
shows a short vendor-specific reference for manual login. Nothing is ever
sent to a device, and the report explicitly records:
`credential_attempts: 0`.

## Advanced analysis

`--deep` adds three authentication-free discovery protocols:

- **mDNS/DNS-SD** on UDP 5353 for advertised service names and addresses
- **SSDP/UPnP** on UDP 1900, reading only the headers returned to `M-SEARCH`
- **ONVIF WS-Discovery** on UDP 3702 — the standard way to find IP cameras

It also reads the TLS certificate of HTTPS services (CN, SAN, issuer, expiry)
for identification. Nothing is logged into, paired with, or streamed.

Every device receives a transparent **risk score** (Info → Critical). It is a
review priority, not a vulnerability verdict: exposed RTSP, Telnet/FTP,
remote desktop, camera management ports, and relevant factory defaults raise
the score. The dashboard explains every point.

`--baseline FILE` compares against a saved report and reports new, missing,
and changed devices (ports or category). `--watch SEC` repeats the scan and
diffs against the previous run, which is useful for spotting a newly plugged-in
camera on an authorized network.

## Project layout

```
absearch/
  banner.py         AB SEARCH ASCII wordmark
  bluetooth.py      optional BLE advertisement scan
  classify.py       five-category heuristic classifier
  cli.py            argparse CLI and orchestration
  credentials.py    safe credential-reference parser
  demo.py           sample inventory
  discovery.py      mDNS / SSDP / ONVIF passive discovery
  history.py        baseline diff and watch comparison
  models.py         Device/PortInfo/CredentialPair dataclasses
  net.py            interfaces, gateway, ARP, nmap parsing, discovery
  oui.py            MAC normalisation and OUI lookup
  report.py         report building, JSON/CSV, HTML rendering
  risk.py           explainable exposure scoring
  services.py       safe TCP/service probes and URL helpers
  web.py            localhost dashboard server
  web/template.html offline dashboard template
tests/              pytest suite
authorized_inventory.py  original single-file script (kept for reference)
try1_project/            original scaffold (kept for reference)
```

## Tests

```bash
python -m pytest -q
```

The suite covers nmap output parsing, OUI/MAC handling, classification,
credential parsing, report/CSV generation, HTML escaping, and the demo CLI.

## Publishing to GitHub

This repository is ready to publish. For example:

```bash
git init
git add .
git commit -m "AB Search: authorized local-network and CCTV inventory"
git branch -M main
git remote add origin https://github.com/<owner>/<repo>.git
git push -u origin main
```

No remote or credentials are stored in this project. Supply your own GitHub
repository URL and authentication when you are ready to publish.

## License

MIT — see [LICENSE](LICENSE).
