# How AB Search Works — Architecture 😊

This document explains the internals in plain language. For step-by-step usage,
see [GUIDE.md](GUIDE.md).

## 1. One-line summary

`absearch` is a Python CLI that turns **local network evidence** into a
reviewable inventory: it discovers hosts, checks which ports/services are
reachable, guesses a category with explainable heuristics, scores review risk,
and writes a self-contained HTML dashboard — without ever logging in.

## 2. Pipeline

```
┌──────────────┐
│  CLI / args  │  absearch.cli — argparse, authorization gate
└──────┬───────┘
       ▼
┌──────────────┐
│ Network pick │  net.detect_interfaces → net.parse_network
└──────┬───────┘
       ▼
┌──────────────┐
│ Host discovery│ net.discover_hosts (nmap -sn → ARP table → ping sweep)
└──────┬───────┘
       ▼
┌──────────────┐
│ Port/service │  services.probe_ports (safe TCP connects + HEAD/OPTIONS)
└──────┬───────┘
       ▼
┌──────────────┐
│ --deep hints │  discovery.discover_hints (mDNS, SSDP, ONVIF) + TLS cert
└──────┬───────┘
       ▼
┌──────────────┐
│ Classification│ classify.apply_classification → 5 categories + confidence
└──────┬───────┘
       ▼
┌──────────────┐
│ Credentials  │ credentials.CredentialStore — reference only, never sent
└──────┬───────┘
       ▼
┌──────────────┐
│ Risk + diff  │ risk.assess, history.compare_reports
└──────┬───────┘
       ▼
┌──────────────┐
│ Reports      │ report.write_reports → JSON / CSV / index.html
└──────┬───────┘
       ▼
┌──────────────┐
│ Dashboard    │ web/template.html — offline, responsive, CSP-hardened
└──────────────┘
```

## 3. Each stage in detail

### CLI and authorization (`absearch/cli.py`)
- `build_parser()` defines all flags; `--demo` and `--yes` are the safe
  automation paths.
- `require_authorization()` refuses to scan until the operator types
  `I AUTHORIZE` (or passes `--yes` / sets `AUTHORIZED=1`).
- `--watch` reuses the same scan function in a loop and diffs against the
  previous report.

### Network selection (`absearch/net.py`)
- `detect_interfaces()` reads `psutil.net_if_addrs()` and skips loopback,
  link-local, and unusable `/32` aliases.
- `default_gateway()` parses `/proc/net/route` (fallback: `ip route`).
- `parse_network()` validates CIDR input; the CLI refuses non-private and
  overly large networks unless explicitly allowed.

### Host discovery (`absearch/net.py`)
Order matters, and each step fills gaps in the previous one:

1. `nmap_discover()` runs `nmap -sn -T2 <network>` and `parse_nmap_discovery()`
   extracts IP, hostname, MAC, and vendor.
2. `arp_table()` reads `ip neigh show` (or `/proc/net/arp`) to recover MACs for
   hosts nmap could not fingerprint without root.
3. `merge_hosts()` combines both sources, then `oui.lookup_vendor()` resolves
   vendors from `/usr/share/nmap/nmap-mac-prefixes` with a built-in fallback.
4. If nmap is missing, `ping_sweep()` provides a best-effort fallback for up to
   a /24.
5. `reverse_dns()` runs in a bounded thread pool so a slow resolver cannot hang
   the scan.

### Port and service checks (`absearch/services.py`)
- Only TCP connects plus harmless greetings:
  - HTTP/HTTPS: `HEAD / HTTP/1.0`
  - RTSP: `OPTIONS rtsp://... RTSP/1.0` — no `DESCRIBE`/`SETUP`/`PLAY`
  - SSH/FTP/Telnet: read the server's volunteered banner
- `--deep` additionally reads the TLS certificate (CN/SAN/issuer/expiry) with
  verification disabled — identification only, never pinning or trusting.
- Results are stored as `PortInfo(port, service, banner, metadata)`.

### Advanced discovery (`absearch/discovery.py`)
All three are standard, authentication-free discovery protocols:

| Protocol | Port | What it reads |
| --- | --- | --- |
| mDNS/DNS-SD | UDP 5353 | PTR/SRV/TXT/A records for advertised services |
| SSDP/UPnP | UDP 1900 | `SERVER`, `ST`, `USN`, `LOCATION` headers from M-SEARCH replies |
| ONVIF WS-Discovery | UDP 3702 | SOAP `ProbeMatches`: endpoint address, friendly name, manufacturer |

A minimal DNS packet encoder/parser is implemented in-house, so no extra
dependency is needed. `discover_hints()` runs the probes concurrently,
deduplicates, and returns `DiscoveryHint` objects that are attached to matching
device IPs.

### Classification (`absearch/classify.py`)
Five fixed categories are scored independently:

| Signal | Example |
| --- | --- |
| Gateway address | device IP equals the default gateway → Router |
| Vendor/OUI | `Hikvision` → camera; `TP-Link` → router |
| Hostname | `IPC-64`, `iPhone`, `macbook-pro` |
| Ports | 554/8554 → camera; 445/3389 → computer; 62078 → phone |
| Banners/hints | `RTSP/1.0`, ONVIF, `SSH-2.0` |

The highest score wins; confidence is capped at 0.99, and weak evidence falls
back to **Unknown device**. Every reason is stored in `notes` and shown in the
dashboard, so no guess is opaque.

### Credential reference (`absearch/credentials.py`)
- Parses `try.txt`, `try1.txt`, `~/.config/absearch/credentials.txt`, and the
  packaged `data/defaults.txt`.
- Filters headers/separators/prose, maps `(leave blank)` to an empty password,
  and deduplicates.
- `for_device()` picks a vendor-relevant short list (Hikvision, Dahua, Axis,
  TP-Link, etc.).
- **There is no network code in this module.** It cannot authenticate anywhere.

### Risk scoring (`absearch/risk.py`)
Additive, explainable points for: cleartext management (Telnet/FTP/HTTP),
RTSP exposure, camera SDK ports, remote desktop, many open ports, and relevant
factory defaults. Levels: Info → Low → Medium → High → Critical. It is a review
priority, not a vulnerability verdict.

### Baseline and watch (`absearch/history.py`)
`compare_reports()` indexes devices by IP and reports:
- new IPs, missing IPs
- added/removed ports and category changes

`report_path()` adds a numeric suffix when two scans land in the same second,
so watch mode never overwrites an earlier report.

### Reporting and dashboard (`absearch/report.py`, `web/template.html`)
- `build_report()` assembles a versioned JSON document with `meta`, `summary`,
  `devices`, `bluetooth`, `credential_reference`, `diff`, and `safety` blocks.
- `safe_json()` escapes `<`, `>`, `&`, and Unicode line separators before the
  report is embedded in a `<script type="application/json">` tag.
- The template receives `__PAGE_TITLE__`, `__MODE_BADGE__`, and
  `__REPORT_JSON__` placeholders. Static placeholders are replaced **before**
  the JSON payload to avoid corrupting device data.
- JavaScript renders all device-supplied strings with `textContent`; URLs are
  validated against `http(s)://` and `rtsp://`. A Content-Security-Policy meta
  tag blocks external requests.
- No CDN, no external fonts, no analytics — the file works from `file://`.

## 4. Safety boundaries

| Action | Allowed |
| --- | --- |
| TCP connect + safe banner | Yes, in authorized scans |
| mDNS/SSDP/ONVIF discovery | Yes, with `--deep` |
| Reading TLS certificate | Yes, with `--deep` |
| Sending credentials | **Never** |
| Brute force / password guessing | **Never** |
| Opening/playing camera streams | **Never** |
| Bluetooth pairing/connecting | **Never** (advertisements only) |

## 5. Data model

`Device` is the central dataclass: IP, MAC, vendor, hostname, category,
confidence, ports, web/RTSP links, notes, credential vendor/pairs, discovery
hints, risk, and diff. `PortInfo` adds service, banner, and metadata. Both
serialise to plain dictionaries for JSON/CSV/HTML.

## 6. Testing strategy

- Pure parsers are tested with captured fixtures (nmap output, mDNS DNS
  packets, ONVIF SOAP XML).
- Classification, credential parsing, risk, and diffing are deterministic unit
  tests.
- `test_report.py` injects hostile hostnames like
  `<img src=x onerror=alert(1)>` and asserts they are escaped.
- `test_cli.py` runs the whole demo pipeline and verifies report files.
- `node --check` is used during development on the embedded dashboard JS.

## 7. Extension points

- Add a vendor keyword to `classify.py` for a new device family.
- Add a port to `services.SERVICE_BY_PORT` / `CAMERA_PORTS`.
- Add a default-credential vendor rule in `credentials.VENDOR_PRIORITY`.
- Add a discovery protocol by registering it in `discovery.SOURCES`.
- Restyle the dashboard by editing only `absearch/web/template.html`.

---

Made by AB ([kingabse192-web](https://github.com/kingabse192-web)).
See [AUTHORS.md](AUTHORS.md) for credits.
