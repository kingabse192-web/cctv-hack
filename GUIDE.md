# AB Search 😊 — User Guide

This guide explains how AB Search works and how to use it safely. The project
lives at **https://github.com/kingabse192-web/cctv-hack**. For the internal
architecture and data flow, see [ARCHITECTURE.md](ARCHITECTURE.md).

---

## 1. What it does

AB Search takes an inventory of a local Wi-Fi/Ethernet network:

1. Detects your active network interface and default gateway.
2. Discovers hosts with `nmap` (or ARP/ping fallback).
3. Resolves IP, MAC, hostname, and vendor (offline OUI database).
4. Checks common TCP ports and politely identifies services.
5. Categorises each device as **Router**, **Computer**, **Phone**,
   **Possible CCTV camera**, or **Unknown device**.
6. Optionally discovers cameras and services with ONVIF, mDNS, and SSDP.
7. Writes JSON, CSV, and a beautiful offline HTML dashboard.
8. Never sends credentials, never brute-forces, never opens a camera stream.

---

## 2. Requirements

- Linux (tested on WSL/Ubuntu) with Python 3.10+
- `nmap` for best results: `sudo apt install nmap bluez`
- `psutil` (installed automatically)
- Optional: `bleak` for Bluetooth, `rich` for a prettier CLI table

---

## 3. Install

```bash
git clone https://github.com/kingabse192-web/cctv-hack.git
cd cctv-hack
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
```

Optional extras:

```bash
pip install -e '.[bluetooth,ui]'
```

---

## 4. First run — completely safe demo

**Easiest:** in the project folder, run `TRY_ME.sh` (Linux/WSL/macOS) or
double-click `TRY_ME.bat` (Windows). Both start the demo automatically.

Manually:

```bash
python -m absearch --demo --web
```

This uses built-in sample data. It does **not** scan your network or Bluetooth.
A browser opens at `http://127.0.0.1:8765/` with the dashboard. Press `Ctrl+C`
in the terminal to stop the server.

---

## 5. Your first real scan

> Only scan networks and devices you own or are explicitly authorized to test.

```bash
python -m absearch
```

You will be asked to type `I AUTHORIZE`. Then AB Search will:

- show the detected local networks,
- discover devices,
- check ports,
- classify devices,
- create a timestamped folder under `inventory_reports/`.

For automation (no prompt):

```bash
python -m absearch --yes
```

For a specific subnet:

```bash
python -m absearch --network 192.168.1.0/24 --yes
```

---

## 6. Advanced camera discovery

```bash
python -m absearch --deep --camera-ports --yes
```

`--deep` adds:

- **ONVIF WS-Discovery** — the standard way IP cameras announce themselves
- **mDNS/DNS-SD** — service names from printers, cameras, phones, TVs
- **SSDP/UPnP** — router and media-device announcements
- **TLS certificate details** — CN/SAN/issuer of HTTPS management pages

All of this is read-only discovery. No login is attempted.

---

## 7. Open a device's management page manually

```bash
python -m absearch --open --yes
```

After the scan you choose a numbered device. AB Search shows the default
credential reference from `try.txt` / `try1.txt` and opens the web page in your
browser. **You** type the username/password. AB Search never does.

---

## 8. Understanding the dashboard

Open `inventory_reports/scan-*/index.html` directly, or start it with `--web`.

- **Summary tiles** — counts per category; click to filter
- **Top open ports** — quick exposure overview
- **Search** — IP, MAC, hostname, vendor, port, or link (`/` focuses it)
- **Cards / Table** — switch views; click column headers to sort
- **Risk badge** — review priority with explanation, not a vulnerability verdict
- **Detail panel** — confidence, evidence, ports, TLS details, web links,
  copyable RTSP URL, and the credential reference
- **Theme button** — switch light/dark; your choice is remembered
- **JSON / CSV buttons** — download the raw report

Everything is offline: no CDN, no fonts, no tracking, no external requests.

---

## 9. Reports

Each scan writes:

| File | Meaning |
| --- | --- |
| `report.json` | Full machine-readable report |
| `devices.csv` | Spreadsheet-friendly device list |
| `index.html` | Offline interactive dashboard |

The JSON includes a `safety` block showing `credential_attempts: 0` and
`stream_access: false`.

---

## 10. Change detection

Compare with an earlier scan:

```bash
python -m absearch --baseline inventory_reports/scan-20261123-120000/report.json --yes
```

The dashboard shows a **Changes since baseline** panel with new, missing, and
changed devices.

Watch continuously:

```bash
python -m absearch --watch 60 --yes --quiet
```

This rescans every 60 seconds and diffs against the previous scan — useful for
noticing a newly connected camera on an authorized network.

---

## 11. Troubleshooting

| Problem | Fix |
| --- | --- |
| `No local network detected` | Connect to Wi-Fi/Ethernet or pass `--network CIDR` |
| `Network is not private` | Pass `--allow-public` only if you are authorized |
| `above --max-hosts` | Use a smaller subnet or `--allow-large` |
| MAC addresses missing | Run with `sudo nmap` or rely on the ARP table |
| Bluetooth skipped | `pip install bleak` and enable Bluetooth |
| No cameras found | Try `--deep --camera-ports` and check ONVIF is enabled on the camera |
| Dashboard looks empty | Open `index.html` from the scan folder, not the repo root |

---

## 12. Safety rules

- Authorized networks and devices only.
- No credential guessing, brute force, or default-login attempts.
- No camera stream access.
- Bluetooth is advertisement-only; no pairing or connecting.
- The dashboard escapes all device-provided text and has a strict CSP.

---

## 13. Uninstall

```bash
pip uninstall absearch
rm -rf inventory_reports
```

---

Made by AB (https://github.com/kingabse192-web). See [AUTHORS.md](AUTHORS.md)
for full credits.
