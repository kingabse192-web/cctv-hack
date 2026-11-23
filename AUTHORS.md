# Authors & Credits 😊

## Creator and maintainer

**AB** — GitHub: [kingabse192-web](https://github.com/kingabse192-web)

AB defined the original CCTV/network-inventory requirements, supplied the
`AB SEARCH` logo, the default-credential reference files, and directed the
scope, safety rules, and visual style of this project.

Project repository: **https://github.com/kingabse192-web/cctv-hack**

## Development

The implementation was produced with the help of the **OpenCode** AI coding
agent (Hy4 flash Free), following two requested disciplines:

- **Reverse-engineering methodology** — evidence-driven parsing of real
  nmap output, ARP tables, DNS/mDNS packets, SSDP headers, and ONVIF SOAP
  responses; verification through reproducible fixtures and tests.
- **Frontend design engineering** — the offline dashboard was designed as a
  real product: intentional typography, spacing, hierarchy, components,
  states, responsive layout, dark mode, accessibility, and restrained
  micro-interactions.

## Logo / banner

The `AB SEARCH` wordmark image supplied in the repository was converted into
a six-row block-character ASCII banner (`absearch/banner.py`) so the branding
renders in any terminal without an image library or external font.

## Open-source building blocks

- [nmap](https://nmap.org/) — host discovery and the OUI vendor database
- [psutil](https://github.com/giampaolo/psutil) — network interface detection
- [bleak](https://github.com/hbldh/bleak) — optional Bluetooth LE discovery
- [rich](https://github.com/Textualize/rich) — optional prettier CLI tables
- Python standard library — sockets, HTTP server, CSV, JSON, SOAP parsing

## License

MIT License. See [LICENSE](LICENSE).
