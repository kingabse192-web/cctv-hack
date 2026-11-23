"""MAC address normalisation and offline OUI/vendor lookup.

The best source of OUI data is the file that ships with nmap
(``/usr/share/nmap/nmap-mac-prefixes``).  We read it when present and fall
back to a small built-in table so the tool still works on a minimal machine.
No network requests are made.
"""

from __future__ import annotations

import re
from pathlib import Path

_HEX_RE = re.compile(r"[^0-9A-Fa-f]")

# A small fallback table.  Prefixes are the first three octets without
# separators.  This is intentionally limited to vendors relevant to a home
# or small-office inventory; the nmap file provides the full IEEE database.
_BUILTIN: dict[str, str] = {
    "000C29": "VMware",
    "001122": "Cimsys",
    "00155D": "Microsoft",
    "001B21": "Intel",
    "001B78": "HP",
    "001451": "Apple",
    "0017F2": "Apple",
    "001B63": "Apple",
    "0021E9": "Apple",
    "002312": "Apple",
    "002500": "Apple",
    "0026B0": "Apple",
    "003065": "Apple",
    "003EE1": "Apple",
    "00408C": "Axis Communications",
    "0050E4": "Apple",
    "0050F2": "Microsoft",
    "0056CD": "Apple",
    "006171": "Apple",
    "008865": "Apple",
    "0090B0": "Apple",
    "00A040": "Apple",
    "00C610": "Apple",
    "040CCE": "Apple",
    "0C4DE9": "Apple",
    "1093E9": "Apple",
    "14109F": "Apple",
    "18AF61": "Apple",
    "1C1AC0": "Apple",
    "28CFE9": "Apple",
    "2C1F23": "Apple",
    "3C22FB": "Apple",
    "3C5AB4": "Google",
    "3C970E": "Intel",
    "40A6D9": "Apple",
    "44D884": "Apple",
    "4C57CA": "Apple",
    "50C7BF": "TP-Link",
    "5C0A5B": "Samsung",
    "5CF938": "Apple",
    "64CC2E": "Xiaomi",
    "68FB7E": "Apple",
    "6C709F": "Apple",
    "70DEE2": "Apple",
    "78CA39": "Apple",
    "7C1E52": "Microsoft",
    "7CD1C3": "Apple",
    "842999": "Apple",
    "8C8EF2": "Apple",
    "9CB654": "HP",
    "A4BB6D": "Intel",
    "A4C361": "Apple",
    "A483E7": "Apple",
    "ACCC8E": "Axis Communications",
    "B827EB": "Raspberry Pi Foundation",
    "B82A72": "Dell",
    "BCAD28": "Hikvision",
    "C056E3": "Hikvision",
    "C46E1F": "TP-Link",
    "D0817A": "Apple",
    "DCA632": "Raspberry Pi Foundation",
    "E45F01": "Raspberry Pi Foundation",
    "EC71DB": "Reolink",
    "F01898": "Apple",
    "F4F5D8": "Google",
    "F8BC12": "Dell",
    "F0DBF8": "Apple",
}

# A few commonly seen prefixes that are not necessarily in the fallback table
# but should still be recognised in a demo or a very small installation.
_VENDOR_ALIASES = {
    "hewlett packard": "HP",
    "hp": "HP",
    "tp-link": "TP-Link",
    "tplink": "TP-Link",
    "hikvision": "Hikvision",
    "hangzhou hikvision": "Hikvision",
    "dahua": "Dahua",
    "zhejiang dahua": "Dahua",
    "axis": "Axis Communications",
    "axis communications": "Axis Communications",
    "reolink": "Reolink",
    "apple": "Apple",
    "samsung": "Samsung",
    "xiaomi": "Xiaomi",
    "raspberry pi": "Raspberry Pi Foundation",
    "intel": "Intel",
    "dell": "Dell",
    "lenovo": "Lenovo",
}

_SEARCH_PATHS = (
    Path("/usr/share/nmap/nmap-mac-prefixes"),
    Path("/usr/share/ieee-data/oui.txt"),
    Path("/var/lib/ieee-data/oui.txt"),
    Path("/usr/share/misc/oui.txt"),
    Path(r"C:\Program Files (x86)\Nmap\nmap-mac-prefixes"),
    Path(r"C:\Program Files\Nmap\nmap-mac-prefixes"),
)


def normalize_mac(value: str) -> str:
    """Return ``AA:BB:CC:DD:EE:FF`` or an empty string for invalid input."""

    if not value:
        return ""
    raw = _HEX_RE.sub("", value).upper()
    if len(raw) < 12:
        return ""
    raw = raw[:12]
    return ":".join(raw[i : i + 2] for i in range(0, 12, 2))


def mac_prefix(value: str) -> str:
    """Return the first six hex digits of a MAC, or an empty string."""

    normalized = normalize_mac(value)
    return normalized.replace(":", "")[:6] if normalized else ""


def is_valid_mac(value: str) -> bool:
    normalized = normalize_mac(value)
    if not normalized:
        return False
    raw = normalized.replace(":", "")
    return raw not in {"000000000000", "FFFFFFFFFFFF"}


def is_locally_administered(value: str) -> bool:
    """True for randomised/VM MACs (the U/L bit is set)."""

    normalized = normalize_mac(value)
    if not normalized:
        return False
    try:
        return bool(int(normalized[0:2], 16) & 0x02)
    except ValueError:
        return False


def clean_vendor(value: str) -> str:
    vendor = " ".join(value.strip().split())
    if not vendor:
        return ""
    lowered = vendor.lower()
    for needle, canonical in _VENDOR_ALIASES.items():
        if re.search(rf"\b{re.escape(needle)}\b", lowered):
            return canonical
    return vendor


class OUILookup:
    """Lazy, cached OUI database backed by local files and a fallback table."""

    def __init__(self, paths: tuple[Path, ...] | None = None) -> None:
        self.paths = paths if paths is not None else _SEARCH_PATHS
        self._table: dict[str, str] | None = None

    def _load_file(self, path: Path) -> dict[str, str]:
        table: dict[str, str] = {}
        try:
            lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            return table

        for line in lines:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            # nmap: 000C29 VMware
            if re.match(r"^[0-9A-Fa-f]{6}\s+", line):
                prefix, vendor = line.split(None, 1)
                table[prefix.upper()] = clean_vendor(vendor)
                continue
            # IEEE oui.txt: 00-0C-29   (hex)        VMware, Inc.
            match = re.match(
                r"^([0-9A-Fa-f]{2})[-:]([0-9A-Fa-f]{2})[-:]([0-9A-Fa-f]{2})"
                r"\s+\(hex\)\s+(.+)$",
                line,
            )
            if match:
                prefix = "".join(match.groups()[:3]).upper()
                table[prefix] = clean_vendor(match.group(4))
        return table

    def load(self) -> dict[str, str]:
        if self._table is not None:
            return self._table
        table: dict[str, str] = {}
        for path in self.paths:
            if path.is_file():
                table.update(self._load_file(path))
        # The fallback is authoritative for its few entries; it keeps demo
        # data stable even if a local database is incomplete.
        for prefix, vendor in _BUILTIN.items():
            table.setdefault(prefix, vendor)
        self._table = table
        return table

    def lookup(self, mac: str) -> str:
        prefix = mac_prefix(mac)
        if not prefix:
            return ""
        return self.load().get(prefix, "")

    def __len__(self) -> int:
        return len(self.load())


_DEFAULT_LOOKUP = OUILookup()


def lookup_vendor(mac: str) -> str:
    return _DEFAULT_LOOKUP.lookup(mac)


def vendor_key(vendor: str) -> str:
    """Normalise a vendor name for keyword matching."""

    return clean_vendor(vendor).lower()
