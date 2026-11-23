"""Optional Bluetooth LE discovery.

Bluetooth is deliberately optional: it needs extra permissions and the
``bleak`` package.  When it is unavailable the rest of the inventory still
works.  Only advertisements are read; the tool never pairs, connects, or
writes to a device.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field


@dataclass
class BluetoothDevice:
    address: str
    name: str = ""
    rssi: int | None = None
    vendor: str = ""
    services: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, object]:
        return {
            "address": self.address,
            "name": self.name or "Unknown Bluetooth device",
            "rssi": self.rssi,
            "vendor": self.vendor,
            "services": self.services,
        }


@dataclass
class BluetoothScan:
    devices: list[BluetoothDevice] = field(default_factory=list)
    error: str = ""
    supported: bool = False

    @property
    def available(self) -> bool:
        return self.supported and not self.error


def bleak_available() -> bool:
    try:
        import bleak  # noqa: F401
    except Exception:
        return False
    return True


async def _discover(timeout: float) -> list[BluetoothDevice]:
    from bleak import BleakScanner

    scanner = BleakScanner()
    await scanner.start()
    try:
        await asyncio.sleep(timeout)
    finally:
        await scanner.stop()

    found: list[BluetoothDevice] = []
    discovered = getattr(scanner, "discovered_devices_and_advertisement_data", {})
    for address, value in discovered.items():
        device = None
        advertisement = None
        if isinstance(value, tuple) and len(value) >= 2:
            device, advertisement = value[0], value[1]
        else:
            device = value
        name = getattr(device, "name", "") or ""
        rssi = getattr(advertisement, "rssi", None) if advertisement else getattr(device, "rssi", None)
        manufacturer = ""
        services: list[str] = []
        if advertisement is not None:
            data = getattr(advertisement, "manufacturer_data", {}) or {}
            if data:
                first = next(iter(data.values()))
                manufacturer = bytes(first).decode("utf-8", errors="replace").strip("\x00 ")[:64]
            services = [str(uuid) for uuid in (getattr(advertisement, "service_uuids", []) or [])][:8]
        found.append(
            BluetoothDevice(
                address=address,
                name=name,
                rssi=rssi,
                vendor=manufacturer,
                services=services,
            )
        )
    found.sort(key=lambda item: (-(item.rssi or -999), item.name.lower(), item.address))
    return found


def scan_bluetooth(timeout: float = 6.0) -> BluetoothScan:
    """Scan for BLE advertisements; never raises."""

    if not bleak_available():
        return BluetoothScan(
            supported=False,
            error="Bluetooth scan skipped: install the optional 'bleak' package.",
        )
    try:
        devices = asyncio.run(_discover(max(1.0, timeout)))
    except Exception as exc:  # Bluetooth permission/daemon errors are common.
        return BluetoothScan(supported=True, error=f"Bluetooth scan unavailable: {exc}")
    return BluetoothScan(devices=devices, supported=True)
