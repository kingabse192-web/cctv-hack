import ipaddress

from absearch.models import Device, PortInfo
from absearch.net import (
    HostRecord,
    merge_hosts,
    network_hosts,
    parse_network,
    parse_nmap_discovery,
)
from absearch.oui import is_locally_administered, is_valid_mac, lookup_vendor, normalize_mac

NMAP_OUTPUT = """
Starting Nmap 7.95 ( https://nmap.org ) at 2026-11-23 14:00 IST
Nmap scan report for Archer (192.168.1.1)
Host is up (0.0021s latency).
MAC Address: 50:C7:BF:12:34:56 (TP-Link Technologies)

Nmap scan report for 192.168.1.64
Host is up (0.0050s latency).
MAC Address: 4C:BD:8F:AA:10:20 (Hangzhou Hikvision Digital Technology)

Nmap scan report for phone.lan (192.168.1.23)
Host is up (0.0090s latency).

Nmap done: 256 IP addresses (3 hosts up) scanned in 4.20 seconds
"""


def test_parse_nmap_discovery():
    hosts = parse_nmap_discovery(NMAP_OUTPUT)
    assert [host.ip for host in hosts] == ["192.168.1.1", "192.168.1.64", "192.168.1.23"]
    assert hosts[0].hostname == "Archer"
    assert hosts[0].mac == "50:C7:BF:12:34:56"
    assert "TP-Link" in hosts[0].vendor
    assert hosts[2].hostname == "phone.lan"
    assert hosts[2].mac == ""


def test_mac_normalisation_and_vendor_lookup():
    assert normalize_mac("50-c7-bf-12-34-56") == "50:C7:BF:12:34:56"
    assert normalize_mac("not a mac") == ""
    assert is_valid_mac("00:00:00:00:00:00") is False
    assert is_valid_mac("50:C7:BF:12:34:56") is True
    assert is_locally_administered("50:C7:BF:12:34:56") is False
    assert is_locally_administered("DA:A1:19:00:00:90") is True
    # Built-in fallback works even when nmap's OUI file is absent.
    assert "TP-Link" in lookup_vendor("50:C7:BF:12:34:56")
    assert "Hikvision" in lookup_vendor("4C:BD:8F:AA:10:20")


def test_merge_hosts_fills_mac_from_arp():
    nmap = [HostRecord(ip="192.168.1.10", source="nmap")]
    arp = {
        "192.168.1.10": HostRecord(ip="192.168.1.10", mac="B8:2A:72:77:88:99", source="arp")
    }
    merged = merge_hosts(nmap, arp, network=parse_network("192.168.1.0/24"))
    assert len(merged) == 1
    assert merged[0].mac == "B8:2A:72:77:88:99"
    assert "Dell" in merged[0].vendor


def test_network_helpers():
    network = parse_network("192.168.1.129/25")
    assert str(network) == "192.168.1.128/25"
    hosts = network_hosts(network)
    assert "192.168.1.129" in hosts
    assert "192.168.1.128" not in hosts
    assert isinstance(network, ipaddress.IPv4Network)
