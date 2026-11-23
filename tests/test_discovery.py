import socket
import struct

from absearch.discovery import (
    _encode_name,
    _parse_mdns_response,
    _parse_onvif_response,
    discover_hints,
)


def test_parse_mdns_response_extracts_address_and_service():
    ptr_data = _encode_name("Printer._http._tcp.local")
    a_data = socket.inet_aton("192.168.1.50")
    packet = struct.pack("!HHHHHH", 0x1234, 0x8400, 0, 2, 0, 0)
    packet += _encode_name("_http._tcp.local") + struct.pack("!HHIH", 12, 1, 120, len(ptr_data)) + ptr_data
    packet += _encode_name("Printer._http._tcp.local") + struct.pack("!HHIH", 1, 1, 120, 4) + a_data

    hints = _parse_mdns_response(packet)
    assert len(hints) == 1
    assert hints[0].ip == "192.168.1.50"
    assert hints[0].service == "_http._tcp.local"
    assert hints[0].name == "Printer._http._tcp.local"
    assert hints[0].source == "mdns"


ONVIF_XML = """<?xml version="1.0"?>
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"
 xmlns:a="http://www.w3.org/2005/08/addressing"
 xmlns:wsd="http://schemas.xmlsoap.org/ws/2005/04/discovery">
 <s:Header><a:Address>urn:uuid:anonymous</a:Address></s:Header>
 <s:Body><wsd:ProbeMatches><wsd:ProbeMatch>
  <a:Address>http://192.168.1.64/onvif/device_service</a:Address>
  <wsd:Types>tds:Device</wsd:Types>
  <wsd:FriendlyName>Front Door IPC</wsd:FriendlyName>
  <wsd:Manufacturer>Hikvision</wsd:Manufacturer>
 </wsd:ProbeMatch></wsd:ProbeMatches></s:Body>
</s:Envelope>"""


def test_parse_onvif_response_skips_anonymous_address():
    hint = _parse_onvif_response(ONVIF_XML)
    assert hint is not None
    assert hint.ip == "192.168.1.64"
    assert hint.name == "Front Door IPC"
    assert hint.service == "onvif"
    assert hint.details["vendor"] == "Hikvision"


def test_discover_hints_deduplicates(monkeypatch):
    from absearch import discovery

    def fake(_timeout):
        return [discovery.DiscoveryHint("10.0.0.5", "Cam", "onvif", "onvif")]

    monkeypatch.setattr(discovery, "SOURCES", {"mdns": fake, "ssdp": fake, "onvif": fake})
    hints = discover_hints(timeout=0.1)
    assert len(hints) == 1
    assert hints[0].ip == "10.0.0.5"
