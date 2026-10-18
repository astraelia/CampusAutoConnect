import json
from dataclasses import replace

import pytest

from campus_autoconnect.core.errors import CampusError
from campus_autoconnect.core.models import NetworkSnapshot
from campus_autoconnect.core.network import WindowsNetworkProvider, decode_ssid, parse_adapters

pytestmark = pytest.mark.mock


@pytest.mark.parametrize("ssid", ["Example-Campus", "校园示例", "Network : 1", " SSID "])
def test_exact_ssid_unicode(ssid):
    assert decode_ssid(ssid.encode("utf-8")) == ssid


@pytest.mark.parametrize("raw", [b"", b"x" * 33, b"\xff", b"bad\x00ssid"])
def test_unsupported_ssid_fails_closed(raw):
    with pytest.raises((UnicodeError, ValueError)):
        decode_ssid(raw)


def test_structured_adapter_parse_and_guid_match():
    raw = json.dumps(
        [
            {
                "index": 7,
                "name": "无线网络",
                "guid": "{ABC-DEF}",
                "connected": True,
                "hardware": True,
                "ipv4": ["192.0.2.10"],
                "ipv6": ["2001:db8::1"],
                "gateways": ["192.0.2.1"],
                "dns": ["192.0.2.53"],
            }
        ]
    )
    (adapter,) = parse_adapters(raw, {"abc-def": "Example-Campus"})
    assert adapter.ssid == "Example-Campus"
    assert adapter.ipv6 == ("2001:db8::1",)
    assert adapter.dns == ("192.0.2.53",)
    assert NetworkSnapshot((adapter,)).connected


def test_ambiguous_wifi_has_no_match(snapshot):
    other = replace(snapshot.adapters[0], index=8, ssid="Other")
    assert NetworkSnapshot(snapshot.adapters + (other,)).ssid is None


def test_provider_permission_warning_preserved():
    provider = WindowsNetworkProvider(
        runner=lambda *_: "[]", wlan_reader=lambda: ({}, ("ssid_permission_denied",))
    )
    assert provider.snapshot().warnings == ("ssid_permission_denied",)


def test_invalid_powershell_json_reported():
    provider = WindowsNetworkProvider(runner=lambda *_: "{bad", wlan_reader=lambda: ({}, ()))
    with pytest.raises(CampusError):
        provider.snapshot()


def test_route_gate_requires_physical_wifi(snapshot):
    provider = WindowsNetworkProvider(runner=lambda *_: "true")
    assert provider.route_allows("https://portal.example.edu", snapshot)
    assert not provider.route_allows("https://portal.example.edu", NetworkSnapshot())
    virtual = replace(snapshot.adapters[0], index=8, ssid=None, hardware=False)
    assert not provider.route_allows(
        "https://portal.example.edu", NetworkSnapshot(snapshot.adapters + (virtual,))
    )
    assert not provider.route_allows(
        "https://portal.example.edu", replace(snapshot, warnings=("ssid_permission_denied",))
    )
