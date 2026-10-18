import ctypes as c
import json
from dataclasses import replace

import pytest

from campus_autoconnect.core.errors import CampusError
from campus_autoconnect.core.models import ErrorCode, NetworkSnapshot
from campus_autoconnect.core.network import WindowsNetworkProvider, normalize_adapters
from campus_autoconnect.core.network_native import (
    MAX_BUFFER,
    AdapterNode,
    AddressNode,
    BufferReader,
    Guid,
    InterfaceRow,
    NativeFailure,
    NativeNetwork,
    NativeQueryError,
    RouteRow,
    SockaddrInet,
    UnicastNode,
    destination_address,
)

pytestmark = pytest.mark.mock
GUID = "00000000-0000-0000-0000-000000000007"


class FakeApi:
    def __init__(self):
        self.snapshot_calls = 0
        self.index = 7
        self.flags = 5
        self.dad_state = 4
        self.statuses = [0]
        self.route_index = 7
        self.route_code = 0
        self.route_calls = []

    def GetAdaptersAddresses(self, family, flags, reserved, buffer, size):
        self.snapshot_calls += 1
        status = self.statuses.pop(0) if len(self.statuses) > 1 else self.statuses[0]
        if status == 111:
            c.cast(size, c.POINTER(c.c_uint32))[0] = 131072
            return status
        if status:
            return status
        base = c.addressof(buffer)
        node = AdapterNode.from_buffer(buffer)
        node.length = c.sizeof(AdapterNode)
        node.index, node.luid, node.if_type, node.oper_status = self.index, 707, 71, 1
        node.unicast, node.gateways, node.dns = base + 256, base + 352, base + 448
        for offset, value, unicast in (
            (256, "192.0.2.10", True),
            (352, "192.0.2.1", False),
            (448, "192.0.2.53", False),
        ):
            layout = UnicastNode if unicast else AddressNode
            item = layout.from_buffer(buffer, offset)
            item.length = c.sizeof(layout)
            item.address.pointer, item.address.length = base + offset + 64, 16
            address = destination_address(value)
            c.memmove(item.address.pointer, c.byref(address), 16)
            if unicast:
                item.dad_state = self.dad_state
        return 0

    def GetIfEntry2(self, pointer):
        row = c.cast(pointer, c.POINTER(InterfaceRow)).contents
        row.index, row.luid, row.oper_status, row.status_flags = self.index, 707, 1, self.flags
        row.guid = Guid((c.c_uint8 * 16)(*bytes.fromhex("00000000000000000000000000000007")))
        return 0

    def GetBestRoute2(self, luid, index, source, destination, options, route, chosen_source):
        assert luid is None and index == 0 and source is None  # No forced Wi-Fi route.
        target = c.cast(destination, c.POINTER(SockaddrInet)).contents
        self.route_calls.append(target.family)
        result = c.cast(route, c.POINTER(RouteRow)).contents
        result.index, result.luid = self.route_index, 707
        address = destination_address("192.0.2.10" if target.family == 2 else "2001:db8::10")
        c.memmove(chosen_source, c.byref(address), c.sizeof(address))
        return self.route_code


@pytest.fixture
def native():
    result = NativeNetwork()
    result._dll = FakeApi()
    return result


def test_windows_x64_abi_sizes_and_offsets():
    assert c.sizeof(c.c_void_p) == 8
    assert c.sizeof(InterfaceRow) == 1352
    assert c.sizeof(RouteRow) == 104
    assert c.sizeof(AdapterNode) == 232
    assert c.sizeof(SockaddrInet) == 28
    assert InterfaceRow.status_flags.offset == 1152
    assert AdapterNode.luid.offset == 224


def test_native_reads_full_snapshot_and_resolves_exact_guid(native):
    (adapter,) = native.snapshot({GUID: "Example-Campus"})
    assert adapter.index == 7 and adapter.hardware and adapter.connected
    assert adapter.ssid == "Example-Campus"
    assert adapter.ipv4 == ("192.0.2.10",)
    assert adapter.gateways == ("192.0.2.1",)
    assert adapter.dns == ("192.0.2.53",)
    native._dll.index = 99
    assert native.snapshot({GUID: "Other"})[0].index == 99


@pytest.mark.parametrize("state", [0, 1, 2])
def test_invalid_tentative_duplicate_addresses_cannot_authorize(native, state):
    native._dll.dad_state = state
    assert native.snapshot({GUID: "Example-Campus"})[0].ipv4 == ()


@pytest.mark.parametrize("flags", [2, 128, 130])
def test_filter_layers_and_endpoints_are_not_network_adapters(native, flags):
    native._dll.flags = flags
    assert native.snapshot({}) == ()


def test_buffer_expands_from_returned_size_with_bounded_retries(native):
    native._dll.statuses = [111, 0]
    assert len(native.snapshot({})) == 1
    assert native._dll.snapshot_calls == 2
    native._dll.statuses = [111]
    with pytest.raises(NativeQueryError) as error:
        native.snapshot({})
    assert error.value.reason == NativeFailure.BUFFER_LIMIT
    assert native._dll.snapshot_calls == 5


def test_oversized_allocation_is_rejected_before_allocating(native):
    def oversized(*args):
        c.cast(args[-1], c.POINTER(c.c_uint32))[0] = MAX_BUFFER + 1
        return 111

    native._dll.GetAdaptersAddresses = oversized
    with pytest.raises(NativeQueryError) as error:
        native.snapshot({})
    assert error.value.reason == NativeFailure.BUFFER_LIMIT


def test_no_data_is_valid_empty_network_not_technical_failure(native):
    native._dll.statuses = [232]
    assert native.snapshot({}) == ()


@pytest.mark.parametrize("corruption", ["short", "outside", "cycle", "socket"])
def test_malformed_buffer_never_dereferences_outside_owned_memory(corruption):
    buffer = c.create_string_buffer(1024)
    reader = BufferReader(buffer)
    node = AddressNode.from_buffer(buffer)
    node.length = c.sizeof(AddressNode)
    if corruption == "short":
        node.length = 8
    elif corruption == "outside":
        node.next = reader.end + 100
    elif corruption == "cycle":
        node.next = reader.start
    else:
        node.address.pointer = reader.end + 1
        node.address.length = 28
    with pytest.raises(NativeQueryError):
        if corruption == "socket":
            reader.addresses(reader.start)
        else:
            list(reader.nodes(reader.start, AddressNode))


def test_loader_failure_has_only_safe_reason():
    def fail(_):
        raise OSError("must-not-be-exposed")

    with pytest.raises(NativeQueryError) as error:
        NativeNetwork(loader=fail).snapshot({})
    assert str(error.value) == "native_unavailable"


def test_native_route_checks_all_dns_families_and_source(native, snapshot):
    native._resolver = lambda *_: [
        (2, 1, 6, "", ("192.0.2.1", 0)),
        (23, 1, 6, "", ("2001:db8::1", 0, 0, 0)),
    ]
    assert native.route_allows("portal.example.test", snapshot)
    assert set(native._dll.route_calls) == {2, 23}
    native._dll.route_index = 9
    assert not native.route_allows("192.0.2.1", snapshot)
    other = replace(snapshot.adapters[0], ipv4=("192.0.2.99",))
    native._dll.route_index = 7
    assert not native.route_allows("192.0.2.1", NetworkSnapshot((other,)))


@pytest.mark.parametrize("code", [2, 50, 1168, 1231])
def test_native_unknown_or_missing_route_is_denial_not_fallback(native, snapshot, code):
    native._dll.route_code = code
    assert not native.route_allows("192.0.2.1", snapshot)


def test_native_route_technical_failure_is_distinct(native, snapshot):
    native._dll.route_code = 87
    with pytest.raises(NativeQueryError):
        native.route_allows("192.0.2.1", snapshot)


def legacy_json(snapshot):
    a = snapshot.adapters[0]
    return json.dumps(
        [
            dict(
                index=a.index,
                guid=a.guid,
                name=a.name,
                connected=a.connected,
                hardware=a.hardware,
                ipv4=a.ipv4,
                ipv6=a.ipv6,
                gateways=a.gateways,
                dns=a.dns,
            )
        ]
    )


def test_native_failure_degrades_once_and_fallback_recollects_complete_context(snapshot):
    class Broken:
        calls = 0

        def snapshot(self, _):
            self.calls += 1
            raise NativeQueryError(NativeFailure.UNAVAILABLE)

    broken = Broken()
    provider = WindowsNetworkProvider(
        native=broken,
        runner=lambda *_: legacy_json(snapshot),
        wlan_reader=lambda: ({GUID: snapshot.ssid}, ()),
    )
    assert provider.snapshot().fingerprint == snapshot.fingerprint
    assert provider.snapshot().fingerprint == snapshot.fingerprint
    assert broken.calls == 1
    assert provider.diagnostics()["fallback_reason"] == "native_unavailable"


def test_valid_empty_native_snapshot_and_wlan_warning_do_not_fallback(native):
    native._dll.statuses = [232]
    provider = WindowsNetworkProvider(
        native=native,
        runner=lambda *_: pytest.fail("no fallback"),
        wlan_reader=lambda: ({}, ("ssid_permission_denied",)),
    )
    assert provider.snapshot() == NetworkSnapshot(warnings=("ssid_permission_denied",))


def test_native_route_denial_never_tries_powershell(native, snapshot):
    native._dll.route_index = 8
    provider = WindowsNetworkProvider(native=native, runner=lambda *_: pytest.fail("no fallback"))
    assert not provider.route_allows("https://192.0.2.1", snapshot)
    assert provider.diagnostics()["backend"] == "native"


def test_route_backend_switch_requires_fresh_matching_context(native, snapshot):
    native._dll.route_code = 87
    calls = []

    def runner(script, payload):
        calls.append(bool(payload))
        return "true" if payload else legacy_json(snapshot)

    provider = WindowsNetworkProvider(
        native=native, runner=runner, wlan_reader=lambda: ({GUID: snapshot.ssid}, ())
    )
    assert provider.route_allows("https://192.0.2.1", snapshot)
    assert calls == [False, True]
    native._dll.route_code = 87
    provider = WindowsNetworkProvider(
        native=native, runner=lambda *_: "[]", wlan_reader=lambda: ({}, ())
    )
    assert not provider.route_allows("https://192.0.2.1", snapshot)


def test_network_change_is_not_a_technical_fallback(snapshot):
    class Changed:
        def snapshot(self, _):
            raise CampusError(ErrorCode.NETWORK_CHANGED, "synthetic")

    provider = WindowsNetworkProvider(
        native=Changed(), runner=lambda *_: pytest.fail("no fallback")
    )
    with pytest.raises(CampusError) as error:
        provider.snapshot()
    assert error.value.code == ErrorCode.NETWORK_CHANGED


def test_address_order_is_canonical_but_changed_ip_is_still_a_new_network(snapshot):
    a = snapshot.adapters[0]
    one = replace(a, dns=("192.0.2.54", "192.0.2.53"))
    two = replace(a, dns=tuple(reversed(one.dns)))
    assert normalize_adapters((one,)) == normalize_adapters((two,))
    assert normalize_adapters((a,)) != normalize_adapters((replace(a, ipv4=("192.0.2.99",)),))
