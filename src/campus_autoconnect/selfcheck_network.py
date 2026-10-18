"""Opt-in, read-only host checks; no HTTP, profile, account or credential access."""

import ctypes
import time

from campus_autoconnect.core.network import WindowsNetworkProvider
from campus_autoconnect.core.network_native import (
    InterfaceRow,
    NativeNetwork,
    RouteRow,
    destination_address,
)


def run() -> dict:
    native = WindowsNetworkProvider()
    legacy = WindowsNetworkProvider(prefer_native=False)
    samples = []
    snapshots = []
    for _ in range(3):
        start = time.monotonic()
        snapshots.append(native.snapshot())
        samples.append(round((time.monotonic() - start) * 1000, 2))
    start = time.monotonic()
    previous = legacy.snapshot()
    legacy_ms = round((time.monotonic() - start) * 1000, 2)
    current = native.snapshot()
    by_guid = {a.guid: a for a in current.adapters}

    # Native IP Helper also enumerates hidden system interfaces. Compare every
    # legacy adapter, and all active interfaces with addresses, by semantic fields.
    def context(a):
        return a.index, a.connected, a.hardware, a.ssid, a.ipv4, a.ipv6, a.gateways, a.dns

    common_matches = all(
        a.guid in by_guid and context(a) == context(by_guid[a.guid]) for a in previous.adapters
    )
    known = {a.guid for a in previous.adapters}
    extra_active = [
        a
        for a in current.adapters
        if a.guid not in known and a.connected and (a.ipv4 or a.ipv6 or a.gateways)
    ]
    # Exercise GetBestRoute2 without sending a packet or forcing an interface.
    api = NativeNetwork()._api()
    target = destination_address("127.0.0.1")
    route = RouteRow()
    from campus_autoconnect.core.network_native import SockaddrInet

    source = SockaddrInet()
    code = api.GetBestRoute2(
        None, 0, None, ctypes.byref(target), 0, ctypes.byref(route), ctypes.byref(source)
    )
    return {
        "native_backend_selected": native.diagnostics()["backend"] == "native",
        "x64_abi_layout": ctypes.sizeof(InterfaceRow) == 1352 and ctypes.sizeof(RouteRow) == 104,
        "snapshot_stable": snapshots[0].fingerprint == current.fingerprint,
        "legacy_adapters_match": common_matches,
        "no_unmatched_active_addressed_interfaces": not extra_active,
        "loopback_route_api_succeeded": code == 0 and route.index > 0,
        "native_snapshot_ms": samples,
        "powershell_snapshot_ms": legacy_ms,
        "identifiers": "withheld",
        "http_requests": "not_attempted",
    }
