"""Read-only Windows IP Helper queries. No network mutation or credential access.

The ctypes layouts follow the Windows SDK, using fixed-width Windows types. Only
the supported x64 ABI is admitted. Variable lists are read inside their owning
buffer with length, cycle and allocation limits before dereferencing pointers.
"""

import ctypes as c
import ipaddress
import os
import socket
import uuid
from collections.abc import Callable, Iterator
from enum import StrEnum
from pathlib import Path

from campus_autoconnect.core.errors import CampusError
from campus_autoconnect.core.models import ErrorCode, NetworkAdapter, NetworkSnapshot

U8, U16, U32, U64 = c.c_uint8, c.c_uint16, c.c_uint32, c.c_uint64
PTR = c.c_void_p
MAX_BUFFER = 16 * 1024 * 1024
MAX_ITEMS = 512


class NativeFailure(StrEnum):
    UNAVAILABLE = "native_unavailable"
    API_ERROR = "native_api_error"
    INVALID_RESPONSE = "native_invalid_response"
    BUFFER_LIMIT = "native_buffer_limit"


class NativeQueryError(Exception):
    def __init__(self, reason: NativeFailure) -> None:
        self.reason = reason
        super().__init__(reason.value)


class Guid(c.Structure):
    _fields_ = [("data", U8 * 16)]


class SocketAddress(c.Structure):
    _fields_ = [("pointer", PTR), ("length", c.c_int32)]


class AddressNode(c.Structure):
    _fields_ = [("length", U32), ("flags", U32), ("next", PTR), ("address", SocketAddress)]


class UnicastNode(c.Structure):
    _fields_ = AddressNode._fields_ + [
        ("prefix_origin", U32),
        ("suffix_origin", U32),
        ("dad_state", U32),
        ("valid_lifetime", U32),
        ("preferred_lifetime", U32),
        ("lease_lifetime", U32),
        ("prefix_length", U8),
    ]


class AdapterNode(c.Structure):
    # Prefix through Luid; later Windows fields are not dereferenced.
    _fields_ = [
        ("length", U32),
        ("index", U32),
        ("next", PTR),
        ("adapter_name", PTR),
        ("unicast", PTR),
        ("anycast", PTR),
        ("multicast", PTR),
        ("dns", PTR),
        ("dns_suffix", PTR),
        ("description", PTR),
        ("friendly_name", PTR),
        ("physical_address", U8 * 8),
        ("physical_address_length", U32),
        ("flags", U32),
        ("mtu", U32),
        ("if_type", U32),
        ("oper_status", U32),
        ("ipv6_index", U32),
        ("zone_indices", U32 * 16),
        ("prefix", PTR),
        ("transmit_speed", U64),
        ("receive_speed", U64),
        ("wins", PTR),
        ("gateways", PTR),
        ("ipv4_metric", U32),
        ("ipv6_metric", U32),
        ("luid", U64),
    ]


class InterfaceRow(c.Structure):
    _fields_ = [
        ("luid", U64),
        ("index", U32),
        ("guid", Guid),
        ("alias", U16 * 257),
        ("description", U16 * 257),
        ("physical_length", U32),
        ("physical", U8 * 32),
        ("permanent", U8 * 32),
        ("mtu", U32),
        ("if_type", U32),
        ("tunnel_type", U32),
        ("media_type", U32),
        ("physical_medium", U32),
        ("access_type", U32),
        ("direction", U32),
        ("status_flags", U8),
        ("oper_status", U32),
        ("admin_status", U32),
        ("media_connect_state", U32),
        ("network_guid", Guid),
        ("connection_type", U32),
        ("transmit_speed", U64),
        ("receive_speed", U64),
        ("statistics", U64 * 18),
    ]


class Sockaddr4(c.Structure):
    _fields_ = [("family", U16), ("port", U16), ("address", U8 * 4), ("zero", U8 * 8)]


class Sockaddr6(c.Structure):
    _fields_ = [
        ("family", U16),
        ("port", U16),
        ("flow", U32),
        ("address", U8 * 16),
        ("scope", U32),
    ]


class SockaddrInet(c.Union):
    _fields_ = [("v4", Sockaddr4), ("v6", Sockaddr6), ("family", U16)]


class AddressPrefix(c.Structure):
    _fields_ = [("address", SockaddrInet), ("length", U8)]


class RouteRow(c.Structure):
    _fields_ = [
        ("luid", U64),
        ("index", U32),
        ("prefix", AddressPrefix),
        ("next_hop", SockaddrInet),
        ("site_prefix_length", U8),
        ("valid_lifetime", U32),
        ("preferred_lifetime", U32),
        ("metric", U32),
        ("protocol", U32),
        ("loopback", U8),
        ("autoconfigure", U8),
        ("publish", U8),
        ("immortal", U8),
        ("age", U32),
        ("origin", U32),
    ]


class BufferReader:
    def __init__(self, buffer: c.Array) -> None:
        self.buffer = buffer
        self.start = c.addressof(buffer)
        self.end = self.start + c.sizeof(buffer)

    def read(self, pointer: int | None, size: int) -> bytes:
        if pointer is None or size < 0 or not self.start <= pointer <= self.end - size:
            raise NativeQueryError(NativeFailure.INVALID_RESPONSE)
        return c.string_at(pointer, size)

    def nodes(self, pointer: int | None, layout: type[c.Structure]) -> Iterator[c.Structure]:
        visited = set()
        while pointer:
            if pointer in visited or len(visited) >= MAX_ITEMS:
                raise NativeQueryError(NativeFailure.INVALID_RESPONSE)
            visited.add(pointer)
            length = U32.from_buffer_copy(self.read(pointer, 4)).value
            if length < c.sizeof(layout):
                raise NativeQueryError(NativeFailure.INVALID_RESPONSE)
            self.read(pointer, length)
            node = layout.from_buffer_copy(self.read(pointer, c.sizeof(layout)))
            yield node
            pointer = node.next

    def addresses(self, pointer: int | None, *, unicast: bool = False) -> tuple[str, ...]:
        values = []
        for node in self.nodes(pointer, UnicastNode if unicast else AddressNode):
            # Tentative, duplicate and invalid addresses cannot authorize authentication.
            if unicast and node.dad_state not in (3, 4):
                continue
            data = self.read(node.address.pointer, node.address.length)
            values.append(decode_address(data))
        return tuple(sorted(set(values)))


def decode_address(data: bytes) -> str:
    if len(data) >= c.sizeof(Sockaddr4) and int.from_bytes(data[:2], "little") == 2:
        return str(ipaddress.IPv4Address(data[4:8]))
    if len(data) >= c.sizeof(Sockaddr6) and int.from_bytes(data[:2], "little") == 23:
        return str(ipaddress.IPv6Address(data[8:24]))
    raise NativeQueryError(NativeFailure.INVALID_RESPONSE)


def destination_address(value: str) -> SockaddrInet:
    address = ipaddress.ip_address(value)
    result = SockaddrInet()
    if address.version == 4:
        result.v4.family = 2
        result.v4.address[:] = address.packed
    else:
        result.v6.family = 23
        result.v6.address[:] = address.packed
        if address.scope_id:
            result.v6.scope = int(address.scope_id)
    return result


class NativeNetwork:
    def __init__(
        self, *, loader: Callable | None = None, resolver: Callable = socket.getaddrinfo
    ) -> None:
        self._loader = loader
        self._resolver = resolver
        self._dll = None

    def _api(self) -> c.CDLL:
        if self._dll is not None:
            return self._dll
        if c.sizeof(PTR) != 8 or (os.name != "nt" and self._loader is None):
            raise NativeQueryError(NativeFailure.UNAVAILABLE)
        try:
            loader = self._loader or c.WinDLL
            dll = loader(
                str(Path(os.environ.get("SYSTEMROOT", r"C:\Windows")) / "System32/iphlpapi.dll")
            )
            dll.GetAdaptersAddresses.argtypes = [U32, U32, PTR, PTR, c.POINTER(U32)]
            dll.GetAdaptersAddresses.restype = U32
            dll.GetIfEntry2.argtypes = [c.POINTER(InterfaceRow)]
            dll.GetIfEntry2.restype = U32
            dll.GetBestRoute2.argtypes = [
                c.POINTER(U64),
                U32,
                c.POINTER(SockaddrInet),
                c.POINTER(SockaddrInet),
                U32,
                c.POINTER(RouteRow),
                c.POINTER(SockaddrInet),
            ]
            dll.GetBestRoute2.restype = U32
        except (OSError, AttributeError) as exc:
            raise NativeQueryError(NativeFailure.UNAVAILABLE) from exc
        self._dll = dll
        return dll

    def snapshot(self, ssids: dict[str, str]) -> tuple[NetworkAdapter, ...]:
        dll = self._api()
        size = U32(65536)
        for _ in range(3):
            if not 1 <= size.value <= MAX_BUFFER:
                raise NativeQueryError(NativeFailure.BUFFER_LIMIT)
            buffer = c.create_string_buffer(size.value)
            status = dll.GetAdaptersAddresses(0, 0x186, None, buffer, c.byref(size))
            if status == 232:  # ERROR_NO_DATA is an empty network, not an API failure.
                return ()
            if status == 111:  # ERROR_BUFFER_OVERFLOW: allocation size may change again.
                continue
            if status:
                raise NativeQueryError(NativeFailure.API_ERROR)
            break
        else:
            raise NativeQueryError(NativeFailure.BUFFER_LIMIT)
        reader = BufferReader(buffer)
        adapters = []
        for item in reader.nodes(reader.start, AdapterNode):
            if item.if_type == 24:  # Software loopback is not an external network adapter.
                continue
            row = InterfaceRow(luid=item.luid)
            code = dll.GetIfEntry2(c.byref(row))
            if code in (2, 1168):
                raise CampusError(
                    ErrorCode.NETWORK_CHANGED, "查询期间网卡发生变化，请等待网络稳定。"
                )
            if code:
                raise NativeQueryError(NativeFailure.API_ERROR)
            if not row.index or row.luid != item.luid or row.oper_status != item.oper_status:
                raise CampusError(ErrorCode.NETWORK_CHANGED, "查询期间网络状态发生变化。")
            if row.status_flags & 0x82:
                # NDIS filter layers and endpoints are not independent adapters.
                continue
            guid = str(uuid.UUID(bytes_le=bytes(row.guid.data)))
            try:
                alias = bytes(row.alias).decode("utf-16-le", errors="strict").split("\0", 1)[0]
            except UnicodeError as exc:
                raise NativeQueryError(NativeFailure.INVALID_RESPONSE) from exc
            addresses = reader.addresses(item.unicast, unicast=True)
            adapters.append(
                NetworkAdapter(
                    index=row.index,
                    name=alias,
                    guid=guid,
                    connected=row.oper_status == 1,
                    hardware=bool(row.status_flags & 1),
                    ssid=ssids.get(guid),
                    ipv4=tuple(a for a in addresses if ":" not in a),
                    ipv6=tuple(a for a in addresses if ":" in a),
                    gateways=reader.addresses(item.gateways),
                    dns=reader.addresses(item.dns),
                )
            )
        return tuple(sorted(adapters, key=lambda a: a.index))

    def route_allows(self, host: str, snapshot: NetworkSnapshot) -> bool:
        wifi = snapshot.wifi
        if wifi is None:
            return False
        dll = self._api()
        row = InterfaceRow(index=wifi.index)
        code = dll.GetIfEntry2(c.byref(row))
        if code in (2, 1168):
            return False
        if code:
            raise NativeQueryError(NativeFailure.API_ERROR)
        if (
            str(uuid.UUID(bytes_le=bytes(row.guid.data))) != wifi.guid
            or row.oper_status != 1
            or not row.status_flags & 1
        ):
            return False
        try:
            ipaddress.ip_address(host)
            addresses = {host}
        except ValueError:
            try:
                addresses = {
                    item[4][0] for item in self._resolver(host, None, 0, socket.SOCK_STREAM)
                }
            except (OSError, ValueError):
                return False
        if not 1 <= len(addresses) <= 64:
            return False
        allowed_sources = {a.split("%")[0] for a in (*wifi.ipv4, *wifi.ipv6)}
        for address in sorted(addresses):
            try:
                target = destination_address(address)
            except (ValueError, OverflowError):
                return False
            route, source = RouteRow(), SockaddrInet()
            # Unconstrained query: observe Windows' selected route, never force Wi-Fi.
            code = dll.GetBestRoute2(
                None, 0, None, c.byref(target), 0, c.byref(route), c.byref(source)
            )
            if code in (2, 50, 1168, 1231):
                return False
            if code:
                raise NativeQueryError(NativeFailure.API_ERROR)
            source_ip = decode_address(bytes(source))
            if (
                route.luid != row.luid
                or route.index != wifi.index
                or source_ip not in allowed_sources
            ):
                return False
        return True
