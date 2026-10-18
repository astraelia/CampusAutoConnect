"""Native Windows network queries, with a fail-closed PowerShell compatibility path.

No localized netsh parsing and no elevated privileges. Fixed scripts never receive secrets.
"""

import ctypes
import ipaddress
import json
import os
import subprocess
import threading
import time
import uuid
from collections.abc import Callable
from dataclasses import replace
from typing import Protocol
from urllib.parse import urlsplit

from campus_autoconnect.core.errors import CampusError
from campus_autoconnect.core.models import ErrorCode, NetworkAdapter, NetworkSnapshot
from campus_autoconnect.core.network_native import NativeFailure, NativeNetwork, NativeQueryError


class NetworkProvider(Protocol):
    def snapshot(self) -> NetworkSnapshot: ...
    def route_allows(self, url: str, snapshot: NetworkSnapshot) -> bool: ...


class _GUID(ctypes.Structure):
    _fields_ = [("data", ctypes.c_ubyte * 16)]


class _InterfaceInfo(ctypes.Structure):
    _fields_ = [("guid", _GUID), ("description", ctypes.c_wchar * 256), ("state", ctypes.c_uint32)]


class _SSID(ctypes.Structure):
    _fields_ = [("length", ctypes.c_uint32), ("data", ctypes.c_ubyte * 32)]


class _Association(ctypes.Structure):
    _fields_ = [
        ("ssid", _SSID),
        ("bss_type", ctypes.c_uint32),
        ("bssid", ctypes.c_ubyte * 6),
        ("phy_type", ctypes.c_uint32),
        ("phy_index", ctypes.c_uint32),
        ("signal", ctypes.c_uint32),
        ("rx_rate", ctypes.c_uint32),
        ("tx_rate", ctypes.c_uint32),
    ]


class _Security(ctypes.Structure):
    _fields_ = [
        ("enabled", ctypes.c_int32),
        ("one_x", ctypes.c_int32),
        ("auth", ctypes.c_uint32),
        ("cipher", ctypes.c_uint32),
    ]


class _Connection(ctypes.Structure):
    _fields_ = [
        ("state", ctypes.c_uint32),
        ("mode", ctypes.c_uint32),
        ("profile", ctypes.c_wchar * 256),
        ("association", _Association),
        ("security", _Security),
    ]


def decode_ssid(raw: bytes) -> str:
    if not 1 <= len(raw) <= 32:
        raise ValueError("SSID 字节长度无效。")
    value = raw.decode("utf-8", errors="strict")
    if any(ord(c) < 32 or ord(c) == 127 for c in value):
        raise ValueError("SSID 含不可显示字符。")
    return value


def read_wlan_ssids() -> tuple[dict[str, str], tuple[str, ...]]:
    """Return interface GUID -> exact SSID. Fail closed if location access is denied."""
    if os.name != "nt":
        return {}, ("windows_required",)
    try:
        dll = ctypes.WinDLL("wlanapi.dll")
        dword = ctypes.c_uint32
        ptr = ctypes.c_void_p
        dll.WlanOpenHandle.argtypes = [dword, ptr, ctypes.POINTER(dword), ctypes.POINTER(ptr)]
        dll.WlanOpenHandle.restype = dword
        dll.WlanEnumInterfaces.argtypes = [ptr, ptr, ctypes.POINTER(ptr)]
        dll.WlanEnumInterfaces.restype = dword
        dll.WlanQueryInterface.argtypes = [
            ptr,
            ctypes.POINTER(_GUID),
            dword,
            ptr,
            ctypes.POINTER(dword),
            ctypes.POINTER(ptr),
            ctypes.POINTER(dword),
        ]
        dll.WlanQueryInterface.restype = dword
        dll.WlanFreeMemory.argtypes = [ptr]
        dll.WlanFreeMemory.restype = None
        dll.WlanCloseHandle.argtypes = [ptr, ptr]
        dll.WlanCloseHandle.restype = dword
        handle, negotiated = ptr(), dword()
        if dll.WlanOpenHandle(2, None, ctypes.byref(negotiated), ctypes.byref(handle)):
            return {}, ("wlan_unavailable",)
        result: dict[str, str] = {}
        warnings: list[str] = []
        interfaces = ptr()
        try:
            status = dll.WlanEnumInterfaces(handle, None, ctypes.byref(interfaces))
            if status:
                return {}, ("ssid_permission_denied" if status == 5 else "wlan_unavailable",)
            count = dword.from_address(interfaces.value).value
            if count > 128:
                return {}, ("wlan_invalid_response",)
            for i in range(count):
                info = _InterfaceInfo.from_address(
                    interfaces.value + 8 + i * ctypes.sizeof(_InterfaceInfo)
                )
                if info.state != 1:
                    continue
                size, value_type, data = dword(), dword(), ptr()
                try:
                    status = dll.WlanQueryInterface(
                        handle,
                        ctypes.byref(info.guid),
                        7,
                        None,
                        ctypes.byref(size),
                        ctypes.byref(data),
                        ctypes.byref(value_type),
                    )
                    if status:
                        warnings.append(
                            "ssid_permission_denied" if status == 5 else "ssid_unavailable"
                        )
                        continue
                    if size.value < ctypes.sizeof(_Connection):
                        warnings.append("wlan_invalid_response")
                        continue
                    conn = _Connection.from_address(data.value)
                    ssid = conn.association.ssid
                    if ssid.length > 32:
                        warnings.append("ssid_encoding_unsupported")
                        continue
                    try:
                        name = decode_ssid(bytes(ssid.data[: ssid.length]))
                    except (UnicodeError, ValueError):
                        warnings.append("ssid_encoding_unsupported")
                        continue
                    guid = str(uuid.UUID(bytes_le=bytes(info.guid.data))).lower()
                    result[guid] = name
                finally:
                    if data:
                        dll.WlanFreeMemory(data)
        finally:
            if interfaces:
                dll.WlanFreeMemory(interfaces)
            dll.WlanCloseHandle(handle, None)
        return result, tuple(sorted(set(warnings)))
    except (OSError, AttributeError, ValueError):
        return {}, ("wlan_unavailable",)


_PREFIX = """
$ErrorActionPreference = 'Stop'
$OutputEncoding = [Console]::OutputEncoding = [Text.UTF8Encoding]::new($false)
"""
_SNAPSHOT_SCRIPT = (
    _PREFIX
    + """
$addresses = @(Get-NetIPAddress -ErrorAction Stop)
$routes = @(Get-NetRoute -ErrorAction Stop | Where-Object {
    $_.DestinationPrefix -in @('0.0.0.0/0', '::/0')
})
$servers = @(Get-DnsClientServerAddress -ErrorAction Stop)
$items = @(Get-NetAdapter | Sort-Object InterfaceIndex | ForEach-Object {
    $a = $_
    $ip = @($addresses | Where-Object {
        $_.InterfaceIndex -eq $a.InterfaceIndex -and
            $_.AddressState -in @('Preferred', 'Deprecated')
    })
    [pscustomobject]@{
        index = [int]$a.InterfaceIndex
        name = [string]$a.Name
        guid = [string]$a.InterfaceGuid
        connected = ($a.Status -eq 'Up')
        hardware = [bool]$a.HardwareInterface
        ipv4 = @($ip | Where-Object { $_.AddressFamily -eq 'IPv4' } |
            ForEach-Object { $_.IPAddress })
        ipv6 = @($ip | Where-Object { $_.AddressFamily -eq 'IPv6' } |
            ForEach-Object { $_.IPAddress })
        gateways = @($routes | Where-Object { $_.InterfaceIndex -eq $a.InterfaceIndex } |
            ForEach-Object { $_.NextHop } | Where-Object { $_ -notin @('0.0.0.0', '::') })
        dns = @($servers | Where-Object { $_.InterfaceIndex -eq $a.InterfaceIndex } |
            ForEach-Object { $_.ServerAddresses } | Where-Object { $_ })
    }
})
ConvertTo-Json -InputObject $items -Compress -Depth 6
"""
)
_ROUTE_SCRIPT = (
    _PREFIX
    + """
$target = [Console]::In.ReadToEnd() | ConvertFrom-Json
$addresses = @()
$ip = $null
if ([Net.IPAddress]::TryParse([string]$target.host, [ref]$ip)) {
    $addresses = @([string]$ip)
} else {
    $addresses = @(Resolve-DnsName -Name $target.host -DnsOnly -QuickTimeout |
        Where-Object { $_.Type -eq 'A' -or $_.Type -eq 'AAAA' } |
        ForEach-Object { $_.IPAddress })
}
$ok = ($addresses.Count -gt 0)
foreach ($address in $addresses) {
    $routes = @(Find-NetRoute -RemoteIPAddress $address)
    if ($routes.Count -eq 0) { $ok = $false }
    foreach ($r in $routes) {
        if ([int]$r.InterfaceIndex -ne [int]$target.index) { $ok = $false }
    }
}
ConvertTo-Json -InputObject ([bool]$ok) -Compress
"""
)


def _run_powershell(script: str, input_text: str = "") -> str:
    from campus_autoconnect.infrastructure.process_environment import system_process_environment

    if os.name != "nt":
        raise CampusError(ErrorCode.NETWORK_UNREACHABLE, "网络查询需要 Windows 10/11。")
    root = os.environ.get("SYSTEMROOT", r"C:\Windows")
    executable = os.path.join(root, "System32", "WindowsPowerShell", "v1.0", "powershell.exe")
    try:
        with system_process_environment() as environment:
            result = subprocess.run(
                [executable, "-NoProfile", "-NonInteractive", "-Command", script],
                input=input_text,
                capture_output=True,
                encoding="utf-8",
                errors="strict",
                timeout=18,
                check=True,
                creationflags=subprocess.CREATE_NO_WINDOW,
                env=environment,
            )
        return result.stdout.lstrip("\ufeff").strip()
    except subprocess.TimeoutExpired as exc:
        raise CampusError(ErrorCode.TIMEOUT, "Windows 网络查询超时，请稍后重试。") from exc
    except (OSError, UnicodeError, subprocess.CalledProcessError) as exc:
        raise CampusError(
            ErrorCode.NETWORK_UNREACHABLE, "Windows 网络查询失败，请检查系统网络服务。"
        ) from exc


def parse_adapters(raw: str, ssids: dict[str, str]) -> tuple[NetworkAdapter, ...]:
    data = json.loads(raw)
    if not isinstance(data, list):
        raise ValueError("网络查询结构无效。")
    result = []
    for item in data:
        guid = str(item["guid"]).strip("{}").lower()
        result.append(
            NetworkAdapter(
                index=int(item["index"]),
                name=str(item["name"]),
                guid=guid,
                connected=item["connected"] is True,
                hardware=item.get("hardware") is True,
                ssid=ssids.get(guid),
                ipv4=tuple(item.get("ipv4") or ()),
                ipv6=tuple(item.get("ipv6") or ()),
                gateways=tuple(item.get("gateways") or ()),
                dns=tuple(item.get("dns") or ()),
            )
        )
    return normalize_adapters(tuple(result))


def normalize_adapters(adapters: tuple[NetworkAdapter, ...]) -> tuple[NetworkAdapter, ...]:
    """Canonical order prevents API enumeration order becoming a false network switch."""
    if len(adapters) > 512:
        raise ValueError("网络接口数量超出限制。")
    result = []
    for adapter in adapters:
        if adapter.index <= 0 or not adapter.guid or len(adapter.name) > 1024:
            raise ValueError("网络接口结构无效。")

        def addresses(values: tuple[str, ...]) -> tuple[str, ...]:
            if len(values) > 512:
                raise ValueError("网络地址数量超出限制。")
            return tuple(sorted({str(ipaddress.ip_address(a.split("%")[0])) for a in values}))

        result.append(
            replace(
                adapter,
                guid=adapter.guid.lower(),
                ipv4=addresses(adapter.ipv4),
                ipv6=addresses(adapter.ipv6),
                gateways=addresses(adapter.gateways),
                dns=addresses(adapter.dns),
            )
        )
    if len({a.index for a in result}) != len(result) or len({a.guid for a in result}) != len(
        result
    ):
        raise ValueError("网络接口标识不唯一。")
    return tuple(sorted(result, key=lambda a: a.index))


class WindowsNetworkProvider:
    def __init__(
        self,
        runner: Callable[[str, str], str] = _run_powershell,
        wlan_reader: Callable = read_wlan_ssids,
        *,
        native: NativeNetwork | None = None,
        prefer_native: bool = True,
    ) -> None:
        self._run = runner
        self._wlan = wlan_reader
        # An explicitly injected legacy runner stays isolated from the real host APIs.
        self._native = native or (
            NativeNetwork() if prefer_native and runner is _run_powershell else None
        )
        self._fallback_reason: NativeFailure | None = None
        self._query_lock = threading.RLock()
        self._snapshot_ms = self._route_ms = 0

    def diagnostics(self) -> dict:
        return {
            "backend": "native" if self._native is not None else "powershell",
            "fallback_reason": self._fallback_reason.value if self._fallback_reason else None,
            "snapshot_ms": self._snapshot_ms,
            "route_ms": self._route_ms,
        }

    def _degrade(self, error: NativeQueryError) -> None:
        self._fallback_reason = error.reason
        self._native = None

    def snapshot(self) -> NetworkSnapshot:
        with self._query_lock:
            start = time.monotonic()
            try:
                return self._snapshot()
            finally:
                self._snapshot_ms = min(86400000, round((time.monotonic() - start) * 1000))

    def _snapshot(self) -> NetworkSnapshot:
        ssids, warnings = self._wlan()
        try:
            if self._native is not None:
                try:
                    adapters = normalize_adapters(self._native.snapshot(ssids))
                    return NetworkSnapshot(adapters, warnings)
                except NativeQueryError as exc:
                    self._degrade(exc)
                    # Fresh complete fallback; never combine partial native and legacy data.
                    ssids, warnings = self._wlan()
                except (ValueError, TypeError):
                    self._degrade(NativeQueryError(NativeFailure.INVALID_RESPONSE))
                    ssids, warnings = self._wlan()
            return NetworkSnapshot(parse_adapters(self._run(_SNAPSHOT_SCRIPT, ""), ssids), warnings)
        except (ValueError, KeyError, TypeError) as exc:
            raise CampusError(ErrorCode.NETWORK_UNREACHABLE, "Windows 网络数据无法识别。") from exc

    def route_allows(self, url: str, snapshot: NetworkSnapshot) -> bool:
        with self._query_lock:
            start = time.monotonic()
            try:
                return self._route_allows(url, snapshot)
            finally:
                self._route_ms = min(86400000, round((time.monotonic() - start) * 1000))

    def _route_allows(self, url: str, snapshot: NetworkSnapshot) -> bool:
        wifi = snapshot.wifi
        if not wifi or not wifi.hardware or snapshot.warnings:
            return False
        # Conservatively reject active virtual gateways before resolving the portal.
        if any(a.connected and not a.hardware and a.gateways for a in snapshot.adapters):
            return False
        try:
            if self._native is not None:
                try:
                    host = urlsplit(url).hostname
                    return bool(host) and self._native.route_allows(host, snapshot)
                except NativeQueryError as exc:
                    self._degrade(exc)
                    # A backend switch invalidates the old context unless freshly re-established.
                    current = self._snapshot()
                    if current.fingerprint != snapshot.fingerprint:
                        return False
            value = self._run(
                _ROUTE_SCRIPT, json.dumps({"host": urlsplit(url).hostname, "index": wifi.index})
            )
            return json.loads(value) is True
        except (CampusError, ValueError, TypeError):
            return False
