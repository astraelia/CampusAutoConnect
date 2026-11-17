"""Immutable domain data; no GUI or operating-system dependencies."""

from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from ipaddress import IPv4Address


class AuthState(StrEnum):
    DISCONNECTED = "DISCONNECTED"
    NETWORK_CONNECTED = "NETWORK_CONNECTED"
    CHECKING = "CHECKING"
    AUTH_REQUIRED = "AUTH_REQUIRED"
    AUTHENTICATING = "AUTHENTICATING"
    AUTHENTICATED = "AUTHENTICATED"
    AUTH_FAILED = "AUTH_FAILED"
    UNKNOWN = "UNKNOWN"


class ErrorCode(StrEnum):
    NONE = "none"
    NETWORK_UNREACHABLE = "network_unreachable"
    TIMEOUT = "timeout"
    DNS_ERROR = "dns_error"
    PORTAL_UNRECOGNIZED = "portal_unrecognized"
    SERVER_ERROR = "server_error"
    INVALID_CREDENTIALS = "invalid_credentials"
    MANUAL_ACTION = "manual_action"
    PROTOCOL_CHANGED = "protocol_changed"
    PROTOCOL_UNVERIFIED = "protocol_unverified"
    SESSION_FIELDS_INVALID = "session_fields_invalid"
    SESSION_IP_MISMATCH = "session_ip_mismatch"
    SESSION_MAC_INVALID = "session_mac_invalid"
    ZERO_MAC_PERMISSION_REQUIRED = "zero_mac_permission_required"
    SESSION_VLAN_INVALID = "session_vlan_invalid"
    ALREADY_AUTHENTICATED = "already_authenticated"
    UNTRUSTED_NETWORK = "untrusted_network"
    UNTRUSTED_TARGET = "untrusted_target"
    TLS_ERROR = "tls_error"
    ROUTE_UNCONFIRMED = "route_unconfirmed"
    CREDENTIALS_MISSING = "credentials_missing"
    CREDENTIAL_STORE = "credential_store"
    CREDENTIAL_VERIFY = "credential_verify"
    CONFIG_ERROR = "config_error"
    NETWORK_CHANGED = "network_changed"
    CANCELLED = "cancelled"
    BUSY = "busy"
    AUTOMATION_DISABLED = "automation_disabled"
    STARTUP_ERROR = "startup_error"
    UNKNOWN = "unknown"


class AuthStage(StrEnum):
    NOT_STARTED = "not_started"
    NETWORK = "network"
    CONNECTIVITY = "connectivity"
    PROFILE = "profile"
    TARGET = "target"
    ROUTE = "route"
    PREPARE = "prepare"
    CREDENTIALS = "credentials"
    SUBMIT = "submit"
    VERIFY = "verify"
    COMPLETED = "completed"


AUTH_STAGE_LABELS = {
    AuthStage.NOT_STARTED: "尚未执行",
    AuthStage.NETWORK: "读取网络",
    AuthStage.CONNECTIVITY: "检测互联网",
    AuthStage.PROFILE: "匹配网络档案",
    AuthStage.TARGET: "检查认证入口与许可",
    AuthStage.ROUTE: "核对校园网路由",
    AuthStage.PREPARE: "核对实时会话和协议",
    AuthStage.CREDENTIALS: "读取安全凭据及提交前复核",
    AuthStage.SUBMIT: "发起单次登录",
    AuthStage.VERIFY: "验证登录后的互联网",
    AuthStage.COMPLETED: "检测完成",
}


class ProfileIssue(StrEnum):
    DISABLED = "profile_disabled"
    PAGE_MISSING = "portal_page_missing"
    API_MISSING = "api_origin_missing"
    HTTP_PERMISSION = "http_permission_required"
    HTTPS_TRUST = "https_targets_untrusted"
    WIRED_PROTOCOL = "wired_protocol_unverified"


@dataclass(frozen=True)
class AuthProgress:
    """Only enums and facts from this operation, never identifiers or secrets."""

    stage: AuthStage = AuthStage.NOT_STARTED
    profile_matched: bool = False
    portal_page_configured: bool = False
    api_origin_configured: bool = False
    http_auth_allowed: bool = False
    zero_mac_allowed: bool = False
    zero_mac_observed: bool | None = None
    zero_vlan_observed: bool | None = None
    profile_issues: tuple[ProfileIssue, ...] = ()
    credential_read_attempted: bool | None = None
    login_request_attempted: bool | None = None

    def diagnostic(self) -> dict:
        return {
            "stage": self.stage.value,
            "profile_matched": self.profile_matched,
            "portal_page_configured": self.portal_page_configured,
            "api_origin_configured": self.api_origin_configured,
            "http_auth_allowed": self.http_auth_allowed,
            "zero_mac_allowed": self.zero_mac_allowed,
            "zero_mac_observed": self.zero_mac_observed,
            "zero_vlan_observed": self.zero_vlan_observed,
            "profile_issues": [issue.value for issue in self.profile_issues],
            "credential_read_attempted": self.credential_read_attempted,
            "login_request_attempted": self.login_request_attempted,
        }


class LinkType(StrEnum):
    UNKNOWN = "unknown"
    WIFI = "wifi"
    ETHERNET = "ethernet"


BJUT_WIRED_ADAPTER = "bjut-wired"


def usable_ipv4(values: tuple[str, ...]) -> tuple[str, ...]:
    addresses = set()
    for value in values:
        try:
            address = IPv4Address(value)
        except ValueError:
            continue
        if not (
            address.is_unspecified
            or address.is_link_local
            or address.is_loopback
            or address.is_multicast
            or address.is_reserved
        ):
            addresses.add(str(address))
    return tuple(sorted(addresses))


@dataclass(frozen=True)
class NetworkAdapter:
    index: int
    name: str
    guid: str
    connected: bool
    hardware: bool = True
    ssid: str | None = None
    ipv4: tuple[str, ...] = ()
    ipv6: tuple[str, ...] = ()
    gateways: tuple[str, ...] = ()
    dns: tuple[str, ...] = ()
    link_type: LinkType = LinkType.UNKNOWN

    @property
    def link(self) -> LinkType:
        return LinkType.WIFI if self.ssid is not None else self.link_type

    @property
    def wired_gateways(self) -> tuple[str, ...]:
        return usable_ipv4(self.gateways)

    @property
    def ethernet_ready(self) -> bool:
        return (
            self.connected
            and self.hardware
            and self.link == LinkType.ETHERNET
            and bool(usable_ipv4(self.ipv4) and self.wired_gateways)
        )


@dataclass(frozen=True)
class NetworkSnapshot:
    adapters: tuple[NetworkAdapter, ...] = ()
    warnings: tuple[str, ...] = ()

    @property
    def connected(self) -> bool:
        return any(a.connected and (a.ipv4 or a.ipv6) for a in self.adapters)

    @property
    def wifi(self) -> NetworkAdapter | None:
        matches = [a for a in self.adapters if a.connected and a.ssid is not None]
        return matches[0] if len(matches) == 1 else None

    @property
    def ssid(self) -> str | None:
        return self.wifi.ssid if self.wifi else None

    @property
    def ready_ethernet(self) -> tuple[NetworkAdapter, ...]:
        return tuple(adapter for adapter in self.adapters if adapter.ethernet_ready)

    @property
    def selected(self) -> NetworkAdapter | None:
        wired = self.ready_ethernet
        if wired:
            return wired[0] if len(wired) == 1 else None
        wifi = self.wifi
        return wifi if wifi is not None and wifi.hardware else None

    @property
    def selection(self) -> LinkType:
        selected = self.selected
        return selected.link if selected else LinkType.UNKNOWN

    def link_diagnostics(self) -> dict:
        return {
            "selected_link": self.selection.value,
            "ethernet_links_up": sum(
                a.connected and a.hardware and a.link == LinkType.ETHERNET for a in self.adapters
            ),
            "ethernet_ready_count": len(self.ready_ethernet),
            "wifi_link_up": any(
                a.connected and a.hardware and a.link == LinkType.WIFI for a in self.adapters
            ),
            "wifi_ssid_known": self.ssid is not None,
        }

    @property
    def fingerprint(self) -> tuple:
        """Compare live network context without serializing it into diagnostics."""
        return tuple(
            (
                a.index,
                a.guid,
                a.connected,
                a.hardware,
                a.link,
                a.ssid,
                a.ipv4,
                a.ipv6,
                a.gateways,
                a.dns,
            )
            for a in self.adapters
        ) + (self.warnings,)


@dataclass(frozen=True)
class NetworkProfile:
    profile_id: str
    display_name: str
    ssid: str
    enabled: bool = True
    auto_auth: bool = False
    adapter_id: str = "bjut"
    credential_ref: str = "shared"
    trusted_portal_hosts: tuple[str, ...] = ()
    last_verified_at: str | None = None
    portal_page_url: str = field(default="", repr=False)
    bjut_api_origin: str = field(default="", repr=False)
    allow_http_auth: bool = False
    allow_zero_mac: bool = False
    wired_interface: str = field(default="", repr=False)
    wired_gateways: tuple[str, ...] = field(default=(), repr=False)

    @property
    def is_wired(self) -> bool:
        return self.adapter_id == BJUT_WIRED_ADAPTER

    def matches_adapter(self, adapter: NetworkAdapter) -> bool:
        if self.is_wired:
            return (
                adapter.ethernet_ready
                and adapter.guid == self.wired_interface
                and adapter.wired_gateways == self.wired_gateways
            )
        return adapter.link == LinkType.WIFI and adapter.ssid == self.ssid


@dataclass(frozen=True)
class Credentials:
    username: str = field(repr=False)
    password: str = field(repr=False)


@dataclass(frozen=True)
class ProbeEndpoint:
    url: str
    expected_status: int
    expected_body: bytes


@dataclass(frozen=True)
class ProbeObservation:
    reachable: bool = False
    expected: bool = False
    portal_url: str | None = field(default=None, repr=False)
    code: ErrorCode = ErrorCode.NONE
    socket_ips: tuple[str, str] | None = field(default=None, repr=False)


@dataclass(frozen=True)
class ConnectivityResult:
    online: bool = False
    portal_url: str | None = field(default=None, repr=False)
    code: ErrorCode = ErrorCode.NONE
    observations: tuple[ProbeObservation, ...] = ()


@dataclass(frozen=True)
class AuthResult:
    state: AuthState
    code: ErrorCode
    message: str
    network: NetworkSnapshot = field(default_factory=NetworkSnapshot, repr=False)
    portal_url: str | None = field(default=None, repr=False)
    checked_at: str = field(default_factory=lambda: datetime.now(UTC).isoformat())
    history: tuple[AuthState, ...] = ()
    progress: AuthProgress = field(default_factory=AuthProgress)
