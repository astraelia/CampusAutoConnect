"""Credential-free, dependency-injected rechecks. No GUI or authentication calls."""

import json
import re
import socket
import ssl
import threading
import time
from collections.abc import Callable
from pathlib import Path
from urllib.parse import urlsplit

import certifi
import httpx

from campus_autoconnect import __version__ as reference_version
from campus_autoconnect.adapters.bjut import BJUTPortalAdapter
from campus_autoconnect.core.errors import CampusError
from campus_autoconnect.core.models import (
    ErrorCode,
    NetworkProfile,
    NetworkSnapshot,
    ProbeEndpoint,
    ProbeObservation,
)
from campus_autoconnect.core.network import NetworkProvider, WindowsNetworkProvider
from campus_autoconnect.core.portal import normalize_authority, validate_target
from campus_autoconnect.infrastructure.config import ConfigStore
from campus_autoconnect.infrastructure.startup import WindowsStartupService
from campus_autoconnect.security.credentials import WindowsCredentialStore
from campus_autoconnect.services.connectivity import ConnectivityService, make_client
from campus_autoconnect.services.inspection_records import Fact, Outcome, Step, exception_type
from campus_autoconnect.services.monitor import MonitorControl


def read_json(path: Path, limit: int) -> object:
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate field")
            result[key] = value
        return result

    with path.open("rb") as stream:
        data = stream.read(limit + 1)
    if len(data) > limit:
        raise ValueError("input too large")
    return json.loads(
        data.decode("utf-8-sig"),
        object_pairs_hook=unique,
        parse_constant=lambda _: (_ for _ in ()).throw(ValueError("nonfinite value")),
    )


def trust_reason(url: str, profile: NetworkProfile) -> str:
    """Delegate acceptance to the original validator; refine only the failure reason."""
    try:
        validate_target(url, profile)
        return "trusted_http" if urlsplit(url).scheme == "http" else "trusted_https"
    except (CampusError, ValueError, TypeError):
        try:
            parts = urlsplit(url)
            if parts.scheme == "http":
                return "http_target_not_allowed" if profile.allow_http_auth else "http_disallowed"
            if parts.scheme != "https":
                return "scheme_disallowed"
            authority = normalize_authority(parts.netloc)
            allowed = {normalize_authority(host) for host in profile.trusted_portal_hosts}
            host = urlsplit("https://" + authority).hostname
            if authority not in allowed and any(
                urlsplit("https://" + item).hostname == host for item in allowed
            ):
                return "port_not_allowed"
            if authority not in allowed:
                return "host_not_allowed"
        except (ValueError, TypeError, UnicodeError):
            pass
        return "invalid_target"


TRUST_MESSAGES = {
    "http_disallowed": "发现 HTTP 认证线索；本档案未明确允许 HTTP 兼容，已停止。",
    "http_target_not_allowed": "HTTP 目标不在本档案明确配置的入口和路径范围内。",
    "trusted_http": "HTTP 目标符合本档案的明确许可；该传输不提供 TLS 加密。",
    "scheme_disallowed": "认证线索没有使用允许的 HTTPS 协议。",
    "port_not_allowed": "HTTPS 主机名匹配，但端口未获档案授权。",
    "host_not_allowed": "HTTPS 主机未列入当前档案的精确信任范围。",
    "invalid_target": "目标含不允许的地址格式、用户信息或片段，安全校验未通过。",
    "trusted_https": "发现的 HTTPS 目标通过原程序的精确主机及端口校验。",
}
KNOWN_WARNINGS = {
    "windows_required",
    "wlan_unavailable",
    "wlan_invalid_response",
    "ssid_permission_denied",
    "ssid_unavailable",
    "ssid_encoding_unsupported",
}


class ObservedConnectivity(ConnectivityService):
    def __init__(
        self,
        emit: Callable[[Step], None],
        run: int,
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        self.emit = emit
        self.run = run
        self.statuses: dict[str, int] = {}

        def client():
            instance = make_client(transport=transport)
            instance.event_hooks["response"].append(
                lambda response: self.statuses.__setitem__(
                    str(response.request.url), response.status_code
                )
            )
            return instance

        super().__init__(client_factory=client)

    def _probe(
        self, client: httpx.Client, endpoint: ProbeEndpoint, cancel: threading.Event | None
    ) -> ProbeObservation:
        start = time.monotonic()
        result = super()._probe(client, endpoint, cancel)
        number = self.endpoints.index(endpoint) + 1
        self.emit(
            Step(
                f"probe_{number}",
                f"联网探测点 {number}",
                Outcome.PASS if result.expected else Outcome.WARNING,
                result.code.value
                if result.code != ErrorCode.NONE
                else ("expected_response" if result.expected else "portal_redirect"),
                "状态及正文均符合预期。"
                if result.expected
                else "此探测未满足联网条件；跳转仅作为线索，未跟随跳转。",
                facts={
                    "https": urlsplit(endpoint.url).scheme == "https",
                    "http_status": self.statuses.get(endpoint.url),
                    "expected": result.expected,
                    "redirect_observed": bool(result.portal_url),
                },
                elapsed_ms=round((time.monotonic() - start) * 1000),
                run=self.run,
            )
        )
        return result


def verify_tls(url: str) -> tuple[bool, str, dict]:
    parts = urlsplit(url)
    try:
        # Match HTTPX verify=True/trust_env=False, rather than inheriting SSL_CERT_FILE.
        context = ssl.create_default_context(cafile=certifi.where())
        with (
            socket.create_connection((parts.hostname, parts.port or 443), timeout=4) as connection,
            context.wrap_socket(connection, server_hostname=parts.hostname),
        ):
            return True, "tls_verified", {"certificate_validation": True}
    except ssl.SSLCertVerificationError as exc:
        code = "tls_identity_mismatch" if exc.verify_code in (62, 64) else "tls_certificate_error"
        return False, code, {"verify_code": int(exc.verify_code)}
    except ssl.SSLError:
        return False, "tls_error", {}
    except socket.gaierror:
        return False, "dns_error", {}
    except TimeoutError:
        return False, "timeout", {}
    except OSError:
        return False, "network_unreachable", {}


class InspectionRunner:
    def __init__(
        self,
        directory: Path,
        emit: Callable[[Step], None],
        *,
        run: int = 1,
        network: NetworkProvider | None = None,
        transport: httpx.BaseTransport | None = None,
        tls: Callable = verify_tls,
        startup: Callable | None = None,
        backend: Callable | None = None,
    ) -> None:
        self.directory = directory
        self.emit = emit
        self.run = run
        self.network = network if network is not None else WindowsNetworkProvider()
        self.transport = transport
        self.tls = tls
        self.startup = startup if startup is not None else WindowsStartupService().status
        self.backend = backend if backend is not None else WindowsCredentialStore._backend

    def add(
        self,
        key: str,
        title: str,
        outcome: Outcome,
        code: str,
        detail: str,
        facts: dict[str, Fact] | None = None,
        elapsed_ms: int = 0,
    ) -> None:
        self.emit(
            Step(
                key,
                title,
                outcome,
                code,
                detail,
                facts=facts or {},
                elapsed_ms=elapsed_ms,
                run=self.run,
            )
        )

    def context(self) -> None:
        self.add(
            "reference",
            "检测规则来源",
            Outcome.INFO,
            "source_reference",
            "复用当前项目检测模块；本次结果为独立复查，不是 EXE 内部执行轨迹。",
            {"reference_version": reference_version},
        )
        try:
            backend = self.backend()
            valid = type(backend).__name__ == "WinVaultKeyring" and (
                type(backend).__module__ == "keyring.backends.Windows"
            )
            self.add(
                "vault",
                "安全存储后端",
                Outcome.PASS if valid else Outcome.WARNING,
                "vault_backend_available" if valid else "credential_store",
                "仅检查 WinVaultKeyring 后端类型，不查询或读取任何凭据。",
                {"winvault_backend": valid},
            )
        except Exception:
            self.add(
                "vault",
                "安全存储后端",
                Outcome.WARNING,
                "credential_store",
                "无法加载指定安全存储后端；未访问凭据内容。",
            )
        try:
            path = self.directory / "automation.json"
            raw = (
                read_json(path, 1024) if path.exists() else {"schema_version": 1, "enabled": False}
            )
            if (
                not isinstance(raw, dict)
                or set(raw) != {"schema_version", "enabled"}
                or type(raw["schema_version"]) is not int
                or raw["schema_version"] != 1
                or type(raw["enabled"]) is not bool
            ):
                raise ValueError
            enabled = raw["enabled"]
            self.add(
                "automation",
                "全局自动认证",
                Outcome.INFO,
                "automation_enabled" if enabled else "automation_disabled",
                "仅查询现有开关；关闭全局自动认证不妨碍手动检测。",
                {"enabled": enabled},
            )
        except (OSError, ValueError, TypeError, RecursionError):
            self.add(
                "automation",
                "全局自动认证",
                Outcome.WARNING,
                "config_error",
                "全局自动设置不可读；本工具没有修改配置。",
            )
        try:
            monitor = MonitorControl(self.directory).status()
            facts = {
                key: monitor[key] for key in ("running", "state", "error_code") if key in monitor
            }
            for key in ("attempts", "max_attempts", "operation_running", "event_fallback"):
                if key in monitor:
                    facts[key] = monitor[key]
            self.add(
                "background",
                "后台监视状态",
                Outcome.INFO,
                "monitor_status",
                "只查询当前后台状态；进程存在与自动认证启用是两个独立条件。",
                facts,
            )
        except Exception as exc:
            self.add(
                "background",
                "后台监视状态",
                Outcome.WARNING,
                "monitor_unavailable",
                "无法读取后台状态；不启动、停止或重启后台。",
                {"exception_type": exception_type(exc)},
            )
        try:
            status = self.startup()
            facts = {
                key: status[key]
                for key in ("configured", "owned", "installed", "enabled")
                if key in status and type(status[key]) is bool
            }
            self.add(
                "startup",
                "Windows 登录启动",
                Outcome.INFO,
                "startup_status",
                "仅查询现有任务状态，不注册、执行或删除任务。",
                facts,
            )
        except Exception:
            self.add(
                "startup",
                "Windows 登录启动",
                Outcome.WARNING,
                "startup_error",
                "无法查询登录任务；不影响下面的独立网络复查。",
            )

    def inspect(self, cancel: threading.Event) -> None:
        try:
            self._inspect(cancel)
        except Exception as exc:
            self.add(
                "inspection_error",
                "独立复查",
                Outcome.ERROR,
                "unexpected_error",
                "本轮复查发生未预期错误；未输出原始异常或网络内容。",
                {"exception_type": exception_type(exc)},
            )
        finally:
            self.add(
                "submission",
                "凭据及登录提交",
                Outcome.SKIPPED,
                "not_attempted",
                "本工具只执行无凭据检查，没有读取认证凭据或发送登录请求。",
                {"tool_credential_reads": 0, "tool_login_submissions": 0},
            )

    def _inspect(self, cancel: threading.Event) -> None:
        if cancel.is_set():
            return
        started = time.monotonic()
        try:
            snapshot = self.network.snapshot()
        except CampusError as exc:
            self.add(
                "network",
                "Windows 网络快照",
                Outcome.ERROR,
                exc.code.value,
                "无法取得 Windows 网络快照；后续网络检查未执行。",
            )
            self.skip("network_unavailable")
            return
        self.add(
            "network",
            "Windows 网络快照",
            Outcome.PASS if snapshot.connected else Outcome.BLOCKED,
            "network_connected" if snapshot.connected else "network_unreachable",
            "已取得网络快照；识别到 SSID 不等于验证校园网身份。"
            if snapshot.connected
            else "没有带可用地址的活动连接，后续联网检查未执行。",
            {
                "adapter_count": len(snapshot.adapters),
                "connected": snapshot.connected,
                "ssid_known": snapshot.ssid is not None,
                "active_virtual_gateway": any(
                    a.connected and not a.hardware and a.gateways for a in snapshot.adapters
                ),
                "warning_count": len(snapshot.warnings),
                **{w: True for w in snapshot.warnings if w in KNOWN_WARNINGS},
            },
            round((time.monotonic() - started) * 1000),
        )
        if not snapshot.connected or cancel.is_set():
            self.skip("cancelled" if cancel.is_set() else "network_unreachable")
            return
        profile = self.profile(snapshot)
        connection = ObservedConnectivity(self.emit, self.run, self.transport).check(cancel)
        if cancel.is_set():
            self.skip("cancelled")
            return
        current = self.network.snapshot()
        if current.fingerprint != snapshot.fingerprint:
            self.add(
                "network_stability",
                "检测期间网络稳定性",
                Outcome.BLOCKED,
                "network_changed",
                "网络在探测期间发生变化，本轮联网与 Portal 结论作废。",
            )
            self.skip("network_changed")
            return
        if connection.online:
            self.add(
                "internet",
                "互联网状态",
                Outcome.PASS,
                "already_authenticated",
                "两个独立探测均满足预期，当前互联网可用；无需本工具发起登录。",
            )
            self.skip("already_online")
            self.add(
                "capability",
                "真实 BJUT 登录能力",
                Outcome.WARNING,
                "login_not_attempted",
                "本轮未执行登录；互联网可用不证明由本应用完成认证。",
            )
            return
        self.add(
            "internet",
            "互联网状态",
            Outcome.WARNING,
            connection.code.value,
            "未满足两个独立探测的联网条件，继续检查 Portal 线索。",
            {"portal_discovered": connection.portal_url is not None},
        )
        if connection.code == ErrorCode.TLS_ERROR:
            self.add(
                "probe_tls",
                "探测 TLS 安全门槛",
                Outcome.BLOCKED,
                "tls_error",
                "联网探测出现 TLS 校验错误；按原程序规则停止后续认证准备检查。",
            )
            self.skip("tls_error")
            return
        if profile is None:
            self.add(
                "profile_gate",
                "认证档案门槛",
                Outcome.BLOCKED,
                "untrusted_network",
                "当前没有可授予认证信任的精确启用档案，不能继续认证准备。",
            )
            self.skip("profile_not_matched")
            return
        portal = connection.portal_url or profile.portal_page_url
        if not portal:
            self.add(
                "portal",
                "Portal 发现",
                Outcome.BLOCKED,
                "portal_unrecognized",
                "未发现可检查的 Portal 跳转，不能确认是待认证、探测被屏蔽还是网络故障。",
            )
            self.skip("no_portal")
            return
        reason = trust_reason(portal, profile)
        self.add(
            "trust",
            "Portal 目标安全检查",
            Outcome.PASS if reason in {"trusted_https", "trusted_http"} else Outcome.BLOCKED,
            reason,
            TRUST_MESSAGES[reason],
            {
                "https": urlsplit(portal).scheme == "https",
                "trusted_host_count": len(profile.trusted_portal_hosts),
            },
        )
        if reason not in {"trusted_https", "trusted_http"}:
            self.skip(reason)
            return
        # These are independent readiness checks. The production adapter currently blocks
        # before route/TLS transport, so they must not be presented as its execution trace.
        from dataclasses import replace

        detection = BJUTPortalAdapter().detect(profile, replace(connection, portal_url=portal))
        self.add(
            "capability",
            "真实 BJUT 登录能力",
            Outcome.INFO if detection.recognized else Outcome.BLOCKED,
            "adapter_configured" if detection.recognized else detection.code.value,
            "已配置受限适配器；本工具不读取凭据、不执行认证准备或登录，下面仅独立复查路由。"
            if detection.recognized
            else "生产适配器尚未配置；下面仅独立检查路由和 TLS 准备条件。",
            {"adapter_recognized": detection.recognized},
        )
        if cancel.is_set():
            self.skip("cancelled", keys=("route", "tls"))
            return
        targets = (portal, detection.target_url) if detection.target_url else (portal,)
        route = all(self.network.route_allows(target, snapshot) for target in targets)
        self.add(
            "route",
            "目标路由独立复查",
            Outcome.PASS if route else Outcome.BLOCKED,
            "route_confirmed" if route else "route_unconfirmed",
            "路由复查通过；这不是生产认证流程已走到此处的证据。"
            if route
            else "无法确认目标走当前 Wi-Fi，或存在虚拟网关/查询警告；不连接认证目标。",
        )
        if not route or cancel.is_set():
            self.skip("cancelled" if cancel.is_set() else "route_unconfirmed", keys=("tls",))
            return
        if urlsplit(portal).scheme == "http":
            self.add(
                "tls",
                "目标传输方式",
                Outcome.INFO,
                "explicit_http_compatibility",
                "本档案明确允许 HTTP；该流量不受 TLS 加密，本工具没有发送登录。",
            )
            return
        if self.network.snapshot().fingerprint != snapshot.fingerprint:
            self.add(
                "tls",
                "目标 TLS 独立复查",
                Outcome.SKIPPED,
                "network_changed",
                "TLS 握手前网络变化，未连接认证目标。",
            )
            return
        started = time.monotonic()
        ok, code, facts = self.tls(portal)
        self.add(
            "tls",
            "目标 TLS 独立复查",
            Outcome.PASS if ok else Outcome.BLOCKED,
            code,
            "仅 TLS 握手与证书身份校验通过，未发送 HTTP 或登录请求。"
            if ok
            else "目标 TLS/DNS/连接检查未通过；没有关闭证书验证。",
            facts,
            round((time.monotonic() - started) * 1000),
        )

    def profile(self, snapshot: NetworkSnapshot) -> NetworkProfile | None:
        try:
            path = self.directory / "config.json"
            # Read directly: never repair, recover or write the user's configuration.
            profiles = ConfigStore.decode(json.dumps(read_json(path, ConfigStore.MAX_BYTES)))
        except FileNotFoundError:
            profiles = []
        except (OSError, ValueError, TypeError, KeyError, RecursionError):
            self.add(
                "profile",
                "精确网络档案",
                Outcome.WARNING,
                "config_error",
                "档案主文件损坏或不可读；未使用备份授予信任，也未修改原件。",
            )
            return None
        matches = [p for p in profiles if p.enabled and p.ssid == snapshot.ssid]
        profile = matches[0] if snapshot.ssid is not None and len(matches) == 1 else None
        self.add(
            "profile",
            "精确网络档案",
            Outcome.INFO if profile else Outcome.WARNING,
            "profile_matched" if profile else "untrusted_network",
            "当前 SSID 精确匹配唯一启用档案；匹配本身不证明网络身份。"
            if profile
            else "SSID 未唯一匹配启用档案；仅允许下面的无凭据联网探测。",
            {
                "profile_count": len(profiles),
                "enabled_match_count": len(matches),
                "profile_auto_auth": profile.auto_auth if profile else None,
                "zero_mac_allowed": profile.allow_zero_mac if profile else None,
            },
        )
        return profile

    def skip(self, reason: str, keys=("trust", "capability", "route", "tls")) -> None:
        titles = {
            "trust": "Portal 目标安全检查",
            "capability": "协议认证准备",
            "route": "目标路由独立复查",
            "tls": "目标 TLS 独立复查",
        }
        for key in keys:
            self.add(
                key,
                titles[key],
                Outcome.SKIPPED,
                reason,
                "本项因前置条件未满足或当前无需登录而未执行；未执行不等于通过。",
            )


def safe_version(value: object) -> str | None:
    if isinstance(value, str) and re.fullmatch(
        r"\d{1,3}\.\d{1,3}\.\d{1,3}(?:\.dev\d{1,4})?", value
    ):
        return value
    return None
