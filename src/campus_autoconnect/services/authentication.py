"""One manual operation; trust gates precede all credential reads and submissions."""

import threading
from collections.abc import Callable
from dataclasses import replace

from campus_autoconnect.adapters.base import PortalAdapter
from campus_autoconnect.adapters.bjut import BJUTPortalAdapter
from campus_autoconnect.core.errors import CampusError
from campus_autoconnect.core.models import (
    AuthProgress,
    AuthResult,
    AuthStage,
    AuthState,
    ErrorCode,
    NetworkProfile,
    NetworkSnapshot,
)
from campus_autoconnect.core.network import NetworkProvider
from campus_autoconnect.core.observation import OperationTrace, observe
from campus_autoconnect.core.portal import profile_setup_issues, validate_target
from campus_autoconnect.core.profiles import ProfileService
from campus_autoconnect.core.state_machine import StateMachine
from campus_autoconnect.infrastructure.locking import FileMutex
from campus_autoconnect.security.credentials import CredentialStore
from campus_autoconnect.services.connectivity import ConnectivityService


class AuthenticationService:
    def __init__(
        self,
        network: NetworkProvider,
        profiles: ProfileService,
        credentials: CredentialStore,
        connectivity: ConnectivityService,
        adapters: dict[str, Callable[[], PortalAdapter]] | None = None,
        operation_lock: FileMutex | None = None,
        trace: OperationTrace | None = None,
    ) -> None:
        self.network = network
        self.profiles = profiles
        self.credentials = credentials
        self.connectivity = connectivity
        self.adapters = adapters if adapters is not None else {"bjut": BJUTPortalAdapter}
        self._lock = threading.Lock()
        self._operation_lock = operation_lock
        self.trace = trace if trace is not None else OperationTrace()

    def prepare_check(self, cancel: threading.Event | None = None) -> AuthResult:
        """Explicit credential-free deep check using the production guards and parser."""
        return self._run(True, cancel, prepare_only=True)

    def check(self, cancel: threading.Event | None = None) -> AuthResult:
        return self._run(False, cancel)

    def login(
        self,
        cancel: threading.Event | None = None,
        *,
        authorize: Callable[[NetworkSnapshot, NetworkProfile], bool] | None = None,
    ) -> AuthResult:
        return self._run(True, cancel, authorize)

    def _run(
        self,
        login: bool,
        cancel: threading.Event | None,
        authorize: Callable[[NetworkSnapshot, NetworkProfile], bool] | None = None,
        *,
        prepare_only: bool = False,
    ) -> AuthResult:
        if not self._lock.acquire(blocking=False):
            return AuthResult(AuthState.UNKNOWN, ErrorCode.BUSY, "已有检测或认证正在运行。")
        machine = StateMachine()
        trace_token = self.trace.begin(
            "preparation" if prepare_only else "login" if login else "check"
        )
        network = NetworkSnapshot()
        portal: str | None = None
        profile: NetworkProfile | None = None
        stage = AuthStage.NOT_STARTED
        credential_read_attempted = False
        authentication_called = False
        adapter: PortalAdapter | None = None
        process_locked = False

        def mark(value: AuthStage) -> AuthStage:
            observe("stage", stage=value)
            return value

        def session_fact(name: str) -> bool | None:
            value = getattr(adapter, name, None)
            return value if type(value) is bool else None

        def finish(state: AuthState, code: ErrorCode, message: str) -> AuthResult:
            machine.transition(state)
            observe("result", stage=stage, state=state, code=code)
            attempted = getattr(adapter, "login_request_attempted", None)
            progress = AuthProgress(
                stage=AuthStage.COMPLETED if state == AuthState.AUTHENTICATED else stage,
                profile_matched=profile is not None,
                portal_page_configured=bool(profile and profile.portal_page_url),
                api_origin_configured=bool(profile and profile.bjut_api_origin),
                http_auth_allowed=bool(profile and profile.allow_http_auth),
                zero_mac_allowed=bool(profile and profile.allow_zero_mac),
                zero_mac_observed=session_fact("zero_mac_observed"),
                zero_vlan_observed=session_fact("zero_vlan_observed"),
                profile_issues=profile_setup_issues(profile, portal) if profile else (),
                credential_read_attempted=credential_read_attempted,
                # An adapter call can still stop before the HTTP request. Unknown adapters
                # must report unknown, rather than inventing evidence of a submission.
                login_request_attempted=(attempted if type(attempted) is bool else None)
                if authentication_called
                else False,
            )
            return AuthResult(
                state,
                code,
                message,
                network,
                portal,
                history=tuple(machine.history),
                progress=progress,
            )

        def interrupted() -> AuthResult | None:
            if cancel is not None and cancel.is_set():
                return finish(
                    AuthState.UNKNOWN, ErrorCode.CANCELLED, "操作已取消，没有后续认证请求。"
                )
            return None

        try:
            if self._operation_lock is not None:
                process_locked = self._operation_lock.acquire()
                if not process_locked:
                    return finish(AuthState.UNKNOWN, ErrorCode.BUSY, "另一个进程正在检测或认证。")
            if result := interrupted():
                return result
            stage = mark(AuthStage.NETWORK)
            network = self.network.snapshot()
            observe(
                "protocol",
                adapter_count=len(network.adapters),
                active_virtual_gateway=any(
                    a.connected and not a.hardware and a.gateways for a in network.adapters
                ),
            )
            if not network.connected:
                return finish(
                    AuthState.DISCONNECTED, ErrorCode.NETWORK_UNREACHABLE, "当前没有可用网络连接。"
                )
            machine.transition(AuthState.NETWORK_CONNECTED)
            machine.transition(AuthState.CHECKING)
            stage = mark(AuthStage.CONNECTIVITY)
            connection = self.connectivity.check(cancel)
            portal = connection.portal_url
            if result := interrupted():
                return result
            if self.network.snapshot().fingerprint != network.fingerprint:
                return finish(
                    AuthState.UNKNOWN,
                    ErrorCode.NETWORK_CHANGED,
                    "探测期间网络变化，请等待网络稳定后重新检测。",
                )
            if result := interrupted():
                return result
            if connection.online:
                return finish(
                    AuthState.AUTHENTICATED,
                    ErrorCode.ALREADY_AUTHENTICATED,
                    "两个独立探测点验证互联网可用，未重复登录。",
                )
            if connection.code == ErrorCode.TLS_ERROR:
                return finish(
                    AuthState.UNKNOWN,
                    ErrorCode.TLS_ERROR,
                    "HTTPS 证书验证失败，已停止认证；请检查网络和证书。",
                )
            stage = mark(AuthStage.PROFILE)
            profile = self.profiles.match(network.ssid)
            if profile is None:
                return finish(
                    AuthState.UNKNOWN,
                    ErrorCode.UNTRUSTED_NETWORK,
                    "当前 SSID 未唯一匹配启用的可信档案；未读取凭据、未发送认证。",
                )
            if login and authorize is not None and not authorize(network, profile):
                return finish(
                    AuthState.UNKNOWN, ErrorCode.AUTOMATION_DISABLED, "自动认证授权已失效。"
                )
            if not portal:
                # Explicitly configured endpoint is usable when external DNS/probes are blocked.
                # A discovered untrusted redirect is never replaced with this fallback.
                portal = profile.portal_page_url or None
            if not portal:
                code = connection.code
                messages = {
                    ErrorCode.TIMEOUT: "连通性探测超时。",
                    ErrorCode.DNS_ERROR: "域名解析失败。",
                    ErrorCode.TLS_ERROR: "HTTPS 证书验证失败，禁止继续认证。",
                    ErrorCode.SERVER_ERROR: "探测服务器异常。",
                    ErrorCode.NETWORK_UNREACHABLE: "网络不可达。",
                }
                return finish(
                    AuthState.UNKNOWN, code, messages.get(code, "未识别到 Portal 或联网证据不足。")
                )
            stage = mark(AuthStage.TARGET)
            validate_target(portal, profile)
            machine.transition(AuthState.AUTH_REQUIRED)
            if not login:
                return finish(
                    AuthState.AUTH_REQUIRED,
                    ErrorCode.NONE,
                    "联网未通过，已有档案允许的认证入口；手动认证前将核对实时会话和协议。",
                )
            factory = self.adapters.get(profile.adapter_id)
            if factory is None:
                return finish(
                    AuthState.AUTH_FAILED, ErrorCode.PORTAL_UNRECOGNIZED, "档案适配器不可用。"
                )
            adapter = factory()
            detection = adapter.detect(profile, replace(connection, portal_url=portal))
            if not detection.recognized or not detection.target_url:
                # Adapter messages are fixed internal strings, not remote server messages.
                return finish(AuthState.AUTH_FAILED, detection.code, detection.message)
            validate_target(detection.target_url, profile)
            stage = mark(AuthStage.ROUTE)
            if not self.network.route_allows(detection.target_url, network):
                return finish(
                    AuthState.AUTH_FAILED,
                    ErrorCode.ROUTE_UNCONFIRMED,
                    "无法确认认证流量经当前校园 Wi-Fi 发出，请检查 VPN/TUN 和路由。",
                )

            def guard(target_url: str) -> None:
                validate_target(target_url, profile)
                if cancel is not None and cancel.is_set():
                    raise CampusError(ErrorCode.CANCELLED, "认证已取消，没有后续请求。")
                if not self.network.route_allows(target_url, network):
                    raise CampusError(
                        ErrorCode.ROUTE_UNCONFIRMED, "无法确认校园 Wi-Fi 路由，已停止认证请求。"
                    )
                current_network = self.network.snapshot()
                if (
                    current_network.fingerprint != network.fingerprint
                    or self.profiles.match(current_network.ssid) != profile
                ):
                    raise CampusError(ErrorCode.NETWORK_CHANGED, "网络或档案变化，已停止认证请求。")
                if authorize is not None and not authorize(current_network, profile):
                    raise CampusError(ErrorCode.AUTOMATION_DISABLED, "自动认证授权已撤回。")
                if cancel is not None and cancel.is_set():
                    raise CampusError(ErrorCode.CANCELLED, "认证已取消，没有后续请求。")

            # Preparation contains no credentials. Validate live page/configuration first.
            stage = mark(AuthStage.PREPARE)
            adapter.prepare(profile, network, guard)
            if result := interrupted():
                return result
            current = self.network.snapshot()
            current_profile = self.profiles.match(current.ssid)
            if current.fingerprint != network.fingerprint or current_profile != profile:
                return finish(
                    AuthState.AUTH_FAILED,
                    ErrorCode.NETWORK_CHANGED,
                    "网络或档案在操作中变化，已中止旧认证。",
                )
            if authorize is not None and not authorize(current, profile):
                return finish(
                    AuthState.AUTH_FAILED,
                    ErrorCode.AUTOMATION_DISABLED,
                    "自动认证授权已撤回，未读取凭据。",
                )
            if prepare_only:
                return finish(
                    AuthState.AUTH_REQUIRED,
                    ErrorCode.NONE,
                    "无凭据深入诊断已完成：实时会话和协议符合现有分支；未读取凭据、未登录。",
                )
            stage = mark(AuthStage.CREDENTIALS)
            credential_read_attempted = True
            credentials = self.credentials.get(profile.credential_ref)
            if credentials is None:
                return finish(
                    AuthState.AUTH_FAILED,
                    ErrorCode.CREDENTIALS_MISSING,
                    "请先保存该档案对应的凭据。",
                )
            if result := interrupted():
                return result
            # Recheck after reading credentials; do not transmit if the network changed meanwhile.
            before_submit = self.network.snapshot()
            if (
                before_submit.fingerprint != network.fingerprint
                or self.profiles.match(before_submit.ssid) != profile
            ):
                return finish(
                    AuthState.AUTH_FAILED, ErrorCode.NETWORK_CHANGED, "网络变化，已阻止凭据提交。"
                )
            if result := interrupted():
                return result
            if not self.network.route_allows(detection.target_url, before_submit):
                return finish(
                    AuthState.AUTH_FAILED,
                    ErrorCode.ROUTE_UNCONFIRMED,
                    "提交前路由复核未通过，已中止认证。",
                )
            if result := interrupted():
                return result
            if authorize is not None and not authorize(before_submit, profile):
                return finish(
                    AuthState.AUTH_FAILED,
                    ErrorCode.AUTOMATION_DISABLED,
                    "自动认证授权已撤回，已阻止凭据提交。",
                )
            if result := interrupted():
                return result
            machine.transition(AuthState.AUTHENTICATING)
            stage = mark(AuthStage.SUBMIT)
            authentication_called = True
            reply = adapter.authenticate(detection.target_url, credentials)
            del credentials
            if not reply.accepted:
                return finish(AuthState.AUTH_FAILED, reply.code, reply.message)
            if result := interrupted():
                return result
            stage = mark(AuthStage.VERIFY)
            verified = self.connectivity.check(cancel)
            if result := interrupted():
                return result
            if self.network.snapshot().fingerprint != network.fingerprint:
                return finish(
                    AuthState.UNKNOWN, ErrorCode.NETWORK_CHANGED, "验证期间网络变化，结果无法确认。"
                )
            if verified.online and adapter.verify(verified):
                return finish(
                    AuthState.AUTHENTICATED,
                    ErrorCode.NONE,
                    "认证响应已接受，独立互联网探测验证通过。",
                )
            return finish(
                AuthState.UNKNOWN,
                ErrorCode.UNKNOWN,
                "服务器接受请求，但互联网验证未通过，不能确认认证成功。",
            )
        except CampusError as exc:
            target = (
                AuthState.AUTH_FAILED
                if machine.state in {AuthState.AUTH_REQUIRED, AuthState.AUTHENTICATING}
                else AuthState.UNKNOWN
            )
            return finish(target, exc.code, exc.message)
        except Exception:
            # No raw exception text or traceback; may include network identifiers or credentials.
            return finish(
                AuthState.UNKNOWN,
                ErrorCode.UNKNOWN,
                "操作发生未预期错误，请查看脱敏诊断及测试文档。",
            )
        finally:
            if process_locked and self._operation_lock is not None:
                self._operation_lock.release()
            self._lock.release()
            self.trace.end(trace_token)
