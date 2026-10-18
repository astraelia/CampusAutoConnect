"""Observed BJUT ePortal branch; explicit origins and preflight precede credentials."""

import logging
import secrets
import time
from collections.abc import Callable
from urllib.parse import urlsplit

import httpx

from campus_autoconnect.adapters.base import AdapterDetection, AdapterReply
from campus_autoconnect.adapters.eportal import (
    CONFIG_PATH,
    LOGIN_PATH,
    MAX_RESPONSE_BYTES,
    EPortalConfig,
    EPortalContext,
    configuration_params,
    login_account,
    new_callback,
    parse_jsonp,
    protocol_error,
    response_accepted,
)
from campus_autoconnect.core.errors import CampusError
from campus_autoconnect.core.models import (
    AuthState,
    ConnectivityResult,
    Credentials,
    ErrorCode,
    NetworkProfile,
    NetworkSnapshot,
)
from campus_autoconnect.core.observation import observe
from campus_autoconnect.core.portal import normalize_bjut_endpoints, validate_target
from campus_autoconnect.services.connectivity import make_client, request_error_code


class _NoHttpDetails(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        # ePortal uses GET credentials. Even HTTPX's ordinary INFO URL is private.
        return False


_NO_HTTP_DETAILS = _NoHttpDetails()


def _protect_http_logs() -> None:
    # Client construction imports its transport and loggers before this is installed.
    # Publish the app's fixed state/error events, never library wire logs.
    for name in ("httpx", *tuple(logging.Logger.manager.loggerDict)):
        if name == "httpx" or name == "httpcore" or name.startswith("httpcore."):
            logger = logging.getLogger(name)
            if _NO_HTTP_DETAILS not in logger.filters:
                logger.addFilter(_NO_HTTP_DETAILS)


class BJUTPortalAdapter:
    def __init__(self, client_factory: Callable[[], httpx.Client] = make_client) -> None:
        self._status = AuthState.UNKNOWN
        self._make_client = client_factory
        self._ready = False
        self._login_request_attempted = False
        self.zero_mac_observed: bool | None = None
        self.zero_vlan_observed: bool | None = None
        self._profile: NetworkProfile | None = None
        self._context: EPortalContext | None = None
        self._config: EPortalConfig | None = None
        self._guard: Callable[[str], None] | None = None
        self._cookies = httpx.Cookies()

    @property
    def login_request_attempted(self) -> bool:
        return self._login_request_attempted

    def detect(self, profile: NetworkProfile, result: ConnectivityResult) -> AdapterDetection:
        if result.online:
            self._status = AuthState.AUTHENTICATED
            return AdapterDetection(False, ErrorCode.ALREADY_AUTHENTICATED, "互联网已可用。")
        if not result.portal_url:
            return AdapterDetection(False, ErrorCode.PORTAL_UNRECOGNIZED, "尚无明确认证入口。")
        validate_target(result.portal_url, profile)
        page, api = normalize_bjut_endpoints(profile.portal_page_url, profile.bjut_api_origin)
        if not page or not api:
            return AdapterDetection(
                False,
                ErrorCode.PROTOCOL_UNVERIFIED,
                "尚未配置实测认证页和认证服务地址；可在网络档案中从脱敏抓包填写。",
            )
        validate_target(page, profile)
        target = api + LOGIN_PATH
        validate_target(target, profile)
        observed = urlsplit(result.portal_url)
        expected = urlsplit(page)
        if (
            observed.scheme != expected.scheme
            or observed.hostname != expected.hostname
            or (observed.port or (80 if observed.scheme == "http" else 443))
            != (expected.port or (80 if expected.scheme == "http" else 443))
            or observed.path != expected.path
        ):
            return AdapterDetection(
                False, ErrorCode.UNTRUSTED_TARGET, "发现的认证页与档案中确认的入口不一致，已停止。"
            )
        self._status = AuthState.AUTH_REQUIRED
        return AdapterDetection(
            True, target_url=target, message="已配置受限 ePortal 分支；提交前需核对实时会话和配置。"
        )

    @staticmethod
    def _read(response: httpx.Response) -> bytes:
        if 300 <= response.status_code < 400:
            raise CampusError(ErrorCode.UNTRUSTED_TARGET, "认证入口返回重定向，已停止且未跟随。")
        if response.status_code >= 500:
            raise CampusError(ErrorCode.SERVER_ERROR, "认证服务暂时不可用。")
        if response.status_code != 200:
            raise CampusError(ErrorCode.MANUAL_ACTION, "认证服务拒绝请求，请在浏览器中核对。")
        if response.headers.get("content-encoding", "identity").lower() != "identity":
            raise protocol_error()
        body = bytearray()
        start = time.monotonic()
        for chunk in response.iter_bytes():
            if len(body) + len(chunk) > MAX_RESPONSE_BYTES:
                raise protocol_error()
            if time.monotonic() - start > 6:
                raise CampusError(ErrorCode.TIMEOUT, "认证服务读取超时。")
            body.extend(chunk)
        return bytes(body)

    def prepare(
        self, profile: NetworkProfile, network: NetworkSnapshot, guard: Callable[[str], None]
    ) -> None:
        """No credentials here. Retain only ephemeral page/configuration context."""
        self._ready = False
        self._login_request_attempted = False
        self.zero_mac_observed = self.zero_vlan_observed = None
        self._profile = self._context = self._config = self._guard = None
        self._cookies.clear()
        page, api = normalize_bjut_endpoints(profile.portal_page_url, profile.bjut_api_origin)
        if not page or not api or network.wifi is None or not network.wifi.hardware:
            raise CampusError(ErrorCode.PROTOCOL_UNVERIFIED, "认证入口或校园 Wi-Fi 会话尚未确认。")
        validate_target(page, profile)
        config_url = api + CONFIG_PATH
        validate_target(config_url, profile)
        try:
            with self._make_client() as client:
                _protect_http_logs()
                guard(page)
                observe("http_start", role="page")
                with client.stream("GET", page) as response:
                    observe("http_response", role="page", http_status=response.status_code)
                    try:
                        context = EPortalContext.from_page(
                            self._read(response),
                            network.wifi.ipv4,
                            allow_zero_mac=profile.allow_zero_mac,
                        )
                    except CampusError as exc:
                        if exc.code == ErrorCode.ZERO_MAC_PERMISSION_REQUIRED:
                            self.zero_mac_observed = True
                        raise
                    self.zero_mac_observed = context.mac == "000000000000"
                    self.zero_vlan_observed = int(context.vlan) == 0
                guard(config_url)
                callback = new_callback()
                observe("http_start", role="config")
                with client.stream(
                    "GET", config_url, params=configuration_params(context, callback)
                ) as response:
                    observe("http_response", role="config", http_status=response.status_code)
                    payload = parse_jsonp(self._read(response), callback)
                config = EPortalConfig.from_response(payload)
                if payload["data"].get("domain_name", "") != "":
                    raise protocol_error()
                parts = urlsplit(api)
                if (parts.port or (80 if parts.scheme == "http" else 443)) != (
                    config.http_port if parts.scheme == "http" else config.https_port
                ):
                    raise CampusError(
                        ErrorCode.UNTRUSTED_TARGET, "实时认证端口与档案明确配置不一致，请重新核对。"
                    )
                if parts.scheme == "http" and config.https_mode != 0:
                    raise CampusError(
                        ErrorCode.PROTOCOL_CHANGED, "服务端传输配置已变化，请重新核对 HTTPS 入口。"
                    )
                self._cookies = httpx.Cookies(client.cookies)
                observe(
                    "protocol",
                    zero_mac_observed=self.zero_mac_observed,
                    zero_vlan_observed=self.zero_vlan_observed,
                    live_config_supported=True,
                    account_suffix_present=bool(config.account_suffix),
                )
        except httpx.RequestError as exc:
            observe("http_error", code=request_error_code(exc))
            raise CampusError(
                request_error_code(exc), "认证准备请求失败；未读取校园网账号密码。"
            ) from None
        self._profile, self._context, self._config, self._guard = profile, context, config, guard
        self._ready = True

    def authenticate(self, target_url: str, credentials: Credentials) -> AdapterReply:
        self._status = AuthState.AUTH_FAILED
        self._login_request_attempted = False
        profile, context, config, guard = (
            self._profile,
            self._context,
            self._config,
            self._guard,
        )
        if not self._ready or profile is None or context is None or config is None or guard is None:
            return AdapterReply(
                False, ErrorCode.PROTOCOL_UNVERIFIED, "未完成认证准备，已阻止发送凭据。"
            )
        self._ready = False
        submitted_successfully = False
        try:
            if target_url != profile.bjut_api_origin + LOGIN_PATH:
                raise CampusError(ErrorCode.UNTRUSTED_TARGET, "认证提交目标与准备阶段不一致。")
            validate_target(target_url, profile)
            if (
                not credentials.username
                or not credentials.password
                or len(credentials.username) > 256
                or len(credentials.password) > 1024
            ):
                raise CampusError(ErrorCode.CREDENTIAL_STORE, "凭据内容无效，请重新保存。")
            callback = new_callback()
            params = [
                ("callback", callback),
                ("login_method", "1"),
                ("user_account", login_account(credentials.username, config.account_suffix)),
                ("user_password", credentials.password),
                ("wlan_user_ip", context.ipv4),
                ("wlan_user_ipv6", ""),
                ("wlan_user_mac", context.mac),
                ("wlan_ac_ip", ""),
                ("wlan_ac_name", ""),
                ("jsVersion", "4.2.1"),
                ("terminal_type", "1"),
                ("lang", "zh-cn"),
                ("v", str(secrets.randbelow(10000) + 500)),
                ("lang", "zh"),
            ]
            observe("protocol", account_normalized=True)
            with self._make_client() as client:
                _protect_http_logs()
                client.cookies.update(self._cookies)
                guard(target_url)
                self._status = AuthState.AUTHENTICATING
                self._login_request_attempted = True
                observe("http_start", role="login")
                with client.stream("GET", target_url, params=params) as response:
                    observe("http_response", role="login", http_status=response.status_code)
                    accepted = response_accepted(parse_jsonp(self._read(response), callback))
                observe("protocol", role="login", accepted=accepted)
            if accepted:
                submitted_successfully = True
                return AdapterReply(True)
            return AdapterReply(
                False,
                ErrorCode.MANUAL_ACTION,
                "认证服务拒绝本次登录；请在浏览器中检查账号、验证码或设备限制，自动尝试已停止。",
            )
        except CampusError as exc:
            return AdapterReply(False, exc.code, exc.message)
        except httpx.RequestError as exc:
            observe("http_error", role="login", code=request_error_code(exc))
            return AdapterReply(
                False, request_error_code(exc), "认证请求未完成，不能确认登录成功。"
            )
        finally:
            if not submitted_successfully:
                self._status = AuthState.AUTH_FAILED
            self._profile = self._context = self._config = self._guard = None
            self._cookies.clear()

    def verify(self, result: ConnectivityResult) -> bool:
        self._status = AuthState.AUTHENTICATED if result.online else AuthState.UNKNOWN
        return result.online

    def get_status(self) -> AuthState:
        return self._status
