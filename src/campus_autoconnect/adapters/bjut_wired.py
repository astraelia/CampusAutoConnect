"""BJUT's HTTPS Dr.COM branch, based on the gateway's a41/a43/a44 scripts."""

import base64
import re
import secrets
from collections.abc import Callable
from dataclasses import dataclass, field
from html.parser import HTMLParser

import httpx

from campus_autoconnect.adapters.base import AdapterDetection, AdapterReply
from campus_autoconnect.adapters.bjut import protect_http_logs, read_portal_response
from campus_autoconnect.adapters.eportal import (
    login_account,
    new_callback,
    parse_jsonp,
    protocol_error,
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
from campus_autoconnect.core.portal import (
    BJUT_WIRED_API,
    BJUT_WIRED_CONFIG,
    BJUT_WIRED_HOST,
    BJUT_WIRED_LOGIN,
    BJUT_WIRED_PAGE,
    BJUT_WIRED_STATUS,
    bjut_wired_portal_supported,
    validate_target,
)
from campus_autoconnect.services.connectivity import make_client, request_error_code

_Guard = Callable[[str], None]
_Params = list[tuple[str, str]]
_PAGE_INDEX = re.compile(r"[A-Za-z0-9_-]{1,48}\Z")
_JS_STRING = r"""(?:"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*')"""
_FORM_FIELDS = {"R1": "", "R3": "", "R6": "0", "para": ""}


def _literal(source: str, name: str, pattern: str) -> str | None:
    matches = re.findall(r"\b" + name + r"\s*=\s*(['\"]?)(" + pattern + r")\1\s*;", source)
    return matches[0][1] if len(matches) == 1 else None


def _jsonp(body: bytes, callback: str) -> dict:
    # The portal serves GBK HTML and may return a legacy-encoded JSONP message.
    try:
        body.decode("utf-8-sig")
    except UnicodeDecodeError:
        try:
            body = body.decode("gb18030").encode("utf-8")
        except UnicodeError:
            raise protocol_error() from None
    return parse_jsonp(body, callback)


def _jsonp_params(callback: str, version: str, program: str = "", page: str = "") -> _Params:
    return [
        ("callback", callback),
        ("program_index", program),
        ("page_index", page),
        ("jsVersion", version),
    ]


def _cache_buster() -> _Params:
    return [("v", str(secrets.randbelow(10000) + 500)), ("lang", "zh")]


def _configuration_params(ipv4: str, vlan: str, callback: str) -> _Params:
    fields = _jsonp_params(callback, "4.X") + [
        ("wlan_vlan_id", vlan),
        ("wlan_user_ip", base64.b64encode(ipv4.encode("ascii")).decode("ascii")),
        ("wlan_user_ipv6", ""),
        ("wlan_user_ssid", ""),
        ("wlan_user_areaid", ""),
        ("wlan_ac_ip", ""),
        ("wlan_ap_mac", "000000000000"),
        ("gw_id", "000000000000"),
    ]
    # a41.js uses XOR/hex with a public firmware constant for loadConfig.
    # This is a wire encoding. TLS protects the query.
    key = ord("t") ^ ord("e") ^ ord("s") ^ ord("t")
    encoded = [
        (name, "".join(f"{ord(char) ^ key:02x}" for char in value)) for name, value in fields
    ]
    return encoded + [("encrypt", "1")] + _cache_buster()


def _config(payload: dict) -> tuple[str, str, str]:
    data = payload.get("data")
    if not isinstance(data, dict):
        raise protocol_error()
    mode = data.get("login_method")
    if type(mode) not in (int, str) or mode not in (0, "0"):
        raise protocol_error()
    for key in (
        "account_prefix",
        "en_md5",
        "password_cut",
        "enable_r3",
        "enable_alias",
        "io_mode",
        "ipv6_state",
        "en_perceive",
        "enable_hotelop_login",
        "check_online_method",
    ):
        value = data.get(key, 0)
        if type(value) not in (int, str) or value not in (0, "0", ""):
            raise protocol_error()
    if data.get("needCaptcha", 0) not in (0, "0", ""):
        raise CampusError(ErrorCode.MANUAL_ACTION, "有线网关要求验证码，请在浏览器中登录。")
    if data.get("domain_name", "") not in ("", BJUT_WIRED_HOST):
        raise protocol_error()
    program, page = data.get("program_index"), data.get("page_index")
    suffix = data.get("account_suffix", "")
    if (
        not isinstance(program, str)
        or not _PAGE_INDEX.fullmatch(program)
        or not isinstance(page, str)
        or not _PAGE_INDEX.fullmatch(page)
        or not isinstance(suffix, str)
        or not re.fullmatch(r"[@A-Za-z0-9._-]{0,64}", suffix)
    ):
        raise protocol_error()
    return program, page, suffix


class _LoginForm(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.current = ""
        self.forms: dict[str, dict[str, str]] = {}
        self.manual_required = False

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attributes = {key: value or "" for key, value in attrs}
        name = attributes.get("name", "")
        if tag == "form":
            if name and name in self.forms:
                raise protocol_error()
            self.current = name
            self.forms[name] = {}
        if name in {"checkIOMode", "ISP_select", "ISP_radio", "C1", "authorize"}:
            self.manual_required = True
        if name == "captcha":
            style = attributes.get("style", "").replace(" ", "").lower()
            self.manual_required |= "display:none" not in style.split(";")
        if tag == "input" and self.current and name:
            fields = self.forms[self.current]
            if self.current in {"f0", "f1"} and name in fields:
                raise protocol_error()
            fields[name] = (
                attributes.get("value", "")
                if self.current == "f0"
                else (attributes.get("type", "text").lower())
            )

    def handle_endtag(self, tag: str) -> None:
        if tag == "form":
            self.current = ""


def _unescape(match: re.Match) -> str:
    value = match[0][1:]
    if value[0] in ("u", "x") and len(value) > 1:
        return chr(int(value[1:], 16))
    return {"n": "\n", "r": "\r", "t": "\t"}.get(value, value)


def _template(body: bytes) -> tuple[str, tuple[tuple[str, str], ...]]:
    source = body.decode("gb18030", errors="strict")
    version = _literal(source, "jsVersion", r"[0-9.X]{1,12}")
    templates = re.findall(r"\bbodyContent\s*=\s*(" + _JS_STRING + r")\s*;", source)
    if version is None or len(templates) != 1:
        raise protocol_error()
    markup = re.sub(r"\\(?:u[0-9a-fA-F]{4}|x[0-9a-fA-F]{2}|.)", _unescape, templates[0][1:-1])
    forms = _LoginForm()
    forms.feed(markup)
    if forms.manual_required:
        raise CampusError(ErrorCode.MANUAL_ACTION, "有线门户要求人工选择或确认，请在浏览器中登录。")
    login = forms.forms.get("f1", {})
    defaults = forms.forms.get("f0")
    if defaults is None or login.get("DDDDD") != "text" or login.get("upass") != "password":
        raise protocol_error()
    fields = tuple((name, defaults.get(name, fallback)) for name, fallback in _FORM_FIELDS.items())
    if any(not re.fullmatch(r"[A-Za-z0-9.,_+=-]{0,64}", value) for _, value in fields):
        raise protocol_error()
    return version, fields


@dataclass(frozen=True)
class _Prepared:
    ipv4: str = field(repr=False)
    suffix: str = field(repr=False)
    metadata: tuple[tuple[str, str], ...] = field(repr=False)
    form_fields: tuple[tuple[str, str], ...] = field(repr=False)
    guard: _Guard = field(repr=False)
    cookies: httpx.Cookies = field(repr=False)


class BJUTWiredAdapter:
    def __init__(self, client_factory: Callable[[], httpx.Client] = make_client) -> None:
        self._make_client = client_factory
        self._prepared: _Prepared | None = None
        self._status = AuthState.UNKNOWN
        self.login_request_attempted = False

    def detect(self, profile: NetworkProfile, result: ConnectivityResult) -> AdapterDetection:
        if result.online:
            return AdapterDetection(False, ErrorCode.ALREADY_AUTHENTICATED, "互联网已可用。")
        if not profile.is_wired or result.portal_url != profile.portal_page_url:
            return AdapterDetection(False, ErrorCode.UNTRUSTED_TARGET, "未识别到配置的有线网关。")
        if not bjut_wired_portal_supported(profile.portal_page_url):
            return AdapterDetection(
                False, ErrorCode.PROTOCOL_UNVERIFIED, "该有线入口的协议待核对，可在浏览器手动登录。"
            )
        validate_target(BJUT_WIRED_LOGIN, profile)
        return AdapterDetection(True, target_url=BJUT_WIRED_LOGIN)

    def _get(
        self,
        client: httpx.Client,
        url: str,
        guard: _Guard,
        role: str,
        params: _Params | None = None,
    ) -> bytes:
        guard(url)
        if role == "login":
            self.login_request_attempted = True
        observe("http_start", role=role, https=True)
        try:
            with client.stream("GET", url, params=params, follow_redirects=False) as response:
                observe("http_response", role=role, http_status=response.status_code)
                return read_portal_response(response)
        except httpx.RequestError as exc:
            code = request_error_code(exc)
            observe("http_error", role=role, code=code)
            raise CampusError(code, "有线网关请求未完成，请检查网络和 TLS 状态。") from None

    def prepare(self, profile: NetworkProfile, network: NetworkSnapshot, guard: _Guard) -> None:
        self._prepared = None
        self._status = AuthState.UNKNOWN
        self.login_request_attempted = False
        adapter = network.selected
        if not profile.is_wired or adapter is None or not profile.matches_adapter(adapter):
            raise CampusError(ErrorCode.UNTRUSTED_NETWORK, "当前物理网卡或网关与有线档案不一致。")
        if not bjut_wired_portal_supported(profile.portal_page_url):
            raise CampusError(ErrorCode.PROTOCOL_UNVERIFIED, "该有线入口的自动认证协议待核对。")
        validate_target(BJUT_WIRED_PAGE, profile)
        try:
            with self._make_client() as client:
                protect_http_logs()
                page = self._get(client, BJUT_WIRED_PAGE, guard, "page").decode("gb18030")
                ipv4 = _literal(page, "v46ip", r"[0-9.]{7,15}")
                vlan = _literal(page, "vlanid", r"\d{1,4}")
                version = _literal(page, "fileVersion", r"\d{1,16}")
                if (
                    not version
                    or not vlan
                    or int(vlan) > 4094
                    or "<title>上网登录页</title>" not in page
                    or _literal(page, "authexenable", r"\d") != "0"
                ):
                    raise protocol_error()
                if ipv4 is None or ipv4 not in adapter.ipv4:
                    raise CampusError(
                        ErrorCode.SESSION_IP_MISMATCH, "有线登录页的 IPv4 与所选物理网卡不一致。"
                    )
                callback = new_callback()
                status = _jsonp(
                    self._get(
                        client,
                        BJUT_WIRED_STATUS,
                        guard,
                        "config",
                        _jsonp_params(callback, "4.X") + _cache_buster(),
                    ),
                    callback,
                ).get("result")
                if type(status) in (int, str) and status in (1, "1"):
                    raise CampusError(
                        ErrorCode.ALREADY_AUTHENTICATED, "有线网关已有在线会话，外网探测仍待核实。"
                    )
                if type(status) not in (int, str) or status not in (0, "0"):
                    raise protocol_error()
                callback = new_callback()
                params = _configuration_params(ipv4, vlan, callback)
                program, index, suffix = _config(
                    _jsonp(self._get(client, BJUT_WIRED_CONFIG, guard, "config", params), callback)
                )
                url = BJUT_WIRED_API + f"extern/{program}/{index}/pc.js"
                js_version, fields = _template(
                    self._get(client, url, guard, "config", [("v", "_" + version)])
                )
                metadata = _jsonp_params("", js_version, program, index)[1:]
                self._prepared = _Prepared(
                    ipv4, suffix, tuple(metadata), fields, guard, httpx.Cookies(client.cookies)
                )
        except UnicodeError:
            raise protocol_error() from None
        self._status = AuthState.AUTH_REQUIRED
        observe("protocol", live_config_supported=True, account_suffix_present=bool(suffix))

    def authenticate(self, target_url: str, credentials: Credentials) -> AdapterReply:
        prepared, self._prepared = self._prepared, None
        self._status = AuthState.AUTH_FAILED
        self.login_request_attempted = False
        if prepared is None:
            return AdapterReply(False, ErrorCode.PROTOCOL_UNVERIFIED, "尚未核对实时有线协议。")
        if target_url != BJUT_WIRED_LOGIN:
            return AdapterReply(False, ErrorCode.UNTRUSTED_TARGET, "有线认证提交目标已变化。")
        if (
            not re.fullmatch(r"[A-Za-z0-9_.@-]{2,256}", credentials.username)
            or not credentials.password
            or len(credentials.password) > 1024
        ):
            return AdapterReply(False, ErrorCode.CREDENTIAL_STORE, "凭据内容无效，请重新保存。")
        try:
            callback = new_callback()
            params = [
                ("callback", callback),
                ("DDDDD", login_account(credentials.username, prepared.suffix)),
                ("upass", credentials.password),
                ("0MKKey", "123456"),
                ("R2", ""),
                ("v4ip", prepared.ipv4),
                ("v6ip", ""),
                ("terminal_type", "1"),
                ("lang", "zh-cn"),
                *prepared.form_fields,
                *prepared.metadata,
                *_cache_buster(),
            ]
            with self._make_client() as client:
                protect_http_logs()
                client.cookies.update(prepared.cookies)
                result = _jsonp(
                    self._get(client, target_url, prepared.guard, "login", params), callback
                ).get("result")
            if type(result) not in (int, str) or result not in (0, 1, "0", "1", "ok"):
                raise protocol_error()
            accepted = result in (1, "1", "ok")
            observe("protocol", role="login", accepted=accepted)
            if accepted:
                self._status = AuthState.AUTHENTICATING
                return AdapterReply(True)
            return AdapterReply(False, ErrorCode.MANUAL_ACTION, "网关拒绝登录，请在浏览器中核对。")
        except CampusError as exc:
            return AdapterReply(False, exc.code, exc.message)

    def verify(self, result: ConnectivityResult) -> bool:
        self._status = AuthState.AUTHENTICATED if result.online else AuthState.UNKNOWN
        return result.online

    def get_status(self) -> AuthState:
        return self._status
