"""BJUT's two observed wired HTTPS branches."""

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
    BJUT_WIRED_EPORTAL_LOGIN,
    BJUT_WIRED_HOST,
    BJUT_WIRED_LOGIN,
    BJUT_WIRED_PAGE,
    BJUT_WIRED_SCRIPT,
    BJUT_WIRED_STATUS,
    bjut_wired_portal_supported,
    validate_target,
)
from campus_autoconnect.services.connectivity import make_client, request_error_code

_Guard = Callable[[str], None]
_Params = list[tuple[str, str]]
_PAGE_INDEX = re.compile(r"[A-Za-z0-9_-]{1,48}\Z")
_JS_VERSION = r"[0-9.X]{1,12}"
_JS_STRING = r"""(?:"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*')"""
_FORM_FIELDS = {"R1": "", "R3": "", "R6": "0", "para": ""}
_ZERO_MAC = "000000000000"
_OTHER_MAC_PLACEHOLDERS = {"111111111111", "123456789012"}
_MAC_PLACEHOLDERS = {_ZERO_MAC, *_OTHER_MAC_PLACEHOLDERS}
_PREPARE_LABELS = {
    "page": "登录页",
    "status": "在线状态",
    "config": "实时协议配置",
    "template": "登录模板",
    "script": "登录脚本版本",
}


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


def _encoded_params(fields: _Params) -> _Params:
    # a41.js uses UTF-16 code units and XOR/hex for the ePortal API. TLS protects the query.
    key = ord("t") ^ ord("e") ^ ord("s") ^ ord("t")
    encoded = []
    for name, value in fields:
        units = value.encode("utf-16-le", errors="surrogatepass")
        if len(units) > 1024:
            raise CampusError(ErrorCode.CREDENTIAL_STORE, "有线门户参数过长，请在浏览器中登录。")
        hex_value = "".join(
            f"{((high << 8) | low) ^ key:02x}"
            for low, high in zip(units[::2], units[1::2], strict=True)
        )
        encoded.append((name, hex_value))
    return encoded + [("encrypt", "1")] + _cache_buster()


def _configuration_params(ipv4: str, vlan: str, callback: str) -> _Params:
    fields = _jsonp_params(callback, "4.X") + [
        ("wlan_vlan_id", vlan),
        ("wlan_user_ip", base64.b64encode(ipv4.encode("ascii")).decode("ascii")),
        ("wlan_user_ipv6", ""),
        ("wlan_user_ssid", ""),
        ("wlan_user_areaid", ""),
        ("wlan_ac_ip", ""),
        ("wlan_ap_mac", _ZERO_MAC),
        ("gw_id", _ZERO_MAC),
    ]
    return _encoded_params(fields)


@dataclass(frozen=True)
class _WiredConfig:
    target_url: str
    program: str
    page: str
    suffix: str = field(repr=False)
    prefix: str

    @property
    def eportal(self) -> bool:
        return self.target_url == BJUT_WIRED_EPORTAL_LOGIN


def _config(payload: dict) -> _WiredConfig:
    data = payload.get("data")
    if not isinstance(data, dict):
        raise protocol_error()
    mode = str(data.get("login_method"))
    if mode not in {"0", "1"}:
        raise protocol_error()
    eportal = mode == "1"
    for key in (
        "en_md5",
        "password_cut",
        "enable_r3",
        "enable_alias",
        "io_mode",
        "en_perceive",
        "custom_perceive",
        "enable_hotelop_login",
        "check_online_method",
    ):
        if str(data.get(key, 0)) not in {"0", ""}:
            raise protocol_error()
    if str(data.get("needCaptcha", 0)) not in {"0", ""}:
        raise CampusError(ErrorCode.MANUAL_ACTION, "有线网关要求验证码，请在浏览器中登录。")
    if data.get("domain_name", "") not in ("", BJUT_WIRED_HOST):
        raise protocol_error()
    profile_flags = {"0", "1", ""} if eportal else {"0", ""}
    prefix = str(data.get("account_prefix", 0))
    if prefix not in profile_flags or str(data.get("ipv6_state", 0)) not in profile_flags:
        raise protocol_error()
    if eportal and (
        type(payload.get("code")) is not int
        or payload["code"] != 1
        or str(data.get("enable_https")) not in {"1", "2"}
        or str(data.get("ep_https_port")) != "802"
    ):
        raise protocol_error()
    if eportal and str(data.get("checkipv6", 0)) not in {"0", ""}:
        raise CampusError(ErrorCode.MANUAL_ACTION, "有线网关要求核对 IPv6，请在浏览器中登录。")
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
    target = BJUT_WIRED_EPORTAL_LOGIN if eportal else BJUT_WIRED_LOGIN
    return _WiredConfig(target, program, page, suffix, ",0," if prefix == "1" else "")


def _wired_mac(page: str, status: dict) -> str:
    mac = _literal(page, "ss4", r"[0-9A-Fa-f:-]{12,17}")
    mac = mac.replace(":", "").replace("-", "") if mac else ""
    if mac in _MAC_PLACEHOLDERS and (observed := status.get("ss4")):
        if not isinstance(observed, str):
            observed = ""
        observed = observed.replace(":", "").replace("-", "")
        if observed not in _MAC_PLACEHOLDERS:
            mac = observed
    # The exact wired portal may return all zeroes for an IPv4 session.
    if not re.fullmatch(r"[0-9A-Fa-f]{12}", mac) or mac in _OTHER_MAC_PLACEHOLDERS:
        raise CampusError(ErrorCode.SESSION_MAC_INVALID, "有线网关的会话 MAC 字段无效。")
    return mac


class _LoginForm(HTMLParser):
    def __init__(self, *, eportal: bool) -> None:
        super().__init__()
        self.eportal = eportal
        self.current = ""
        self.forms: dict[str, dict[str, str]] = {}
        self.manual_required = False
        self.default_ip_selected = False

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attributes = {key: value or "" for key, value in attrs}
        name = attributes.get("name", "")
        if tag == "form":
            if name and name in self.forms:
                raise protocol_error()
            self.current = name
            self.forms[name] = {}
        if name in {"checkIOMode", "ISP_select", "ISP_radio", "authorize", "checkPerceive"}:
            self.manual_required = True
        if name in {"C1", "captcha"}:
            display = re.findall(
                r"(?:^|;)\s*display\s*:\s*([^;]+)", attributes.get("style", "").lower()
            )
            hidden = [value.strip() for value in display] == ["none"]
            if name == "C1":
                # This portal prechecks a hidden disclaimer control. Never check it ourselves.
                self.manual_required |= not (
                    self.eportal
                    and tag == "input"
                    and self.current == "f1"
                    and attributes.get("type") == "checkbox"
                    and "checked" in attributes
                    and hidden
                )
            else:
                self.manual_required |= not hidden
        if self.eportal and name == "v46s":
            checked = "checked" in attributes
            value = attributes.get("value")
            self.manual_required |= (
                tag != "input"
                or attributes.get("type") != "radio"
                or value not in {"0", "2"}
                or (checked and (value != "0" or self.default_ip_selected))
            )
            self.default_ip_selected |= checked
        if self.eportal and name == "v6ip" and attributes.get("value"):
            self.manual_required = True
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


def _template(body: bytes, *, eportal: bool) -> tuple[str | None, tuple[tuple[str, str], ...]]:
    source = body.decode("gb18030", errors="strict")
    version = _literal(source, "jsVersion", _JS_VERSION)
    templates = re.findall(r"\bbodyContent\s*=\s*(" + _JS_STRING + r")\s*;", source)
    if len(templates) != 1 or (version is None and re.search(r"\bjsVersion\s*=", source)):
        raise protocol_error()
    markup = re.sub(r"\\(?:u[0-9a-fA-F]{4}|x[0-9a-fA-F]{2}|.)", _unescape, templates[0][1:-1])
    forms = _LoginForm(eportal=eportal)
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
    target_url: str = field(repr=False)
    suffix: str = field(repr=False)
    prefix: str = field(repr=False)
    fields: tuple[tuple[str, str], ...] = field(repr=False)
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
        validate_target(BJUT_WIRED_PAGE, profile)
        return AdapterDetection(True, target_url=BJUT_WIRED_PAGE)

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
                if url == BJUT_WIRED_SCRIPT:
                    return read_portal_response(response, limit=256 * 1024, allow_gzip=True)
                return read_portal_response(response)
        except httpx.RequestError as exc:
            code = request_error_code(exc)
            observe("http_error", role=role, code=code)
            raise CampusError(code, "有线网关请求未完成，请检查网络和 TLS 状态。") from None

    def prepare(self, profile: NetworkProfile, network: NetworkSnapshot, guard: _Guard) -> str:
        self._prepared = None
        self._status = AuthState.UNKNOWN
        self.login_request_attempted = False
        adapter = network.selected
        if not profile.is_wired or adapter is None or not profile.matches_adapter(adapter):
            raise CampusError(ErrorCode.UNTRUSTED_NETWORK, "当前物理网卡或网关与有线档案不一致。")
        if not bjut_wired_portal_supported(profile.portal_page_url):
            raise CampusError(ErrorCode.PROTOCOL_UNVERIFIED, "该有线入口的自动认证协议待核对。")
        validate_target(BJUT_WIRED_PAGE, profile)
        role = "page"
        try:
            with self._make_client() as client:
                protect_http_logs()
                page = self._get(client, BJUT_WIRED_PAGE, guard, role).decode("gb18030")
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
                role = "status"
                callback = new_callback()
                status_reply = _jsonp(
                    self._get(
                        client,
                        BJUT_WIRED_STATUS,
                        guard,
                        role,
                        _jsonp_params(callback, "4.X") + _cache_buster(),
                    ),
                    callback,
                )
                status = status_reply.get("result")
                if type(status) in (int, str) and status in (1, "1"):
                    raise CampusError(
                        ErrorCode.ALREADY_AUTHENTICATED, "有线网关已有在线会话，外网探测仍待核实。"
                    )
                if type(status) not in (int, str) or status not in (0, "0"):
                    raise protocol_error()
                role = "config"
                callback = new_callback()
                config = _config(
                    _jsonp(
                        self._get(
                            client,
                            BJUT_WIRED_CONFIG,
                            guard,
                            role,
                            _configuration_params(ipv4, vlan, callback),
                        ),
                        callback,
                    )
                )
                params = [("v", "_" + version)]
                role = "template"
                url = BJUT_WIRED_API + f"extern/{config.program}/{config.page}/pc.js"
                js_version, fields = _template(
                    self._get(client, url, guard, role, params), eportal=config.eportal
                )
                if js_version is None:
                    role = "script"
                    script = self._get(client, BJUT_WIRED_SCRIPT, guard, role, params)
                    js_version = _literal(script.decode("gb18030"), "jsVersion", _JS_VERSION)
                    if js_version is None:
                        raise protocol_error()
                if config.eportal:
                    fields = (
                        ("login_method", "1"),
                        ("wlan_user_ip", ipv4),
                        ("wlan_user_ipv6", ""),
                        ("wlan_user_mac", _wired_mac(page, status_reply)),
                        ("wlan_vlan_id", vlan),
                        ("wlan_ac_ip", ""),
                        ("wlan_ac_name", ""),
                        ("authex_enable", ""),
                        ("login_ip_type", "0"),
                    )
                else:
                    fields += (
                        ("0MKKey", "123456"),
                        ("R2", ""),
                        ("v4ip", ipv4),
                        ("v6ip", ""),
                    )
                metadata = _jsonp_params("", js_version, config.program, config.page)[1:]
                self._prepared = _Prepared(
                    config.target_url,
                    config.suffix,
                    config.prefix,
                    (*fields, *metadata, ("terminal_type", "1"), ("lang", "zh-cn")),
                    guard,
                    httpx.Cookies(client.cookies),
                )
        except (CampusError, UnicodeError) as exc:
            if isinstance(exc, CampusError) and exc.code != ErrorCode.PROTOCOL_CHANGED:
                raise
            observe("protocol", role=role, code=ErrorCode.PROTOCOL_CHANGED)
            raise CampusError(
                ErrorCode.PROTOCOL_CHANGED,
                f"有线网关的{_PREPARE_LABELS[role]}与已核对的协议不符，已停止认证。",
            ) from None
        self._status = AuthState.AUTH_REQUIRED
        observe("protocol", live_config_supported=True, account_suffix_present=bool(config.suffix))
        return config.target_url

    def authenticate(self, target_url: str, credentials: Credentials) -> AdapterReply:
        prepared, self._prepared = self._prepared, None
        self._status = AuthState.AUTH_FAILED
        self.login_request_attempted = False
        if prepared is None:
            return AdapterReply(False, ErrorCode.PROTOCOL_UNVERIFIED, "尚未核对实时有线协议。")
        if target_url != prepared.target_url:
            return AdapterReply(False, ErrorCode.UNTRUSTED_TARGET, "有线认证提交目标已变化。")
        if (
            not re.fullmatch(r"[A-Za-z0-9_.@-]{2,256}", credentials.username)
            or not credentials.password
            or len(credentials.password) > 1024
        ):
            return AdapterReply(False, ErrorCode.CREDENTIAL_STORE, "凭据内容无效，请重新保存。")
        try:
            callback = new_callback()
            account = login_account(credentials.username, prepared.suffix)
            if target_url == BJUT_WIRED_EPORTAL_LOGIN:
                params = _encoded_params(
                    [
                        ("callback", callback),
                        ("user_account", prepared.prefix + account),
                        ("user_password", credentials.password),
                        *prepared.fields,
                    ]
                )
            else:
                params = [
                    ("callback", callback),
                    ("DDDDD", account),
                    ("upass", credentials.password),
                    *prepared.fields,
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
