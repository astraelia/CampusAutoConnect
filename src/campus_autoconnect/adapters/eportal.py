"""Observed ePortal data formats. No JavaScript execution or network side effects."""

import base64
import ipaddress
import json
import re
import secrets
from dataclasses import dataclass, field
from typing import Any

from campus_autoconnect.core.errors import CampusError
from campus_autoconnect.core.models import ErrorCode

MAX_RESPONSE_BYTES = 128 * 1024
LOGIN_PATH = "/eportal/portal/login"
CONFIG_PATH = "/eportal/portal/page/loadConfig"
STATUS_PATH = "/eportal/portal/online_list"
CALLBACK = re.compile(r"dr[0-9]{1,16}\Z")


def protocol_error() -> CampusError:
    return CampusError(ErrorCode.PROTOCOL_CHANGED, "认证数据结构不符合已核对的协议，已停止处理。")


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError
        result[key] = value
    return result


def _reject_constant(_value: str) -> None:
    raise ValueError


def parse_jsonp(body: bytes, callback: str) -> dict[str, Any]:
    """Accept one exact callback around JSON, never executable JS or a stale callback."""
    if (
        not isinstance(body, bytes)
        or not isinstance(callback, str)
        or not CALLBACK.fullmatch(callback)
        or len(body) > MAX_RESPONSE_BYTES
    ):
        raise protocol_error()
    try:
        text = body.decode("utf-8-sig").strip()
        match = re.fullmatch(re.escape(callback) + r"\s*\((.*)\)\s*;?", text, re.DOTALL)
        if match is None:
            raise ValueError
        result = json.loads(
            match.group(1), object_pairs_hook=_unique_object, parse_constant=_reject_constant
        )
        if not isinstance(result, dict):
            raise ValueError
        return result
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise protocol_error() from exc


def _integer(data: dict, name: str, allowed: set[int]) -> int:
    value = data.get(name)
    if type(value) is int and value in allowed:
        return value
    if isinstance(value, str) and value in {str(item) for item in allowed}:
        return int(value)
    raise protocol_error()


@dataclass(frozen=True)
class EPortalConfig:
    """Supported observed branch, with the account suffix kept out of repr/logging."""

    account_suffix: str = field(repr=False)
    https_mode: int
    http_port: int
    https_port: int

    @classmethod
    def from_response(cls, payload: dict) -> "EPortalConfig":
        if (
            not isinstance(payload, dict)
            or type(payload.get("code")) is not int
            or payload["code"] != 1
        ):
            raise protocol_error()
        data = payload.get("data")
        if not isinstance(data, dict):
            raise protocol_error()
        if _integer(data, "login_method", {1}) != 1:
            raise protocol_error()
        # Other branches have not been verified. Never guess a transformation or mode.
        for name in (
            "en_md5",
            "password_cut",
            "account_prefix",
            "enable_alias",
            "io_mode",
            "ipv6_state",
            "enable_hotelop_login",
            "en_perceive",
        ):
            _integer(data, name, {0})
        suffix = data.get("account_suffix")
        if not isinstance(suffix, str) or not re.fullmatch(r"[@A-Za-z0-9._-]{0,64}", suffix):
            raise protocol_error()
        ports = []
        for key in ("ep_http_port", "ep_https_port"):
            value = data.get(key)
            if type(value) is int:
                port = value
            elif isinstance(value, str) and re.fullmatch(r"[0-9]{1,5}", value):
                port = int(value)
            else:
                raise protocol_error()
            if not 1 <= port <= 65535:
                raise protocol_error()
            ports.append(port)
        return cls(suffix, _integer(data, "enable_https", {0, 1, 2}), *ports)


@dataclass(frozen=True, repr=False)
class EPortalContext:
    ipv4: str
    mac: str
    vlan: str

    @classmethod
    def from_page(
        cls, body: bytes, local_ipv4: tuple[str, ...], *, allow_zero_mac: bool = False
    ) -> "EPortalContext":
        """Read only known string literals; expressions and duplicate assignments fail."""
        if len(body) > MAX_RESPONSE_BYTES:
            raise protocol_error()
        try:
            page = body.decode("gb18030")
            values: dict[str, str] = {}
            for name in ("v46ip", "ss4", "vlanid"):
                matches = re.findall(r"\b" + name + r"\s*=\s*(['\"])([^'\"\r\n\\]*)\1\s*;", page)
                if len(matches) != 1:
                    raise ValueError
                values[name] = matches[0][1]
        except (ValueError, UnicodeError) as exc:
            raise CampusError(
                ErrorCode.SESSION_FIELDS_INVALID,
                "认证页会话字段缺失、重复或编码不受支持；未读取凭据。",
            ) from exc
        try:
            address = ipaddress.IPv4Address(values["v46ip"])
            if (
                str(address) not in local_ipv4
                or address.is_unspecified
                or address.is_loopback
                or address.is_link_local
                or address.is_multicast
            ):
                raise ValueError
        except ValueError as exc:
            raise CampusError(
                ErrorCode.SESSION_IP_MISMATCH,
                "认证页 IPv4 无效或与当前 Wi-Fi 不一致；未读取凭据。",
            ) from exc
        mac = values["ss4"].replace(":", "").replace("-", "")
        if not re.fullmatch(r"[0-9A-Fa-f]{12}", mac):
            raise CampusError(ErrorCode.SESSION_MAC_INVALID, "认证页 MAC 格式无效；未读取凭据。")
        if mac == "000000000000" and allow_zero_mac is not True:
            raise CampusError(
                ErrorCode.ZERO_MAC_PERMISSION_REQUIRED,
                "认证页返回全零 MAC；请在“配置当前网络”中明确允许本档案兼容后手动测试。"
                "未读取凭据。",
            )
        vlan = values["vlanid"]
        # This is a Portal configuration parameter. The observed page uses 0 and
        # loadConfig accepts it; it is not a measurement of the interface's VLAN.
        if not re.fullmatch(r"[0-9]{1,4}", vlan) or not 0 <= int(vlan) <= 4094:
            raise CampusError(
                ErrorCode.SESSION_VLAN_INVALID,
                "认证页 VLAN 格式或取值不受支持（允许 0～4094）；未读取凭据。",
            )
        return cls(str(address), mac, vlan)


def response_accepted(payload: dict) -> bool:
    """Only the observed integer result is a success signal; HTTP 200 alone is not."""
    if (
        not isinstance(payload, dict)
        or type(payload.get("result")) is not int
        or payload["result"] not in (0, 1)
    ):
        raise protocol_error()
    return payload["result"] == 1


def login_account(username: str, suffix: str) -> str:
    """Accept a bare account or one exact server suffix without changing the account."""
    if suffix.startswith("@"):
        if username.endswith(suffix):
            base = username[: -len(suffix)]
            if base and "@" not in base:
                return username
        elif "@" not in username:
            return username + suffix
        raise CampusError(
            ErrorCode.MANUAL_ACTION,
            "账号后缀与当前认证配置不一致或重复；请保存纯账号，或只带一次正确后缀的完整账号。",
        )
    return username + suffix


def new_callback() -> str:
    return "dr" + str(secrets.randbelow(10**12))


def configuration_params(context: EPortalContext, callback: str) -> list[tuple[str, str]]:
    """Fields from the observed a41.js getPageInfo/_jsonp branch."""
    return [
        ("callback", callback),
        ("program_index", ""),
        ("wlan_vlan_id", context.vlan),
        ("wlan_user_ip", base64.b64encode(context.ipv4.encode("ascii")).decode("ascii")),
        ("wlan_user_ipv6", ""),
        ("wlan_user_ssid", ""),
        ("wlan_user_areaid", ""),
        ("wlan_ac_ip", ""),
        ("wlan_ap_mac", "000000000000"),
        ("gw_id", ""),
        ("jsVersion", "4.X"),
        ("v", str(secrets.randbelow(10000) + 500)),
        ("lang", "zh"),
    ]
