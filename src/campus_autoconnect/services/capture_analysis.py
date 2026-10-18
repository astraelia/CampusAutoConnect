"""Local sanitized capture analysis. Never returns hosts, values or arbitrary remote text."""

import json
from pathlib import Path
from urllib.parse import urlunsplit

from campus_autoconnect.adapters.eportal import CONFIG_PATH, LOGIN_PATH, STATUS_PATH
from campus_autoconnect.core.errors import CampusError
from campus_autoconnect.core.models import ErrorCode
from campus_autoconnect.core.portal import normalize_bjut_endpoints

MAX_CAPTURE_BYTES = 2 * 1024 * 1024
LOGIN_FIELDS = frozenset(
    (
        "callback",
        "login_method",
        "user_account",
        "user_password",
        "wlan_user_ip",
        "wlan_user_ipv6",
        "wlan_user_mac",
        "wlan_ac_ip",
        "wlan_ac_name",
        "jsVersion",
        "terminal_type",
        "lang",
        "v",
    )
)
_SENSITIVE_FIELDS = {"user_account", "user_password", "wlan_user_ip", "wlan_user_mac"}


def analyze_capture(path: Path) -> dict:
    """Read an explicit user-selected file, with bounded output independent of its text."""
    try:
        with path.open("rb") as stream:
            raw = stream.read(MAX_CAPTURE_BYTES + 1)
        if len(raw) > MAX_CAPTURE_BYTES:
            raise ValueError
        payload = json.loads(raw.decode("utf-8-sig"))
        requests = payload["requests"]
        if (
            not isinstance(payload, dict)
            or payload.get("tool")
            not in {
                "Campus Portal Capture / sanitized v1.1.0",
                "Campus Portal Capture / sanitized v1.2.0",
            }
            or not isinstance(requests, list)
            or not 1 <= len(requests) <= 600
            or type(payload.get("count")) is not int
            or payload["count"] != len(requests)
        ):
            raise ValueError
        http_count = https_count = failures = 0
        steps = []
        credentials_hidden = True
        for request in requests:
            if not isinstance(request, dict):
                raise ValueError
            url = request["url"]
            if not isinstance(url, dict) or url.get("scheme") not in ("http", "https"):
                raise ValueError
            http_count += url["scheme"] == "http"
            https_count += url["scheme"] == "https"
            failures += "network_failure" in request
            path_value = url.get("path")
            if path_value not in ("/a79.htm", CONFIG_PATH, STATUS_PATH, LOGIN_PATH):
                continue
            query = url.get("query", [])
            if not isinstance(query, list) or len(query) > 80:
                raise ValueError
            fields = []
            method_one = False
            for item in query:
                if not isinstance(item, dict) or not isinstance(item.get("name"), str):
                    raise ValueError
                name = item["name"]
                value = item.get("value")
                if not isinstance(value, str):
                    raise ValueError
                if name in LOGIN_FIELDS:
                    fields.append(name)
                method_one |= name == "login_method" and value == "1"
                if name in _SENSITIVE_FIELDS and value != "[empty]":
                    credentials_hidden &= value == "[hidden]" or (
                        value.startswith("[hidden: ") and value.endswith(" chars]")
                    )
            summary = request.get("response_summary", {})
            if not isinstance(summary, dict):
                raise ValueError
            result = summary.get("result")
            status = request.get("http_status")
            steps.append(
                {
                    "path": path_value,
                    "method": request.get("method")
                    if request.get("method") in ("GET", "POST")
                    else "OTHER",
                    "scheme": url["scheme"],
                    "http_status": status if type(status) is int and 100 <= status <= 599 else None,
                    "fields": sorted(set(fields)),
                    "duplicate_language_field": fields.count("lang") > 1,
                    "login_method_1_observed": method_one,
                    "integer_result": result if type(result) is int and result in (0, 1) else None,
                    "success_text_signal": summary.get("text_signal") == "login_success",
                }
            )
        login_steps = [step for step in steps if step["path"] == LOGIN_PATH]
        success = any(
            step["integer_result"] == 1 and step["success_text_signal"] for step in login_steps
        )
        return {
            "kind": "local_capture_structure_only",
            "request_count": len(requests),
            "http_count": http_count,
            "https_count": https_count,
            "network_failure_count": failures,
            "login_request_observed": bool(login_steps),
            "server_success_summary_observed": success,
            "sensitive_query_values_hidden": credentials_hidden,
            "steps": steps,
            "limitations": [
                "抓包摘要不能证明登录后互联网可用，也不会授予认证目标信任。",
                "没有 Cookie/Token 记录不代表协议不需要它们。",
                "运行配置只保留字段名时，不能推断密码处理或账号前后缀。",
                "分析结果不包含原始主机、地址、账号、参数值或响应正文。",
            ],
            "transport_status": (
                "仅观察到 HTTP；需在档案中明确配置并允许 HTTP 兼容，HTTPS 证书验证仍保留。"
            )
            if http_count and not https_count
            else "需要独立核对可信认证目标与证书。",
        }
    except (OSError, ValueError, TypeError, KeyError, RecursionError) as exc:
        raise CampusError(
            ErrorCode.CONFIG_ERROR, "抓包文件无法读取或格式不支持；未显示原始内容。"
        ) from exc


def capture_endpoints(path: Path) -> tuple[str, str]:
    """Local editor hints only. Never grants HTTP permission or modifies any profile."""
    analysis = analyze_capture(path)
    if not analysis["login_request_observed"] or not analysis["sensitive_query_values_hidden"]:
        raise CampusError(ErrorCode.CONFIG_ERROR, "请选择已脱敏且包含实际登录请求的抓包文件。")
    try:
        with path.open("rb") as stream:
            raw = stream.read(MAX_CAPTURE_BYTES + 1)
        if len(raw) > MAX_CAPTURE_BYTES:
            raise ValueError
        payload = json.loads(raw.decode("utf-8-sig"))
        locations: dict[str, set[str]] = {"/a79.htm": set(), CONFIG_PATH: set(), LOGIN_PATH: set()}
        for request in payload["requests"]:
            entry = request["url"]
            endpoint_path = entry.get("path")
            if endpoint_path not in locations:
                continue
            if request.get("method") != "GET":
                raise ValueError
            host, port = entry["host"], entry.get("port")
            if (
                not isinstance(host, str)
                or not host
                or (port is not None and (type(port) is not int or not 1 <= port <= 65535))
            ):
                raise ValueError
            if endpoint_path == "/a79.htm" and entry.get("query"):
                raise ValueError  # Only the observed query-free page context is supported.
            authority = (f"[{host}]" if ":" in host else host) + (
                f":{port}" if port is not None else ""
            )
            locations[endpoint_path].add(
                urlunsplit(
                    (
                        entry["scheme"],
                        authority,
                        "/a79.htm" if endpoint_path == "/a79.htm" else "",
                        "",
                        "",
                    )
                )
            )
        if any(len(values) != 1 for values in locations.values()):
            raise ValueError
        page = next(iter(locations["/a79.htm"]))
        api = next(iter(locations[CONFIG_PATH]))
        if api != next(iter(locations[LOGIN_PATH])):
            raise ValueError
        return normalize_bjut_endpoints(page, api)
    except (OSError, ValueError, KeyError, TypeError, RecursionError) as exc:
        raise CampusError(
            ErrorCode.CONFIG_ERROR, "抓包中的认证页、配置与登录目标缺失或不唯一；请人工核对地址。"
        ) from exc
