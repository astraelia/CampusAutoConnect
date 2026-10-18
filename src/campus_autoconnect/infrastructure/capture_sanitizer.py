"""Portal structure only; never persist raw bodies, query values or header secrets."""

import json
from urllib.parse import parse_qsl, urlsplit

from campus_autoconnect.adapters.eportal import CONFIG_PATH, LOGIN_PATH, STATUS_PATH
from campus_autoconnect.core.errors import CampusError
from campus_autoconnect.services.capture_analysis import LOGIN_FIELDS

PATHS = {"/a79.htm", CONFIG_PATH, LOGIN_PATH, STATUS_PATH, "/connecttest.txt", "/generate_204"}
FIELDS = LOGIN_FIELDS | {"vlan", "wlan_vlan_id", "c", "a", "method", "version", "type"}


def safe_params(pairs: list[tuple[str, str]]) -> list[dict]:
    return [
        {
            "name": key if key in FIELDS else "other_field",
            "value": value
            if key == "login_method" and value in {"0", "1"}
            else "[hidden]"
            if value
            else "[empty]",
        }
        for key, value in pairs[:80]
    ]


def safe_url(raw: str) -> dict:
    try:
        parts = urlsplit(raw)
        if parts.scheme not in {"http", "https"} or not parts.hostname or parts.username:
            raise ValueError
        host = parts.hostname
        # Host is intentionally retained for local endpoint setup; reports flag this privacy scope.
        if len(host) > 253 or any(ord(c) < 33 for c in host):
            raise ValueError
        query = parse_qsl(parts.query, keep_blank_values=True, max_num_fields=80)
        return {
            "scheme": parts.scheme,
            "host": host,
            "port": parts.port,
            "path": parts.path if parts.path in PATHS else "/[other]",
            "query": safe_params(query),
        }
    except (ValueError, TypeError):
        return {"invalid_url": True}


def should_watch(url: str, resource_type: str) -> bool:
    try:
        parts = urlsplit(url)
        if parts.scheme not in {"http", "https"}:
            return False
        return resource_type == "document" or parts.path in PATHS
    except (ValueError, TypeError):
        return False


def safe_post(raw: str | None, content_type: str) -> dict | None:
    if not raw:
        return None
    if len(raw) > 65536:
        return {"type": "oversized", "values": "[not saved]"}
    try:
        if "json" in content_type:
            payload = json.loads(raw)
            if isinstance(payload, dict):
                return {
                    "type": "json",
                    "fields": safe_params([(str(k), str(v)) for k, v in payload.items()]),
                }
        if "x-www-form-urlencoded" in content_type:
            return {
                "type": "form",
                "fields": safe_params(parse_qsl(raw, keep_blank_values=True, max_num_fields=80)),
            }
    except (ValueError, TypeError, RecursionError):
        pass
    return {"type": "other", "values": "[not saved]"}


def outcome(raw: bytes) -> dict:
    if len(raw) > 65536:
        return {}
    from campus_autoconnect.adapters.eportal import parse_jsonp

    try:
        text = raw.decode("utf-8")
        if text.lstrip().startswith("{"):
            payload = json.loads(text)
        else:
            callback = text.split("(", 1)[0].strip()
            payload = parse_jsonp(raw, callback)
        if not isinstance(payload, dict):
            return {}
        result = payload.get("result")
        safe = {"result": result} if type(result) is int and result in (0, 1) else {}
        # This is a bounded signal, never an arbitrary server message.
        if any(word in text.lower() for word in ("login success", "登录成功", "认证成功")):
            safe["text_signal"] = "login_success"
        return safe
    except (ValueError, TypeError, UnicodeError, CampusError, RecursionError):
        return {}
