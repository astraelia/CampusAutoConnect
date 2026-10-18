"""Read-only Portal inspection. Never executes JavaScript or submits credentials."""

import argparse
import hashlib
import json
import re
import ssl
import time
import zlib
from collections.abc import Callable
from html.parser import HTMLParser
from urllib.parse import parse_qsl, urljoin, urlsplit, urlunsplit

import httpx

from campus_autoconnect.services.connectivity import make_client, request_error_code


class InspectionError(ValueError):
    """Fixed machine-readable errors, never arbitrary remote messages."""


def validate_page_url(value: str) -> str:
    try:
        parts = urlsplit(value)
        if (
            re.search(r"[\s\\]", value)
            or parts.scheme not in {"http", "https"}
            or not parts.hostname
            or parts.username is not None
            or parts.password is not None
            or parts.query
            or parts.fragment
            or parts.port == 0
        ):
            raise ValueError
    except (ValueError, TypeError) as exc:
        raise InspectionError("invalid_page_url") from exc
    return value


def static_script_url(base: str, path: str) -> str:
    validate_page_url(base)
    if (
        not re.fullmatch(r"/[A-Za-z0-9_./-]+\.js", path)
        or path.startswith("//")
        or ".." in path.split("/")
    ):
        raise InspectionError("invalid_static_script_path")
    target = urljoin(base, path)
    if urlsplit(target).netloc != urlsplit(base).netloc:
        raise InspectionError("cross_origin_script")
    return target


def locator(value: str, base: str) -> dict:
    target = urlsplit(urljoin(base, value))
    return {
        "scheme": target.scheme,
        "origin": "same-origin" if target.netloc == urlsplit(base).netloc else "external-origin",
        "path": target.path,
        "query_fields": sorted({key for key, _ in parse_qsl(target.query)}),
    }


def read_bounded(response: httpx.Response, limit: int, *, seconds: float = 6) -> bytes:
    """Bound compressed wire bytes and decompressed bytes before parsing."""
    encoding = response.headers.get("content-encoding", "identity").lower()
    if encoding not in {"identity", "gzip"}:
        raise InspectionError("unsupported_page_encoding")
    decoder = zlib.decompressobj(16 + zlib.MAX_WBITS) if encoding == "gzip" else None
    content = bytearray()
    wire_bytes = 0
    started = time.monotonic()
    try:
        for raw in response.iter_raw():
            wire_bytes += len(raw)
            if wire_bytes > limit or time.monotonic() - started > seconds:
                raise InspectionError("page_transfer_limit")
            chunk = decoder.decompress(raw, limit - len(content) + 1) if decoder else raw
            if len(content) + len(chunk) > limit:
                raise InspectionError("page_size_limit")
            content.extend(chunk)
    except zlib.error as exc:
        raise InspectionError("invalid_compressed_page") from exc
    if decoder and (not decoder.eof or decoder.unused_data):
        raise InspectionError("invalid_compressed_page")
    return bytes(content)


def tls_failure(exc: BaseException) -> dict:
    result = {"error_code": request_error_code(exc).value}
    cause: BaseException | None = exc
    visited: set[int] = set()
    while cause is not None and id(cause) not in visited:
        visited.add(id(cause))
        if isinstance(cause, ssl.SSLCertVerificationError):
            message = getattr(cause, "verify_message", "")
            # Never expose verify_message; it can contain the actual private host.
            result["certificate_error"] = (
                "identity_mismatch"
                if isinstance(message, str) and "mismatch" in message.lower()
                else "verification_failed"
            )
            code = getattr(cause, "verify_code", None)
            if type(code) is int:
                result["verify_code"] = code
            break
        if isinstance(cause, ssl.SSLError):
            result["certificate_error"] = "tls_handshake_failed"
        cause = cause.__cause__ or cause.__context__
    return result


def check_https(page_url: str, *, client_factory: Callable[[], httpx.Client] = make_client) -> dict:
    """Check the same page over HTTPS; never grants profile trust.

    HTTP pages use the host's standard HTTPS port. Existing HTTPS URLs keep their port.
    A verified TLS connection says nothing about the school's login protocol.
    """
    parts = urlsplit(validate_page_url(page_url))
    host = f"[{parts.hostname}]" if ":" in parts.hostname else parts.hostname
    authority = parts.netloc if parts.scheme == "https" else host
    target = urlunsplit(("https", authority, parts.path or "/", "", ""))
    try:
        with client_factory() as client, client.stream("GET", target) as response:
            return {
                "certificate_verified": True,
                "status": response.status_code,
                "redirect_discovered": 300 <= response.status_code < 400,
                "authentication_verified": False,
            }
    except (httpx.RequestError, ssl.SSLError) as exc:
        return {
            "certificate_verified": False,
            "authentication_verified": False,
            **tls_failure(exc),
        }


def javascript_signals(source: str) -> dict:
    """Textual indicators only: no JS evaluation or executable request construction."""
    constants: dict[str, int | bool] = {}
    for name in ("enableHttps", "epHTTPPort", "enHTTPSPort", "isJSMin"):
        match = re.search(r"\bvar\s+" + name + r"\s*=\s*(true|false|\d{1,5})\s*;", source)
        if not match:
            continue
        value = match.group(1)
        if name in {"epHTTPPort", "enHTTPSPort"}:
            if value.isdigit() and 1 <= int(value) <= 65535:
                constants[name] = int(value)
        elif value in {"true", "false", "0", "1"}:
            constants[name] = value in {"true", "1"}
    domain = re.search(r"\bvar\s+domainName\s*=\s*['\"]([^'\"\r\n]*)['\"]\s*;", source)
    return {
        "evidence_level": "static_text_only_not_runtime_protocol",
        "template_constants": constants,
        "domain_name_configured": bool(domain and domain.group(1)),
        "runtime_login_method_observed": bool(
            re.search(r"\.login_method\s*=\s*parseInt\(\s*json\.data\.login_method\s*\)", source)
        ),
        "configuration_route_observed": bool(
            re.search(r"portal_api\s*\+\s*['\"]page/loadConfig['\"]", source)
        ),
        "login_branches_observed": [
            name
            for name in ("default_login", "portal_login")
            if re.search(r"\b" + name + r"\s*:\s*function\b", source)
        ],
        "jsonp_helper_observed": bool(re.search(r"\b_jsonp\s*:\s*function\b", source)),
        "jsonp_script_url_observed": bool(re.search(r"\bscript\.src\s*=\s*params\.url", source)),
        "configuration_driven_md5_observed": bool(
            re.search(r"if\s*\(\s*page\.en_md5\s*\)", source)
        ),
        "observations_do_not_authorize_login": True,
    }


class StructureParser(HTMLParser):
    def __init__(self, base: str) -> None:
        super().__init__()
        self.base = base
        self.forms: list[dict] = []
        self.inputs: list[dict] = []
        self.scripts: list[dict] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        values = dict(attrs)
        if tag == "form":
            self.forms.append(
                {
                    "method": (values.get("method") or "GET").upper(),
                    "action": locator(values.get("action") or "", self.base),
                }
            )
        elif tag == "input":
            self.inputs.append({"name": values.get("name"), "type": values.get("type", "text")})
        elif tag == "script" and values.get("src"):
            self.scripts.append(locator(values["src"], self.base))


def inspect_page(page_url: str, script: str | None = None, *, https: bool = False) -> dict:
    validate_page_url(page_url)
    target = static_script_url(page_url, script) if script else page_url
    report: dict = {"kind": "read_only_static_page_structure"}
    if https:
        report["https_check"] = check_https(page_url)
    with make_client() as client, client.stream("GET", target) as response:
        report["status"] = response.status_code
        if 300 <= response.status_code < 400:
            report["redirect"] = locator(response.headers.get("location", ""), page_url)
            return report
        content = read_bounded(response, 1024 * 1024 if script else 128 * 1024)
    page = content.decode("utf-8", errors="replace")
    structure = StructureParser(page_url)
    # JS can contain HTML template strings. They are not the current page DOM.
    if script is None:
        structure.feed(page)
    report.update(
        {
            "body_bytes": len(content),
            "html_structure_applicable": script is None,
            "forms": structure.forms,
            "inputs_without_values": structure.inputs,
            "external_scripts_without_query_values": structure.scripts,
            "static_brand_hints": [
                brand for brand in ("dr.com", "drcom", "eportal", "srun") if brand in page.lower()
            ],
            "inline_script_present": "<script" in page.lower(),
        }
    )
    if script:
        report.update(
            {
                "script_sha256": hashlib.sha256(content).hexdigest(),
                "observed_api_path_literals": sorted(
                    set(
                        re.findall(
                            r"[\"'](/(?:drcom|eportal|portal)/[A-Za-z0-9_./-]+)",
                            page,
                        )
                    )
                ),
                "observed_static_script_paths": sorted(
                    set(
                        re.findall(
                            r"[\"']([A-Za-z0-9_./-]+\.js)(?:\?[^\"']*)?[\"']",
                            page,
                        )
                    )
                ),
                "javascript_signals": javascript_signals(page),
            }
        )
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description="只读检查 Portal 结构与 HTTPS，不登录、不执行脚本")
    parser.add_argument("url", help="本人提供的页面，不含用户信息、查询参数或片段")
    parser.add_argument("--static-js", help="已观察到的同源静态 .js 路径")
    parser.add_argument("--check-https", action="store_true", help="核对同主机 HTTPS，保持证书校验")
    args = parser.parse_args()
    try:
        report = inspect_page(args.url, args.static_js, https=args.check_https)
        print(json.dumps(report, ensure_ascii=False, indent=2))
        # An inspection result never means authentication succeeded.
        return int(bool(args.check_https and not report["https_check"]["certificate_verified"]))
    except InspectionError as exc:
        print(json.dumps({"error": str(exc)}))
        return 1
    except Exception as exc:
        print(json.dumps({"error_code": request_error_code(exc).value}))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
