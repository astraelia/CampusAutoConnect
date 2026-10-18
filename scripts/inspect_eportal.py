"""Read only the observed page/configuration, then check TLS without sending a login."""

import argparse
import base64
import json
from collections.abc import Callable
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

import httpx

from campus_autoconnect.adapters.eportal import (
    CONFIG_PATH,
    EPortalConfig,
    EPortalContext,
    parse_jsonp,
)
from campus_autoconnect.core.errors import CampusError
from campus_autoconnect.core.network import WindowsNetworkProvider
from campus_autoconnect.services.capture_analysis import analyze_capture
from campus_autoconnect.services.connectivity import make_client, request_error_code
from scripts.inspect_portal import (
    InspectionError,
    check_https,
    read_bounded,
    tls_failure,
    validate_page_url,
)


def inspect_eportal(
    page_url: str,
    api_origin: str,
    local_ipv4: tuple[str, ...],
    *,
    client_factory: Callable[[], httpx.Client] = make_client,
) -> dict:
    page = urlsplit(validate_page_url(page_url))
    api = urlsplit(validate_page_url(api_origin))
    if page.path != "/a79.htm" or api.path not in ("", "/") or page.hostname != api.hostname:
        raise InspectionError("unobserved_page_or_api_origin")
    with client_factory() as client, client.stream("GET", page_url) as response:
        if response.status_code != 200:
            raise InspectionError("page_not_accepted")
        # Inspection sends no credentials and grants no profile permission. Observe
        # placeholders so the public configuration can be checked independently.
        context = EPortalContext.from_page(
            read_bounded(response, 128 * 1024), local_ipv4, allow_zero_mac=True
        )
    params = {
        "callback": "dr1001",
        "program_index": "",
        "wlan_vlan_id": context.vlan,
        "wlan_user_ip": base64.b64encode(context.ipv4.encode("ascii")).decode("ascii"),
        "wlan_user_ipv6": "",
        "wlan_user_ssid": "",
        "wlan_user_areaid": "",
        "wlan_ac_ip": "",
        "wlan_ap_mac": "000000000000",
        "gw_id": "",
        "jsVersion": "4.X",
        "v": "501",
        "lang": "zh",
    }
    target = urlunsplit((api.scheme, api.netloc, CONFIG_PATH, "", ""))
    with client_factory() as client, client.stream("GET", target, params=params) as response:
        if response.status_code != 200:
            raise InspectionError("configuration_not_accepted")
        payload = parse_jsonp(read_bounded(response, 128 * 1024), "dr1001")
    config = EPortalConfig.from_response(payload)
    host = f"[{api.hostname}]" if ":" in api.hostname else api.hostname
    secure_config_url = urlunsplit(("https", f"{host}:{config.https_port}", CONFIG_PATH, "", ""))
    try:
        with (
            client_factory() as client,
            client.stream("GET", secure_config_url, params=params) as response,
        ):
            tls_report = {
                "certificate_verified": True,
                "status": response.status_code,
                "authentication_verified": False,
            }
    except httpx.RequestError as exc:
        tls_report = {
            "certificate_verified": False,
            "authentication_verified": False,
            **tls_failure(exc),
        }
    return {
        "kind": "credential_free_observed_configuration_inspection",
        "login_method": 1,
        "password_md5": False,
        "password_cut": False,
        "account_prefix": False,
        "account_suffix_present": bool(config.account_suffix),
        "https_mode": config.https_mode,
        "http_api_port": config.http_port,
        "https_api_port": config.https_port,
        "domain_name_configured": bool(payload["data"].get("domain_name")),
        "zero_mac_observed": context.mac == "000000000000",
        "zero_vlan_observed": int(context.vlan) == 0,
        "login_requires_zero_mac_profile_permission": context.mac == "000000000000",
        "standard_https": check_https(page_url, client_factory=client_factory),
        "configured_https_api": tls_report,
        "credentials_read": False,
        "authentication_attempted": False,
        "note": "配置读取不等于实际登录会话实测；证书通过也不等于认证协议验证通过。",
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="只读检查抓包已观察的 ePortal 入口与公开配置，不登录"
    )
    parser.add_argument("capture", type=Path, help="本人提供的 Campus Portal Capture 脱敏 JSON")
    args = parser.parse_args()
    try:
        analyze_capture(args.capture)
        with args.capture.open("rb") as stream:
            payload = json.loads(stream.read(2 * 1024 * 1024 + 1))
        pages = [r["url"] for r in payload["requests"] if r["url"]["path"] == "/a79.htm"]
        apis = [r["url"] for r in payload["requests"] if r["url"]["path"] == CONFIG_PATH]
        if not pages or not apis:
            raise InspectionError("observed_page_and_configuration_required")

        def location(entry, path):
            host = entry["host"]
            if ":" in host:
                host = f"[{host}]"
            authority = host + (":" + str(entry["port"]) if entry.get("port") else "")
            return urlunsplit((entry["scheme"], authority, path, "", ""))

        page_url, api_origin = location(pages[0], "/a79.htm"), location(apis[0], "")
        provider = WindowsNetworkProvider()
        snapshot = provider.snapshot()
        wifi = snapshot.wifi
        if (
            not wifi
            or not provider.route_allows(page_url, snapshot)
            or not provider.route_allows(api_origin, snapshot)
        ):
            raise InspectionError("campus_route_unconfirmed")
        report = inspect_eportal(page_url, api_origin, wifi.ipv4)
        print(json.dumps(report, ensure_ascii=False, indent=2))
        return int(not report["configured_https_api"]["certificate_verified"])
    except (CampusError, InspectionError) as exc:
        code = exc.code.value if isinstance(exc, CampusError) else str(exc)
        print(json.dumps({"error_code": code}))
    except Exception as exc:
        print(
            json.dumps(
                {"error_code": request_error_code(exc).value, "error_type": type(exc).__name__}
            )
        )
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
