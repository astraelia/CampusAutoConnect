import json
import ssl

import httpx
import pytest

from scripts.inspect_eportal import inspect_eportal
from scripts.inspect_portal import InspectionError

pytestmark = pytest.mark.mock


def make_inspection_client(
    *, tls_failure=False, redirect=False, config_change=False, zero_context=False
):
    requests = []

    def handle(request):
        requests.append(request)
        assert "user_password" not in request.url.params
        assert "user_account" not in request.url.params
        assert "cookie" not in request.headers
        assert "authorization" not in request.headers
        if request.url.scheme == "https" and tls_failure:
            raise httpx.ConnectError(
                "synthetic-secret-network-detail", request=request
            ) from ssl.SSLError()
        if request.url.path == "/a79.htm":
            if redirect:
                return httpx.Response(302, headers={"location": "http://evil.example.test/"})
            body = b"var v46ip='192.0.2.10';var ss4='020000000007';var vlanid='12';"
            if zero_context:
                body = body.replace(b"020000000007", b"000000000000").replace(
                    b"vlanid='12'", b"vlanid='0'"
                )
        elif request.url.path == "/eportal/portal/page/loadConfig":
            payload = {
                "code": 1,
                "data": {
                    "login_method": "1",
                    "en_md5": "0",
                    "password_cut": "0",
                    "account_prefix": "0",
                    "enable_alias": "0",
                    "io_mode": "0",
                    "ipv6_state": "0",
                    "enable_hotelop_login": "0",
                    "en_perceive": "0",
                    "account_suffix": "@synthetic-private-suffix",
                    "enable_https": "0",
                    "ep_http_port": "801",
                    "ep_https_port": "802",
                    "domain_name": "",
                },
            }
            if config_change:
                payload["data"]["password_cut"] = "1"
            body = ("dr1001(" + json.dumps(payload) + ");").encode()
        else:
            raise AssertionError("Unexpected endpoint")
        return httpx.Response(200, stream=httpx.ByteStream(body))

    def client():
        return httpx.Client(
            transport=httpx.MockTransport(handle), trust_env=False, follow_redirects=False
        )

    return client, requests


def test_read_only_inspection_checks_current_context_and_does_not_grant_tls_trust():
    client, requests = make_inspection_client(tls_failure=True)
    report = inspect_eportal(
        "http://portal.example.test/a79.htm",
        "http://portal.example.test:801",
        ("192.0.2.10",),
        client_factory=client,
    )
    assert report["https_mode"] == 0 and report["account_suffix_present"]
    assert not report["configured_https_api"]["certificate_verified"]
    assert report["configured_https_api"]["error_code"] == "tls_error"
    assert not report["credentials_read"] and not report["authentication_attempted"]
    assert all(
        request.method == "GET" and not request.url.path.endswith("/login") for request in requests
    )
    for private in (
        "192.0.2.10",
        "portal.example.test",
        "@synthetic-private-suffix",
        "synthetic-secret-network-detail",
    ):
        assert private not in json.dumps(report)


def test_verified_tls_is_reported_without_claiming_authentication():
    client, _ = make_inspection_client()
    report = inspect_eportal(
        "http://portal.example.test/a79.htm",
        "http://portal.example.test:801",
        ("192.0.2.10",),
        client_factory=client,
    )
    assert report["configured_https_api"]["certificate_verified"]
    assert not report["configured_https_api"]["authentication_verified"]


def test_read_only_inspection_refuses_redirect_without_following_it():
    client, requests = make_inspection_client(redirect=True)
    with pytest.raises(InspectionError):
        inspect_eportal(
            "http://portal.example.test/a79.htm",
            "http://portal.example.test:801",
            ("192.0.2.10",),
            client_factory=client,
        )
    assert len(requests) == 1


def test_other_hosts_and_paths_are_rejected_before_network():
    client, requests = make_inspection_client()
    for page, api in (
        ("http://portal.example.test/login", "http://portal.example.test:801"),
        ("http://portal.example.test/a79.htm", "http://evil.example.test:801"),
    ):
        with pytest.raises(InspectionError):
            inspect_eportal(page, api, ("192.0.2.10",), client_factory=client)
    assert not requests


def test_other_configuration_modes_stop_before_tls_candidate_checks():
    from campus_autoconnect.core.errors import CampusError

    client, requests = make_inspection_client(config_change=True)
    with pytest.raises(CampusError):
        inspect_eportal(
            "http://portal.example.test/a79.htm",
            "http://portal.example.test:801",
            ("192.0.2.10",),
            client_factory=client,
        )
    assert len(requests) == 2


def test_read_only_inspector_can_observe_placeholders_without_granting_login_permission():
    client, requests = make_inspection_client(zero_context=True)
    report = inspect_eportal(
        "http://portal.example.test/a79.htm",
        "http://portal.example.test:801",
        ("192.0.2.10",),
        client_factory=client,
    )
    assert report["zero_mac_observed"] and report["zero_vlan_observed"]
    assert report["login_requires_zero_mac_profile_permission"]
    assert not report["authentication_attempted"]
    assert requests[1].url.params["wlan_vlan_id"] == "0"
    assert all(not request.url.path.endswith("/login") for request in requests)
