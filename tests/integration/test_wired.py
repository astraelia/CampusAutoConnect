import json
from dataclasses import replace
from urllib.parse import urlsplit

import httpx
import pytest

from campus_autoconnect.adapters.bjut_wired import BJUTWiredAdapter
from campus_autoconnect.core.models import (
    BJUT_WIRED_ADAPTER,
    AuthState,
    ConnectivityResult,
    ErrorCode,
    LinkType,
    NetworkAdapter,
    NetworkSnapshot,
)
from campus_autoconnect.core.portal import BJUT_WIRED_HOST, BJUT_WIRED_PAGE, BJUT_WIRED_URL
from campus_autoconnect.core.profiles import new_wired_profile
from campus_autoconnect.services.application import ApplicationServices
from campus_autoconnect.services.authentication import AuthenticationService
from campus_autoconnect.services.automation import readiness
from campus_autoconnect.services.connectivity import ConnectivityService, make_client
from campus_autoconnect.services.inspection_records import Outcome, Step
from campus_autoconnect.services.support import SupportService

pytestmark = pytest.mark.mock


@pytest.fixture
def ethernet():
    return NetworkAdapter(
        12,
        "Test Ethernet",
        "00000000-0000-0000-0000-000000000012",
        True,
        ipv4=("198.51.100.20",),
        gateways=("198.51.100.1",),
        link_type=LinkType.ETHERNET,
    )


@pytest.fixture
def gateway(ethernet, network, profiles, credentials):
    profile = new_wired_profile(ethernet, BJUT_WIRED_URL)
    network.current = NetworkSnapshot((ethernet,))
    profiles.upsert(profile)
    fixture = {
        "profile": profile,
        "status": 0,
        "page_ip": ethernet.ipv4[0],
        "config": {"program_index": "test", "page_index": "1", "login_method": "0"},
        "login_result": 1,
        "login_requests": [],
        "ready": False,
        "probe_source": None,
        "template": (
            '<form name="f0"><input type="hidden" name="R1" value="0"></form>'
            '<form name="f1"><input name="DDDDD"><input name="upass" type="password"></form>'
        ),
    }

    def jsonp(callback, body):
        return httpx.Response(200, content=f"{callback}({json.dumps(body)});".encode())

    def handle(request):
        path = request.url.path
        params = request.url.params
        if request.url.host != BJUT_WIRED_HOST:

            class ProbeStream:
                def get_extra_info(self, name):
                    if name == "client_addr":
                        return fixture["probe_source"], 10000
                    return "192.0.2.50", 443

            extensions = (
                {"network_stream": ProbeStream()} if fixture["probe_source"] is not None else {}
            )
            if path == "/connecttest.txt":
                if fixture["ready"]:
                    return httpx.Response(
                        200, content=b"Microsoft Connect Test", extensions=extensions
                    )
                return httpx.Response(
                    302, headers={"Location": f"http://{BJUT_WIRED_HOST}/?url=hidden"}
                )
            return httpx.Response(204, extensions=extensions)
        assert request.url.scheme == "https" and request.method == "GET"
        assert "proxy-authorization" not in request.headers
        if path == "/a79.htm":
            html = (
                "<title>上网登录页</title><script>"
                f'v46ip="{fixture["page_ip"]}";vlanid="0";'
                "fileVersion=1776917363858;authexenable=0;</script>"
            )
            return httpx.Response(200, content=html.encode("gb18030"))
        if path == "/drcom/chkstatus":
            return jsonp(params["callback"], {"result": fixture["status"]})
        if path == "/eportal/portal/page/loadConfig":
            assert request.url.port == 802 and params["encrypt"] == "1"
            assert params["wlan_vlan_id"] == "26"
            assert params["callback"].startswith("7264")
            callback = "".join(chr(byte ^ 22) for byte in bytes.fromhex(params["callback"]))
            return jsonp(callback, {"code": 1, "data": fixture["config"]})
        if path == "/eportal/extern/test/1/pc.js":
            assert request.url.port == 802
            version = "jsVersion='4.2.1';"
            return httpx.Response(
                200,
                content=(
                    version + "var bodyContent=" + json.dumps(fixture["template"]) + ";"
                ).encode(),
            )
        if path == "/drcom/login":
            fixture["login_requests"].append(params)
            fixture["ready"] = fixture["login_result"] in (1, "ok")
            return jsonp(params["callback"], {"result": fixture["login_result"]})
        pytest.fail("模拟网关收到意外路径")

    transport = httpx.MockTransport(handle)
    fixture["auth"] = AuthenticationService(
        network,
        profiles,
        credentials,
        ConnectivityService(transport=transport),
        adapters={
            BJUT_WIRED_ADAPTER: lambda: BJUTWiredAdapter(lambda: make_client(transport=transport))
        },
    )
    return fixture


def test_ready_ethernet_has_priority_and_unplug_returns_to_wifi(ethernet, snapshot):
    both = NetworkSnapshot((*snapshot.adapters, ethernet))
    assert both.selection == LinkType.ETHERNET
    assert readiness(both)[0] is None
    assert (
        NetworkSnapshot((*snapshot.adapters, replace(ethernet, connected=False))).selected
        == snapshot.wifi
    )
    assert (
        NetworkSnapshot((*snapshot.adapters, replace(ethernet, ipv4=("169.254.10.2",)))).selected
        == snapshot.wifi
    )
    another = replace(ethernet, index=13, guid="00000000-0000-0000-0000-000000000013")
    assert NetworkSnapshot((*both.adapters, another)).selected is None
    assert NetworkSnapshot((replace(ethernet, hardware=False),)).selected is None


def test_wired_profile_coexists_with_legacy_wifi_and_requires_same_gateway(
    gateway, profiles, network, snapshot
):
    profile = gateway["profile"]
    both = NetworkSnapshot((*snapshot.adapters, *network.current.adapters))
    assert profiles.match_network(both) == profile
    assert profiles.match_network(snapshot).ssid == snapshot.ssid
    (wire,) = network.current.adapters
    changed = replace(wire, gateways=("198.51.100.99",))
    assert profiles.match_network(NetworkSnapshot((*snapshot.adapters, changed))) is None
    profiles.upsert(replace(profile, enabled=False))
    assert profiles.match_network(both) is None


@pytest.mark.parametrize("url", [BJUT_WIRED_URL, BJUT_WIRED_PAGE])
def test_save_and_wired_login_use_same_preparation(gateway, profiles, credentials, url):
    auth = gateway["auth"]
    app = ApplicationServices(profiles, credentials, auth)
    saved = app.save_profile_and_check(replace(gateway["profile"], portal_page_url=url))
    assert saved.state == AuthState.AUTH_REQUIRED
    assert saved.progress.login_request_attempted is False
    assert credentials.reads == 0 and not gateway["login_requests"]
    assert app.diagnostics()["links"]["selected_link"] == "ethernet"
    result = auth.login()
    assert result.state == AuthState.AUTHENTICATED and result.code == ErrorCode.NONE
    assert result.progress.login_request_attempted is True
    assert credentials.reads == 1
    (params,) = gateway["login_requests"]
    assert params["DDDDD"] == credentials.values["shared"].username
    assert params["upass"] == credentials.values["shared"].password
    assert params["v4ip"] == gateway["page_ip"]
    assert params["R1"] == "0" and params["R6"] == "0"
    assert params.get_list("lang") == ["zh-cn", "zh"]
    assert auth.login().code == ErrorCode.ALREADY_AUTHENTICATED
    assert len(gateway["login_requests"]) == credentials.reads == 1


def test_user_supplied_wired_url_is_retained_without_guessing_protocol(
    gateway, ethernet, profiles, credentials, monkeypatch
):
    new = new_wired_profile(ethernet, "https://gateway.example.edu:8443/login")
    profiles.remove(gateway["profile"].profile_id)
    auth = gateway["auth"]
    app = ApplicationServices(profiles, credentials, auth)
    monkeypatch.setattr(auth.connectivity, "check", lambda *_: ConnectivityResult())
    result = app.save_profile_and_check(new)
    assert profiles.list()[-1].portal_page_url == "https://gateway.example.edu:8443/login"
    assert result.code == ErrorCode.PROTOCOL_UNVERIFIED
    assert auth.login().code == ErrorCode.PROTOCOL_UNVERIFIED
    assert credentials.reads == 0 and not gateway["login_requests"]


@pytest.mark.parametrize(
    "field,value,code",
    [
        ("page_ip", "198.51.100.99", ErrorCode.SESSION_IP_MISMATCH),
        ("status", 1, ErrorCode.ALREADY_AUTHENTICATED),
        ("config", {"login_method": 1}, ErrorCode.PROTOCOL_CHANGED),
        ("config", {"login_method": 0, "needCaptcha": "1"}, ErrorCode.MANUAL_ACTION),
        ("template", '<form><input name="C1"></form>', ErrorCode.MANUAL_ACTION),
    ],
)
def test_wired_preflight_blocks_before_credentials(gateway, credentials, field, value, code):
    gateway[field] = value
    assert gateway["auth"].login().code == code
    assert credentials.reads == 0 and not gateway["login_requests"]


def test_ethernet_switch_just_before_submission_cancels_old_login(
    gateway, network, credentials, snapshot, monkeypatch
):
    get = credentials.get

    def change(reference):
        result = get(reference)
        network.current = snapshot
        return result

    monkeypatch.setattr(credentials, "get", change)
    result = gateway["auth"].login()
    assert result.code == ErrorCode.NETWORK_CHANGED
    assert result.progress.login_request_attempted is False
    assert not gateway["login_requests"]


def test_wired_link_does_not_claim_other_interfaces_internet(gateway, network, credentials):
    gateway["ready"] = (
        True  # Windows can probe successfully while another interface carries traffic.
    )
    network.route_safe = False
    result = gateway["auth"].login()
    assert result.state == AuthState.UNKNOWN and result.code == ErrorCode.ROUTE_UNCONFIRMED
    assert credentials.reads == 0 and not gateway["login_requests"]


def test_online_probe_verifies_the_socket_address_and_route(
    gateway, network, ethernet, monkeypatch
):
    gateway["ready"] = True
    gateway["probe_source"] = "192.0.2.10"
    monkeypatch.setattr(
        network, "route_allows", lambda url, _: urlsplit(url).hostname == "192.0.2.50"
    )
    assert gateway["auth"].check().code == ErrorCode.ROUTE_UNCONFIRMED
    gateway["probe_source"] = ethernet.ipv4[0]
    assert gateway["auth"].check().code == ErrorCode.ALREADY_AUTHENTICATED


def test_full_diagnostics_records_live_preparation_without_credentials(
    gateway, profiles, credentials, tmp_path, cancel, monkeypatch
):
    class IndependentChecks:
        def __init__(self, directory, emit, *, run):
            self.emit = emit
            self.run = run

        def context(self):
            self.emit(Step("system", "系统", Outcome.PASS, "mock", "", run=self.run))

        def inspect(self, cancel):
            self.emit(Step("network", "网络", Outcome.PASS, "mock", "", run=self.run))

    monkeypatch.setattr("campus_autoconnect.services.support.InspectionRunner", IndependentChecks)
    auth = gateway["auth"]
    support = SupportService(tmp_path, auth, tmp_path / "reports")
    app = ApplicationServices(profiles, credentials, auth, support=support)
    try:
        report = app.diagnose(cancel)
    finally:
        support.close()
    assert {step["key"] for step in report["independent_steps"]} == {"system", "network"}
    preparation = report["diagnostic"]["deep_check"]
    assert preparation["state"] == AuthState.AUTH_REQUIRED
    assert preparation["links"]["selected_link"] == "ethernet"
    assert preparation["authentication"]["credential_read_attempted"] is False
    assert credentials.reads == 0 and not gateway["login_requests"]
    assert gateway["page_ip"] not in json.dumps(report)


def test_http_success_with_unknown_jsonp_status_does_not_mean_login(gateway, credentials):
    gateway["login_result"] = "other"
    result = gateway["auth"].login()
    assert result.code == ErrorCode.PROTOCOL_CHANGED and result.state == AuthState.AUTH_FAILED
    assert len(gateway["login_requests"]) == credentials.reads == 1
