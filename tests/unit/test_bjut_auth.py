"""Production adapter with synthetic ePortal responses, never real school secrets."""

import json
import logging
import ssl
from dataclasses import replace

import httpx
import pytest

from campus_autoconnect.adapters.bjut import BJUTPortalAdapter
from campus_autoconnect.adapters.eportal import CONFIG_PATH, LOGIN_PATH
from campus_autoconnect.core.errors import CampusError
from campus_autoconnect.core.models import (
    AuthStage,
    AuthState,
    ConnectivityResult,
    Credentials,
    ErrorCode,
    ProfileIssue,
)
from campus_autoconnect.core.portal import normalize_bjut_endpoints, validate_target
from campus_autoconnect.services.authentication import AuthenticationService
from campus_autoconnect.services.connectivity import make_client
from tests.unit.test_authentication import SequenceConnectivity

pytestmark = pytest.mark.mock


@pytest.fixture
def http_profile(profile):
    return replace(
        profile,
        portal_page_url="http://portal.example.edu/a79.htm",
        bjut_api_origin="http://portal.example.edu:801",
        allow_http_auth=True,
    )


@pytest.fixture
def portal_payload():
    return {
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
            "account_suffix": "@synthetic-school",
            "enable_https": "0",
            "ep_http_port": "801",
            "ep_https_port": "802",
            "domain_name": "",
        },
    }


@pytest.fixture
def bjut_service(network, profiles, credentials, http_profile, portal_payload):
    profiles.upsert(http_profile)
    requests = []
    modes = {"mode": "success"}

    def handle(request):
        requests.append(request)
        if request.url.path == "/a79.htm":
            assert "user_account" not in request.url.params
            assert "user_password" not in request.url.params
            body = b"var v46ip='192.0.2.10';var ss4='020000000007';var vlanid='12';"
            if modes["mode"] == "wrong_ip":
                body = body.replace(b"192.0.2.10", b"192.0.2.11")
            if modes.get("zero_context"):
                body = body.replace(b"020000000007", b"000000000000").replace(
                    b"vlanid='12'", b"vlanid='0'"
                )
            return httpx.Response(
                200, content=body, headers={"set-cookie": "synthetic_session=one"}
            )
        callback = request.url.params["callback"]
        if request.url.path == CONFIG_PATH:
            assert "user_password" not in request.url.params
            assert "synthetic_session=one" in request.headers.get("cookie", "")
            return httpx.Response(
                200, content=(callback + "(" + json.dumps(portal_payload) + ")").encode()
            )
        assert request.url.path == LOGIN_PATH
        if modes["mode"] == "redirect":
            return httpx.Response(307, headers={"location": "http://evil.example.test/steal"})
        if modes["mode"] == "timeout":
            raise httpx.ReadTimeout("synthetic-private-password-url", request=request)
        if modes["mode"] == "server_error":
            return httpx.Response(503, content=b"synthetic-private-server-body")
        if modes["mode"] == "wrong_callback":
            callback = "dr000000"
        if modes["mode"] == "oversize":
            return httpx.Response(200, content=b"x" * 131073)
        result = {"rejected": 0, "unknown": "ok", "boolean": True}.get(modes["mode"], 1)
        body = callback + "(" + json.dumps({"result": result, "msg": "PRIVATE_RESPONSE"}) + ");"
        return httpx.Response(200, content=body.encode())

    adapter = BJUTPortalAdapter(lambda: make_client(transport=httpx.MockTransport(handle)))
    connectivity = SequenceConnectivity(
        ConnectivityResult(portal_url=http_profile.portal_page_url), ConnectivityResult(online=True)
    )
    service = AuthenticationService(
        network, profiles, credentials, connectivity, {"bjut": lambda: adapter}
    )
    return service, requests, modes, adapter


def test_http_opt_in_submits_observed_request_once_and_verifies(bjut_service, credentials):
    service, requests, _, adapter = bjut_service
    result = service.login()
    assert result.state == AuthState.AUTHENTICATED
    assert credentials.reads == 1
    assert [r.url.path for r in requests] == ["/a79.htm", CONFIG_PATH, LOGIN_PATH]
    login = requests[-1]
    assert login.method == "GET" and login.url.port == 801
    assert login.url.params["user_account"] == "synthetic-account@synthetic-school"
    assert login.url.params["user_password"] == "synthetic-password-only-for-tests"
    assert login.url.params["wlan_user_ip"] == "192.0.2.10"
    assert login.url.params["wlan_user_mac"] == "020000000007"
    assert login.url.params["jsVersion"] == "4.2.1"
    assert login.url.params["terminal_type"] == "1"
    assert login.url.params.get_list("lang") == ["zh-cn", "zh"]
    assert "synthetic_session=one" in login.headers.get("cookie", "")
    assert "PRIVATE_RESPONSE" not in result.message
    assert not adapter.authenticate(str(login.url), credentials.values["shared"]).accepted
    assert len(requests) == 3


def test_http_without_explicit_permission_never_reads_credentials(
    bjut_service, profiles, http_profile, credentials
):
    service, requests, _, _ = bjut_service
    profiles.upsert(replace(http_profile, allow_http_auth=False))
    assert service.login().code == ErrorCode.UNTRUSTED_TARGET
    assert credentials.reads == 0 and not requests


@pytest.mark.parametrize(
    "url",
    [
        "http://evil.example.test/a79.htm",
        "http://portal.example.edu:802/eportal/portal/login",
        "http://portal.example.edu:801/unobserved",
        "http://user:secret@portal.example.edu/a79.htm",
        "http://portal.example.edu/a79.htm#fragment",
        "http://portal.example.edu:801/a79.htm",
    ],
)
def test_http_exception_is_limited_to_explicit_origins_and_paths(http_profile, url):
    with pytest.raises(CampusError):
        validate_target(url, http_profile)


@pytest.mark.parametrize(
    "page,api",
    [
        ("http://portal.example.edu/a79.htm", "https://portal.example.edu:802"),
        ("http://portal.example.edu/a79.htm", "http://evil.example.test:801"),
        ("http://portal.example.edu/a79.htm?token=x", "http://portal.example.edu:801"),
        ("http://portal.example.edu/a79.htm", "http://portal.example.edu:801/login"),
    ],
)
def test_endpoint_configuration_rejects_downgrades_and_ambiguous_input(page, api):
    with pytest.raises(ValueError):
        normalize_bjut_endpoints(page, api)


@pytest.mark.parametrize(
    "mode,code",
    [
        ("redirect", ErrorCode.UNTRUSTED_TARGET),
        ("timeout", ErrorCode.TIMEOUT),
        ("server_error", ErrorCode.SERVER_ERROR),
        ("wrong_callback", ErrorCode.PROTOCOL_CHANGED),
        ("oversize", ErrorCode.PROTOCOL_CHANGED),
        ("rejected", ErrorCode.MANUAL_ACTION),
        ("unknown", ErrorCode.PROTOCOL_CHANGED),
        ("boolean", ErrorCode.PROTOCOL_CHANGED),
    ],
)
def test_failed_login_never_retries_or_exposes_response(bjut_service, mode, code):
    service, requests, modes, adapter = bjut_service
    modes["mode"] = mode
    result = service.login()
    assert result.code == code and result.state == AuthState.AUTH_FAILED
    assert adapter.get_status() == AuthState.AUTH_FAILED
    assert sum(r.url.path == LOGIN_PATH for r in requests) == 1
    assert "PRIVATE" not in result.message and "synthetic" not in result.message


@pytest.mark.parametrize(
    "field,value",
    [("password_cut", "1"), ("ep_http_port", "802"), ("domain_name", "other.example.test")],
)
def test_changed_live_configuration_blocks_before_secret_read(
    bjut_service, portal_payload, credentials, field, value
):
    service, requests, _, _ = bjut_service
    portal_payload["data"][field] = value
    assert service.login().state == AuthState.AUTH_FAILED
    assert credentials.reads == 0
    assert all(r.url.path != LOGIN_PATH for r in requests)


def test_wrong_page_context_blocks_before_secret_read(bjut_service, credentials):
    service, requests, modes, _ = bjut_service
    modes["mode"] = "wrong_ip"
    assert service.login().code == ErrorCode.SESSION_IP_MISMATCH
    assert credentials.reads == 0 and len(requests) == 1


def test_explicit_page_fallback_handles_dns_failure_without_guessing(bjut_service):
    service, _, _, _ = bjut_service
    service.connectivity = SequenceConnectivity(
        ConnectivityResult(code=ErrorCode.DNS_ERROR), ConnectivityResult(online=True)
    )
    assert service.login().state == AuthState.AUTHENTICATED


def test_discovered_untrusted_redirect_is_not_replaced_by_configured_page(
    bjut_service, credentials
):
    service, requests, _, _ = bjut_service
    service.connectivity = SequenceConnectivity(
        ConnectivityResult(portal_url="http://evil.example.test/a79.htm")
    )
    assert service.login().code == ErrorCode.UNTRUSTED_TARGET
    assert credentials.reads == 0 and not requests


def test_acceptance_without_independent_internet_is_not_success(bjut_service):
    service, _, _, _ = bjut_service
    service.connectivity = SequenceConnectivity(
        ConnectivityResult(portal_url="http://portal.example.edu/a79.htm")
    )
    assert service.login().state == AuthState.UNKNOWN


def test_route_risk_blocks_before_page_or_credentials(bjut_service, network, credentials):
    service, requests, _, _ = bjut_service
    network.route_safe = False
    assert service.login().code == ErrorCode.ROUTE_UNCONFIRMED
    assert credentials.reads == 0 and not requests


def test_revoke_http_after_secret_read_prevents_request(
    bjut_service, profiles, http_profile, credentials, monkeypatch
):
    service, requests, _, _ = bjut_service
    get = credentials.get

    def revoke(reference):
        value = get(reference)
        profiles.upsert(replace(http_profile, allow_http_auth=False))
        return value

    monkeypatch.setattr(credentials, "get", revoke)
    assert service.login().code == ErrorCode.NETWORK_CHANGED
    assert credentials.reads == 1
    assert all(r.url.path != LOGIN_PATH for r in requests)


def test_cancellation_after_secret_read_prevents_request(
    bjut_service, credentials, cancel, monkeypatch
):
    service, requests, _, _ = bjut_service
    get = credentials.get

    def cancelled(reference):
        value = get(reference)
        cancel.set()
        return value

    monkeypatch.setattr(credentials, "get", cancelled)
    assert service.login(cancel).code == ErrorCode.CANCELLED
    assert all(r.url.path != LOGIN_PATH for r in requests)


def test_http_library_logs_never_include_get_credentials(bjut_service, caplog):
    service, _, _, _ = bjut_service
    with caplog.at_level(logging.DEBUG):
        assert service.login().state == AuthState.AUTHENTICATED
    assert "synthetic-password" not in caplog.text
    assert "user_password" not in caplog.text
    assert "synthetic-account" not in caplog.text


def test_https_certificate_error_does_not_fall_back_to_http(http_profile, portal_payload, snapshot):
    secure = replace(
        http_profile,
        portal_page_url="https://portal.example.edu/a79.htm",
        bjut_api_origin="https://portal.example.edu:802",
        trusted_portal_hosts=("portal.example.edu", "portal.example.edu:802"),
        allow_http_auth=False,
    )
    calls = []

    def fail(request):
        calls.append(request)
        raise httpx.ConnectError("PRIVATE_TLS_URL", request=request) from ssl.SSLError()

    adapter = BJUTPortalAdapter(lambda: make_client(transport=httpx.MockTransport(fail)))
    with pytest.raises(CampusError) as error:
        adapter.prepare(secure, snapshot, lambda _: None)
    assert error.value.code == ErrorCode.TLS_ERROR
    assert len(calls) == 1 and calls[0].url.scheme == "https"
    assert "PRIVATE_TLS_URL" not in error.value.message


def test_online_conclusion_is_invalidated_when_network_changes(bjut_service, network, snapshot):
    service, _, _, _ = bjut_service
    service.connectivity = SequenceConnectivity(ConnectivityResult(online=True))
    network.on_snapshot = lambda n: (
        setattr(network, "current", replace(snapshot, adapters=())) if n == 2 else None
    )
    assert service.check().code == ErrorCode.NETWORK_CHANGED


@pytest.mark.parametrize("username", ["synthetic-account", "synthetic-account@synthetic-school"])
def test_account_suffix_is_sent_exactly_once(bjut_service, credentials, username):
    service, requests, _, _ = bjut_service
    credentials.set("shared", Credentials(username, "synthetic-password"))
    result = service.login()
    assert result.state == AuthState.AUTHENTICATED
    assert credentials.reads == 1
    assert [r.url.path for r in requests].count(LOGIN_PATH) == 1
    assert requests[-1].url.params["user_account"] == "synthetic-account@synthetic-school"
    assert result.progress.credential_read_attempted is True
    assert result.progress.login_request_attempted is True


@pytest.mark.parametrize(
    "username",
    ["synthetic-account@other-school", "synthetic-account@synthetic-school@synthetic-school"],
)
def test_conflicting_or_repeated_suffix_stops_before_login(bjut_service, credentials, username):
    service, requests, _, _ = bjut_service
    credentials.set("shared", Credentials(username, "synthetic-password"))
    result = service.login()
    assert result.code == ErrorCode.MANUAL_ACTION
    assert result.progress.stage == AuthStage.SUBMIT
    assert result.progress.credential_read_attempted is True
    assert result.progress.login_request_attempted is False
    assert [r.url.path for r in requests] == ["/a79.htm", CONFIG_PATH]
    assert username not in result.message
    assert "synthetic-password" not in result.message


def test_legacy_http_profile_exposes_setup_gaps_without_secrets(
    bjut_service, profiles, http_profile, credentials
):
    from campus_autoconnect.services.application import ApplicationServices

    service, requests, _, _ = bjut_service
    profiles.upsert(
        replace(http_profile, portal_page_url="", bjut_api_origin="", allow_http_auth=False)
    )
    result = service.login()
    assert result.code == ErrorCode.UNTRUSTED_TARGET
    assert result.progress.stage == AuthStage.TARGET
    assert result.progress.profile_matched
    assert result.progress.profile_issues == (
        ProfileIssue.PAGE_MISSING,
        ProfileIssue.API_MISSING,
        ProfileIssue.HTTP_PERMISSION,
    )
    assert credentials.reads == 0 and not requests
    assert result.progress.credential_read_attempted is False
    assert result.progress.login_request_attempted is False
    app = ApplicationServices(profiles, credentials, service)
    app.record_result(result)
    diagnostic = json.dumps(app.diagnostics())
    assert all(
        secret not in diagnostic
        for secret in (
            "portal.example.edu",
            "Example-Campus",
            "192.0.2.10",
            "synthetic-account",
            "synthetic-password",
            '"shared"',
            '"dorm"',
        )
    )


@pytest.mark.parametrize(
    "mode,stage,paths",
    [
        ("wrong_ip", AuthStage.PREPARE, ["/a79.htm"]),
        ("timeout", AuthStage.SUBMIT, ["/a79.htm", CONFIG_PATH, LOGIN_PATH]),
    ],
)
def test_progress_distinguishes_preparation_from_a_login_attempt(
    bjut_service, credentials, mode, stage, paths
):
    service, requests, modes, _ = bjut_service
    modes["mode"] = mode
    result = service.login()
    assert result.progress.stage == stage
    assert [r.url.path for r in requests] == paths
    assert result.progress.credential_read_attempted == (mode == "timeout")
    assert result.progress.login_request_attempted == (mode == "timeout")
    assert credentials.reads == (1 if mode == "timeout" else 0)


def test_acceptance_without_internet_is_reported_at_verification(bjut_service):
    service, requests, _, _ = bjut_service
    service.connectivity.results[-1] = ConnectivityResult()
    result = service.login()
    assert result.state == AuthState.UNKNOWN
    assert result.progress.stage == AuthStage.VERIFY
    assert result.progress.login_request_attempted is True
    assert [r.url.path for r in requests].count(LOGIN_PATH) == 1


def test_a_prior_submission_does_not_contaminate_the_next_blocked_operation(
    bjut_service, profiles, http_profile
):
    service, _, _, _ = bjut_service
    assert service.login().progress.login_request_attempted is True
    service.connectivity.results = [ConnectivityResult(portal_url=http_profile.portal_page_url)]
    profiles.upsert(replace(http_profile, allow_http_auth=False))
    result = service.login()
    assert result.code == ErrorCode.UNTRUSTED_TARGET
    assert result.progress.login_request_attempted is False
    assert result.progress.credential_read_attempted is False


@pytest.mark.parametrize("allowed", [False, True])
def test_zero_context_uses_only_explicit_profile_permission(
    bjut_service, profiles, http_profile, credentials, allowed
):
    service, requests, modes, _ = bjut_service
    modes["zero_context"] = True
    profiles.upsert(replace(http_profile, allow_zero_mac=allowed))
    result = service.login()
    assert result.progress.zero_mac_observed is True
    assert result.progress.zero_mac_allowed is allowed
    if not allowed:
        assert result.code == ErrorCode.ZERO_MAC_PERMISSION_REQUIRED
        assert len(requests) == 1 and credentials.reads == 0
        assert result.progress.login_request_attempted is False
    else:
        assert result.state == AuthState.AUTHENTICATED
        assert result.progress.zero_vlan_observed is True
        assert requests[1].url.params["wlan_vlan_id"] == "0"
        assert requests[2].url.params["wlan_user_mac"] == "000000000000"
        assert len(requests) == 3 and credentials.reads == 1
        assert "000000000000" not in json.dumps(result.progress.diagnostic())


@pytest.mark.parametrize("failure", ["wrong_ip", "revoke", "route", "config"])
def test_zero_context_never_skips_other_submission_gates(
    bjut_service, profiles, http_profile, credentials, network, portal_payload, monkeypatch, failure
):
    service, requests, modes, _ = bjut_service
    approved = replace(http_profile, allow_zero_mac=True)
    profiles.upsert(approved)
    modes["zero_context"] = True
    if failure == "wrong_ip":
        modes["mode"] = "wrong_ip"
    elif failure == "route":
        network.route_safe = False
    elif failure == "config":
        portal_payload["data"]["en_md5"] = "1"
    else:
        get = credentials.get

        def revoke(reference):
            value = get(reference)
            profiles.upsert(replace(approved, allow_zero_mac=False))
            return value

        monkeypatch.setattr(credentials, "get", revoke)
    result = service.login()
    assert result.state == AuthState.AUTH_FAILED
    assert all(r.url.path != LOGIN_PATH for r in requests)
    assert result.progress.login_request_attempted is False
    assert credentials.reads == (1 if failure == "revoke" else 0)
