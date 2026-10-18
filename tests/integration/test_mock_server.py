"""Real local TLS sockets + synthetic protocol. No actual campus authentication."""

import json
import ssl
import threading
import time
from contextlib import suppress
from dataclasses import replace
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import httpx
import pytest
import trustme

from campus_autoconnect.adapters.bjut import BJUTPortalAdapter
from campus_autoconnect.core.models import AuthState, ErrorCode, ProbeEndpoint
from campus_autoconnect.infrastructure.automation import AutomationStore
from campus_autoconnect.services.authentication import AuthenticationService
from campus_autoconnect.services.automation import AutomationCoordinator, AutomationPolicy
from campus_autoconnect.services.connectivity import ConnectivityService
from tests.mocks.portal_adapter import SyntheticPortalAdapter

pytestmark = pytest.mark.mock


class LocalPortal:
    def __init__(self):
        self.online = False
        self.mode = "success"
        self.login_calls = 0
        self.paths = []


@pytest.fixture
def portal_server():
    portal = LocalPortal()

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass  # No raw request logs, even in tests.

        def _reply(self, status, body=b"", **headers):
            self.send_response(status)
            self.send_header("Content-Length", str(len(body)))
            for key, value in headers.items():
                self.send_header(key, value)
            self.end_headers()
            with suppress(BrokenPipeError, ConnectionResetError, ssl.SSLError):
                self.wfile.write(body)

        def do_GET(self):
            portal.paths.append(self.path)
            if self.path == "/loop":
                self._reply(302, Location="/loop")
            elif self.path == "/probe-one" and portal.online:
                self._reply(200, b"expected-one")
            elif self.path == "/probe-two" and portal.online:
                self._reply(204)
            else:
                self._reply(302, Location=f"https://localhost:{self.server.server_port}/mock-login")

        def do_POST(self):
            portal.login_calls += 1
            portal.paths.append(self.path)
            size = int(self.headers.get("Content-Length", "0"))
            payload = json.loads(self.rfile.read(size))
            if portal.mode == "redirect":
                self._reply(307, Location="https://untrusted.example.test/steal")
            elif portal.mode == "server_error":
                self._reply(503)
            elif portal.mode == "timeout":
                time.sleep(0.4)
                self._reply(200, b'{"ok":true}')
            elif portal.mode == "malformed":
                self._reply(200, b"not JSON")
            elif portal.mode in {"captcha", "changed", "bad_credentials"}:
                self._reply(200, json.dumps({"ok": False, "error": portal.mode}).encode())
            elif (
                payload.get("username") == "synthetic-account"
                and payload.get("password") == "synthetic-password-only-for-tests"
            ):
                portal.online = portal.mode != "accepted_without_internet"
                self._reply(200, b'{"ok":true}')
            else:
                self._reply(200, b'{"ok":false,"error":"bad_credentials"}')

    ca = trustme.CA()
    certificate = ca.issue_cert("localhost", "127.0.0.1")
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    certificate.configure_cert(context)
    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    server.daemon_threads = True
    server.socket = context.wrap_socket(server.socket, server_side=True)
    client_context = ssl.create_default_context()
    ca.configure_trust(client_context)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    portal.port = server.server_port
    portal.client_context = client_context
    try:
        yield portal
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


@pytest.fixture
def integration_service(portal_server, network, profiles, profile, credentials):
    portal = portal_server
    profiles.upsert(replace(profile, trusted_portal_hosts=(f"localhost:{portal.port}",)))

    def client():
        return httpx.Client(
            verify=portal.client_context,
            trust_env=False,
            follow_redirects=False,
            timeout=0.15,
        )

    endpoints = (
        ProbeEndpoint(f"http://127.0.0.1:{portal.port}/unused", 200, b"expected-one"),
        ProbeEndpoint(f"https://localhost:{portal.port}/probe-two", 204, b""),
    )
    # Both probes use TLS against the same local server, with two synthetic hosts.
    endpoints = (
        replace(endpoints[0], url=f"https://127.0.0.1:{portal.port}/probe-one"),
        endpoints[1],
    )
    adapter = SyntheticPortalAdapter(client)
    service = AuthenticationService(
        network,
        profiles,
        credentials,
        ConnectivityService(endpoints, client_factory=client),
        {"bjut": lambda: adapter},
    )
    return service


def test_local_tls_full_manual_authentication(
    integration_service, portal_server, credentials, monkeypatch
):
    monkeypatch.setenv("HTTPS_PROXY", "http://127.0.0.1:1")
    monkeypatch.setenv("HTTP_PROXY", "http://127.0.0.1:1")
    result = integration_service.login()
    assert result.state == AuthState.AUTHENTICATED
    assert portal_server.login_calls == 1
    assert credentials.reads == 1
    assert portal_server.paths.count("/mock-login") == 1
    # A second manual click detects existing connectivity and never logs in again.
    assert integration_service.login().code == ErrorCode.ALREADY_AUTHENTICATED
    assert portal_server.login_calls == credentials.reads == 1


@pytest.mark.parametrize(
    "mode,code",
    [
        ("bad_credentials", ErrorCode.INVALID_CREDENTIALS),
        ("captcha", ErrorCode.MANUAL_ACTION),
        ("changed", ErrorCode.PROTOCOL_CHANGED),
        ("malformed", ErrorCode.PROTOCOL_CHANGED),
        ("server_error", ErrorCode.SERVER_ERROR),
        ("timeout", ErrorCode.TIMEOUT),
        ("redirect", ErrorCode.UNTRUSTED_TARGET),
    ],
)
def test_local_tls_failure_categories(integration_service, portal_server, mode, code):
    portal_server.mode = mode
    result = integration_service.login()
    assert result.state == AuthState.AUTH_FAILED
    assert result.code == code
    assert portal_server.login_calls == 1
    assert all("steal" not in path for path in portal_server.paths)


def test_accepted_response_without_internet_is_unknown(integration_service, portal_server):
    portal_server.mode = "accepted_without_internet"
    assert integration_service.login().state == AuthState.UNKNOWN


def test_tls_untrusted_ca_is_not_disabled(portal_server):
    service = ConnectivityService(
        (
            ProbeEndpoint(
                f"https://localhost:{portal_server.port}/probe-one", 200, b"expected-one"
            ),
            ProbeEndpoint(f"https://127.0.0.1:{portal_server.port}/probe-two", 204, b""),
        )
    )
    result = service.check()
    assert not result.online
    assert result.code == ErrorCode.TLS_ERROR
    assert portal_server.login_calls == 0


def test_redirect_loop_never_followed(portal_server):
    def client():
        return httpx.Client(
            verify=portal_server.client_context, trust_env=False, follow_redirects=False
        )

    result = ConnectivityService(
        (ProbeEndpoint(f"https://localhost:{portal_server.port}/loop", 200, b""),),
        client_factory=client,
    ).check()
    assert not result.online
    assert result.portal_url.endswith("/loop")
    assert portal_server.paths == ["/loop"]


@pytest.mark.parametrize(
    "mode,expected_calls,code",
    [
        ("success", 1, ErrorCode.ALREADY_AUTHENTICATED),
        ("server_error", 3, ErrorCode.SERVER_ERROR),
        ("timeout", 3, ErrorCode.TIMEOUT),
        ("bad_credentials", 1, ErrorCode.INVALID_CREDENTIALS),
        ("captcha", 1, ErrorCode.MANUAL_ACTION),
        ("changed", 1, ErrorCode.PROTOCOL_CHANGED),
        ("redirect", 1, ErrorCode.UNTRUSTED_TARGET),
    ],
)
def test_m2_coordinator_against_real_local_tls_sockets(
    integration_service,
    portal_server,
    profiles,
    credentials,
    tmp_path,
    mode,
    expected_calls,
    code,
):
    portal_server.mode = mode
    selected = replace(profiles.list()[0], auto_auth=True)
    profiles.upsert(selected)
    settings = AutomationStore(tmp_path / "automation.json")
    settings.set_enabled(True)
    now = [100.0]
    coordinator = AutomationCoordinator(
        integration_service,
        profiles,
        settings,
        policy=AutomationPolicy(settle_seconds=0, retry_delays=(1, 2)),
        clock=lambda: now[0],
    )
    coordinator.observe(integration_service.network.snapshot(), selected, enabled=True)
    try:
        for _ in range(4):
            coordinator.tick()
            deadline = time.monotonic() + 3
            while coordinator.working and time.monotonic() < deadline:
                time.sleep(0.003)
                coordinator.tick()
            assert not coordinator.working
            now[0] += 100
        assert portal_server.login_calls == expected_calls
        assert credentials.reads == expected_calls
        assert coordinator.code == code
        assert all("steal" not in path for path in portal_server.paths)
    finally:
        coordinator.stop()


def test_m2_real_bjut_adapter_still_blocks_before_credentials(
    integration_service, portal_server, profiles, credentials, tmp_path
):
    integration_service.adapters = {"bjut": BJUTPortalAdapter}
    selected = replace(profiles.list()[0], auto_auth=True)
    profiles.upsert(selected)
    settings = AutomationStore(tmp_path / "automation.json")
    settings.set_enabled(True)
    coordinator = AutomationCoordinator(
        integration_service, profiles, settings, policy=AutomationPolicy(settle_seconds=0)
    )
    coordinator.observe(integration_service.network.snapshot(), selected, enabled=True)
    coordinator.tick()
    deadline = time.monotonic() + 3
    while coordinator.working and time.monotonic() < deadline:
        time.sleep(0.003)
        coordinator.tick()
    assert not coordinator.working
    assert coordinator.code == ErrorCode.PROTOCOL_UNVERIFIED
    assert credentials.reads == portal_server.login_calls == 0
    coordinator.stop()
