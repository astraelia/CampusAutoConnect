import socket
import ssl
import threading

import httpx
import pytest

from campus_autoconnect.core.models import ErrorCode, ProbeEndpoint
from campus_autoconnect.core.observation import OperationTrace
from campus_autoconnect.services.connectivity import ConnectivityService, make_client

pytestmark = pytest.mark.mock

ENDPOINTS = (
    ProbeEndpoint("http://one.example.test/check", 200, b"expected-one"),
    ProbeEndpoint("https://two.example.test/check", 204, b""),
)


def test_two_content_checks_needed_for_online():
    def respond(request):
        if request.url.host == "one.example.test":
            return httpx.Response(200, content=b"expected-one")
        return httpx.Response(204)

    result = ConnectivityService(ENDPOINTS, transport=httpx.MockTransport(respond)).check()
    assert result.online
    single = ConnectivityService(ENDPOINTS[:1], transport=httpx.MockTransport(respond)).check()
    assert not single.online


def test_200_wrong_body_not_success():
    service = ConnectivityService(
        ENDPOINTS, transport=httpx.MockTransport(lambda _: httpx.Response(200, content=b"login"))
    )
    assert not service.check().online


def test_redirect_discovered_not_followed():
    seen = []

    def respond(request):
        seen.append(str(request.url))
        return httpx.Response(
            302, headers={"location": "https://portal.example.edu/login?token=fake"}
        )

    result = ConnectivityService(ENDPOINTS, transport=httpx.MockTransport(respond)).check()
    assert result.portal_url == "https://portal.example.edu/login?token=fake"
    assert sorted(seen) == sorted(p.url for p in ENDPOINTS)


def test_meta_refresh_detected():
    html = b'<meta http-equiv="refresh" content="0; url=https://portal.example.edu/login">'
    service = ConnectivityService(
        ENDPOINTS, transport=httpx.MockTransport(lambda _: httpx.Response(200, content=html))
    )
    assert service.check().portal_url == "https://portal.example.edu/login"


@pytest.mark.parametrize(
    "kind,code",
    [
        ("timeout", ErrorCode.TIMEOUT),
        ("dns", ErrorCode.DNS_ERROR),
        ("tls", ErrorCode.TLS_ERROR),
        ("network", ErrorCode.NETWORK_UNREACHABLE),
    ],
)
def test_network_failures_distinguished(kind, code):
    def fail(request):
        if kind == "timeout":
            raise httpx.ReadTimeout("synthetic", request=request)
        if kind == "dns":
            raise httpx.ConnectError("synthetic", request=request) from socket.gaierror(
                -2, "synthetic"
            )
        if kind == "tls":
            raise httpx.ConnectError("synthetic", request=request) from ssl.SSLError("synthetic")
        raise httpx.ConnectError("synthetic", request=request)

    result = ConnectivityService(ENDPOINTS, transport=httpx.MockTransport(fail)).check()
    assert not result.online
    assert result.code == code


def test_server_error_and_oversized_body():
    server = ConnectivityService(
        ENDPOINTS, transport=httpx.MockTransport(lambda _: httpx.Response(503))
    )
    assert server.check().code == ErrorCode.SERVER_ERROR
    large = ConnectivityService(
        ENDPOINTS,
        transport=httpx.MockTransport(lambda _: httpx.Response(200, content=b"x" * 20000)),
    )
    assert large.check().code == ErrorCode.PORTAL_UNRECOGNIZED


def test_client_never_inherits_proxy_or_follows_redirects(monkeypatch):
    monkeypatch.setenv("HTTP_PROXY", "http://127.0.0.1:1")
    monkeypatch.setenv("HTTPS_PROXY", "http://127.0.0.1:1")
    monkeypatch.setenv("ALL_PROXY", "http://127.0.0.1:1")
    with make_client() as client:
        assert client.trust_env is False
        assert client.follow_redirects is False
        assert not client._mounts
        assert client._transport._pool._ssl_context.verify_mode == ssl.CERT_REQUIRED


def test_cancel_before_request(cancel):
    cancel.set()
    service = ConnectivityService(
        ENDPOINTS, transport=httpx.MockTransport(lambda _: pytest.fail("must not request"))
    )
    assert service.check(cancel).code == ErrorCode.CANCELLED


def test_no_redirect_location_does_not_create_target():
    service = ConnectivityService(
        ENDPOINTS, transport=httpx.MockTransport(lambda _: httpx.Response(302))
    )
    assert service.check().portal_url is None


def test_compressed_untrusted_probe_is_not_decompressed():
    import gzip

    service = ConnectivityService(
        ENDPOINTS,
        transport=httpx.MockTransport(
            lambda _: httpx.Response(
                200,
                content=gzip.compress(b"x" * 20000),
                headers={"content-encoding": "gzip"},
            )
        ),
    )
    assert not service.check().online


def test_probes_overlap_but_results_keep_endpoint_order_and_trace_context():
    barrier = threading.Barrier(2)

    def respond(request):
        barrier.wait(timeout=2)  # Sequential execution cannot pass this condition.
        if request.url.host == "one.example.test":
            return httpx.Response(302, headers={"location": "https://portal.example.edu/login"})
        return httpx.Response(204)

    trace = OperationTrace()
    token = trace.begin("check")
    try:
        result = ConnectivityService(ENDPOINTS, transport=httpx.MockTransport(respond)).check()
    finally:
        trace.end(token)
    assert not result.online
    assert result.portal_url == "https://portal.example.edu/login"
    assert not result.observations[0].expected and result.observations[1].expected
    events = trace.snapshot()
    assert sum(e["event"] == "http_start" for e in events) == 2
    assert len({e["operation_id"] for e in events}) == 1


def test_tls_failure_cannot_be_masked_by_other_probe_timeout():
    def fail(request):
        if request.url.scheme == "http":
            raise httpx.ReadTimeout("synthetic", request=request)
        raise httpx.ConnectError("synthetic", request=request) from ssl.SSLError("synthetic")

    result = ConnectivityService(ENDPOINTS, transport=httpx.MockTransport(fail)).check()
    assert result.code == ErrorCode.TLS_ERROR and not result.online


def test_cancel_during_parallel_probes_drains_workers_before_returning():
    cancel = threading.Event()
    barrier = threading.Barrier(2)
    completed = []

    def respond(request):
        barrier.wait(timeout=2)
        cancel.set()
        completed.append(request.url.host)
        return httpx.Response(204)

    result = ConnectivityService(ENDPOINTS, transport=httpx.MockTransport(respond)).check(cancel)
    assert result.code == ErrorCode.CANCELLED and not result.online
    assert len(completed) == 2
