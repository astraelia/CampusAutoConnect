"""Bounded, credential-free probes; never follow a discovered redirect."""

import socket
import ssl
import threading
import time
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from contextvars import copy_context
from html.parser import HTMLParser
from urllib.parse import urljoin, urlsplit

import httpx

from campus_autoconnect import __version__
from campus_autoconnect.core.models import (
    ConnectivityResult,
    ErrorCode,
    ProbeEndpoint,
    ProbeObservation,
)
from campus_autoconnect.core.observation import observe

DEFAULT_PROBES = (
    ProbeEndpoint("http://www.msftconnecttest.com/connecttest.txt", 200, b"Microsoft Connect Test"),
    ProbeEndpoint("https://connectivitycheck.gstatic.com/generate_204", 204, b""),
)


def make_client(*, transport: httpx.BaseTransport | None = None) -> httpx.Client:
    return httpx.Client(
        trust_env=False,
        verify=True,
        follow_redirects=False,
        timeout=httpx.Timeout(4.0, connect=2.0),
        limits=httpx.Limits(max_connections=4, max_keepalive_connections=0),
        headers={"User-Agent": f"CampusAutoConnect/{__version__}", "Accept-Encoding": "identity"},
        transport=transport,
    )


def request_error_code(exc: BaseException) -> ErrorCode:
    chain: BaseException | None = exc
    visited: set[int] = set()
    while chain is not None and id(chain) not in visited:
        visited.add(id(chain))
        if isinstance(chain, socket.gaierror):
            return ErrorCode.DNS_ERROR
        if isinstance(chain, ssl.SSLError):
            return ErrorCode.TLS_ERROR
        chain = chain.__cause__ or chain.__context__
    if isinstance(exc, httpx.TimeoutException):
        return ErrorCode.TIMEOUT
    return ErrorCode.NETWORK_UNREACHABLE


class _PortalHTML(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.destination: str | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        values = dict(attrs)
        if tag == "meta" and (values.get("http-equiv") or "").lower() == "refresh":
            content = values.get("content") or ""
            _, sep, target = content.partition(";")
            if sep and target.strip().lower().startswith("url="):
                self.destination = target.strip()[4:].strip(" '\"")


class ConnectivityService:
    BODY_LIMIT = 16 * 1024

    def __init__(
        self,
        endpoints: tuple[ProbeEndpoint, ...] = DEFAULT_PROBES,
        *,
        transport: httpx.BaseTransport | None = None,
        client_factory: Callable[[], httpx.Client] | None = None,
    ) -> None:
        # Production success requires independent hosts and at least one TLS probe.
        if not 1 <= len(endpoints) <= 8:
            raise ValueError("探测端点数量须为 1–8 个。")
        self.endpoints = endpoints
        self.transport = transport
        self._make_client = client_factory or (lambda: make_client(transport=self.transport))

    def check(self, cancel: threading.Event | None = None) -> ConnectivityResult:
        if cancel is not None and cancel.is_set():
            return ConnectivityResult(code=ErrorCode.CANCELLED)
        # One read-only client per probe also isolates untrusted endpoint cookies.
        # Join every worker before returning: no late probe can escape the operation.
        with ThreadPoolExecutor(max_workers=min(4, len(self.endpoints))) as pool:
            futures = [
                pool.submit(copy_context().run, self._probe_endpoint, endpoint, cancel)
                for endpoint in self.endpoints
            ]
            observations = [future.result() for future in futures]
        if cancel is not None and cancel.is_set():
            return ConnectivityResult(code=ErrorCode.CANCELLED)
        return self._combine(observations)

    def _probe_endpoint(
        self, endpoint: ProbeEndpoint, cancel: threading.Event | None
    ) -> ProbeObservation:
        with self._make_client() as client:
            if cancel is not None and cancel.is_set():
                return ProbeObservation(code=ErrorCode.CANCELLED)
            return self._probe(client, endpoint, cancel)

    def _combine(self, observations: list[ProbeObservation]) -> ConnectivityResult:
        hosts = {urlsplit(p.url).hostname for p in self.endpoints}
        online = (
            len(observations) >= 2
            and len(hosts) >= 2
            and any(urlsplit(p.url).scheme == "https" for p in self.endpoints)
            and all(p.expected for p in observations)
        )
        portal = next((p.portal_url for p in observations if p.portal_url), None)
        codes = [p.code for p in observations if p.code != ErrorCode.NONE]
        return ConnectivityResult(
            online=online,
            portal_url=portal,
            code=ErrorCode.NONE
            if online
            else (
                ErrorCode.TLS_ERROR
                if ErrorCode.TLS_ERROR in codes
                else codes[0]
                if codes
                else ErrorCode.PORTAL_UNRECOGNIZED
            ),
            observations=tuple(observations),
        )

    def _probe(
        self, client: httpx.Client, endpoint: ProbeEndpoint, cancel: threading.Event | None
    ) -> ProbeObservation:
        start = time.monotonic()
        try:
            observe("http_start", role="probe", https=urlsplit(endpoint.url).scheme == "https")
            with client.stream("GET", endpoint.url) as response:
                observe("http_response", role="probe", http_status=response.status_code)
                if 300 <= response.status_code < 400:
                    location = response.headers.get("location")
                    if not location:
                        return ProbeObservation(True, code=ErrorCode.PORTAL_UNRECOGNIZED)
                    target = urljoin(endpoint.url, location)
                    if urlsplit(target).scheme in {"http", "https"}:
                        return ProbeObservation(True, False, target, ErrorCode.NONE)
                    return ProbeObservation(True, code=ErrorCode.PORTAL_UNRECOGNIZED)
                if response.status_code >= 500:
                    return ProbeObservation(True, code=ErrorCode.SERVER_ERROR)
                content = bytearray()
                # Probe payloads are plain text. Avoid decoding untrusted compressed payloads.
                if response.headers.get("content-encoding", "identity").lower() != "identity":
                    return ProbeObservation(True, code=ErrorCode.PORTAL_UNRECOGNIZED)
                for chunk in response.iter_bytes():
                    if cancel is not None and cancel.is_set():
                        return ProbeObservation(code=ErrorCode.CANCELLED)
                    if time.monotonic() - start > 6:
                        return ProbeObservation(code=ErrorCode.TIMEOUT)
                    if len(content) + len(chunk) > self.BODY_LIMIT:
                        return ProbeObservation(True, code=ErrorCode.PORTAL_UNRECOGNIZED)
                    content.extend(chunk)
                expected = (
                    response.status_code == endpoint.expected_status
                    and bytes(content) == endpoint.expected_body
                )
                if expected:
                    observe("protocol", role="probe", expected=True)
                    return ProbeObservation(True, True)
                parser = _PortalHTML()
                parser.feed(bytes(content).decode("utf-8", errors="replace"))
                if parser.destination:
                    target = urljoin(endpoint.url, parser.destination)
                    if urlsplit(target).scheme in {"http", "https"}:
                        return ProbeObservation(True, False, target)
                return ProbeObservation(True, code=ErrorCode.PORTAL_UNRECOGNIZED)
        except (httpx.RequestError, ssl.SSLError, socket.gaierror) as exc:
            observe("http_error", role="probe", code=request_error_code(exc))
            return ProbeObservation(code=request_error_code(exc))
        except (ValueError, UnicodeError):
            return ProbeObservation(code=ErrorCode.PORTAL_UNRECOGNIZED)
