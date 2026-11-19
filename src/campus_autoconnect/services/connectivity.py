"""Bounded, credential-free probes; never follow a discovered redirect."""

import ipaddress
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
    NetworkSnapshot,
    ProbeEndpoint,
    ProbeObservation,
)
from campus_autoconnect.core.network import NetworkProvider
from campus_autoconnect.core.observation import observe

DEFAULT_PROBES = (
    ProbeEndpoint("http://www.msftconnecttest.com/connecttest.txt", 200, b"Microsoft Connect Test"),
    ProbeEndpoint("https://connectivitycheck.gstatic.com/generate_204", 204, b""),
)
FALLBACK_HTTPS_PROBE = ProbeEndpoint(
    "https://captive.apple.com/hotspot-detect.html",
    200,
    b"<HTML><HEAD><TITLE>Success</TITLE></HEAD><BODY>Success</BODY></HTML>\n",
)
_FALLBACK_ERRORS = frozenset(
    {ErrorCode.TIMEOUT, ErrorCode.DNS_ERROR, ErrorCode.NETWORK_UNREACHABLE, ErrorCode.SERVER_ERROR}
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


def _socket_ips(response: httpx.Response) -> tuple[str, str] | None:
    stream = response.extensions.get("network_stream")
    if stream is None:
        return None
    try:
        local = ipaddress.ip_address(stream.get_extra_info("client_addr")[0].split("%")[0])
        peer = ipaddress.ip_address(stream.get_extra_info("server_addr")[0].split("%")[0])
        return (
            str(getattr(local, "ipv4_mapped", None) or local),
            str(getattr(peer, "ipv4_mapped", None) or peer),
        )
    except (OSError, AttributeError, ValueError, TypeError, IndexError):
        return None


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
        https_fallback: ProbeEndpoint | None = None,
    ) -> None:
        # Production success requires independent hosts and at least one TLS probe.
        if not 1 <= len(endpoints) <= 8:
            raise ValueError("探测端点数量须为 1–8 个。")
        if https_fallback is not None:
            fallback_url = urlsplit(https_fallback.url)
            hosts = {urlsplit(endpoint.url).hostname for endpoint in endpoints}
            if (
                len(endpoints) != 2
                or len(hosts) != 2
                or fallback_url.scheme != "https"
                or fallback_url.hostname is None
                or fallback_url.hostname in hosts
            ):
                raise ValueError("备用探测须使用与两个主端点不同的 HTTPS 主机。")
        self.endpoints = endpoints
        self.https_fallback = https_fallback
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
        if (
            self.https_fallback is not None
            and any(probe.expected for probe in observations)
            and any(probe.code in _FALLBACK_ERRORS for probe in observations)
            and not any(probe.portal_url for probe in observations)
        ):
            observations.append(self._probe_endpoint(self.https_fallback, cancel))
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
        endpoints = self._observed_endpoints(len(observations))
        matched = [
            urlsplit(endpoint.url)
            for endpoint, probe in zip(endpoints, observations, strict=True)
            if probe.expected
        ]
        portal = next((p.portal_url for p in observations if p.portal_url), None)
        fallback_matched = len(observations) > len(self.endpoints) and observations[-1].expected
        online = (
            len({parts.hostname for parts in matched}) >= 2
            and any(parts.scheme == "https" for parts in matched)
            and portal is None
            and (len(matched) == len(observations) or fallback_matched)
        )
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

    def _observed_endpoints(self, count: int) -> tuple[ProbeEndpoint, ...]:
        if self.https_fallback is not None and count == len(self.endpoints) + 1:
            return (*self.endpoints, self.https_fallback)
        return self.endpoints

    def routes_match(
        self, result: ConnectivityResult, network: NetworkProvider, snapshot: NetworkSnapshot
    ) -> bool:
        adapter = snapshot.selected
        endpoints = self._observed_endpoints(len(result.observations))
        if adapter is None or not result.online or len(result.observations) != len(endpoints):
            return False
        confirmed = 0
        for endpoint, observation in zip(endpoints, result.observations, strict=True):
            if not observation.expected:
                continue
            target = endpoint.url
            if observation.socket_ips is not None:
                source, peer = observation.socket_ips
                if source not in (*adapter.ipv4, *adapter.ipv6):
                    return False
                # Verify the address that actually answered, including when IPv6
                # DNS results exist but this probe succeeded over IPv4.
                host = f"[{peer}]" if ":" in peer else peer
                target = f"{urlsplit(target).scheme}://{host}"
            if not network.route_allows(target, snapshot):
                return False
            confirmed += 1
        return confirmed >= 2

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
                socket_ips = (
                    _socket_ips(response)
                    if response.status_code == endpoint.expected_status
                    else None
                )
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
                    return ProbeObservation(True, True, socket_ips=socket_ips)
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
