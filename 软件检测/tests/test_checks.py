import json
import socket
import ssl
import threading
from dataclasses import asdict, replace

import httpx
import pytest
from campus_inspector.checks import InspectionRunner, read_json, verify_tls
from campus_inspector.records import Outcome, Report, ReportWriter
from campus_inspector.selfcheck import SyntheticNetwork, synthetic_config, transport_for

from campus_autoconnect.core.models import NetworkSnapshot


def inspect(tmp_path, target, *, network=None, transport=None, tls=None):
    synthetic_config(tmp_path)
    steps = []
    runner = InspectionRunner(
        tmp_path,
        steps.append,
        network=network if network is not None else SyntheticNetwork(),
        transport=transport if transport is not None else transport_for(target),
        tls=tls if tls is not None else lambda _: (True, "tls_verified", {}),
    )
    runner.inspect(threading.Event())
    return steps


@pytest.mark.parametrize(
    "target,expected",
    [
        ("http://portal.example.edu/a79.htm", "http_disallowed"),
        ("http://portal.example.edu/different", "http_disallowed"),
        ("https://other.example.edu/login", "host_not_allowed"),
        ("https://portal.example.edu:8443/login", "port_not_allowed"),
        ("https://portal.example.edu/#fragment", "invalid_target"),
        ("https://account:password@portal.example.edu/", "invalid_target"),
    ],
)
def test_target_block_does_not_connect_to_portal(tmp_path, target, expected):
    network = SyntheticNetwork()
    steps = inspect(
        tmp_path, target, network=network, tls=lambda _: pytest.fail("must not contact portal")
    )
    trust = next(s for s in steps if s.key == "trust")
    assert trust.outcome == Outcome.BLOCKED
    assert trust.code == expected
    assert network.route_calls == 0
    assert all(s.outcome == Outcome.SKIPPED for s in steps if s.key in {"route", "tls"})


def test_online_unknown_wifi_still_reports_internet_without_login(tmp_path):
    network = SyntheticNetwork()
    network.current = replace(
        network.current, adapters=(replace(network.current.adapters[0], ssid="Other-Private-Wifi"),)
    )
    steps = inspect(tmp_path, None, network=network)
    report = Report(steps=steps)
    assert "互联网可用" in report.summary()
    assert not any(s.outcome == Outcome.BLOCKED for s in steps)
    assert network.route_calls == 0


def test_missing_profile_blocks_only_after_offline_probe(tmp_path):
    network = SyntheticNetwork()
    network.current = replace(
        network.current, adapters=(replace(network.current.adapters[0], ssid="Other-Private-Wifi"),)
    )
    steps = inspect(tmp_path, "http://portal.example.edu/a79.htm", network=network)
    assert any(s.key == "probe_1" for s in steps)
    assert any(s.key == "profile_gate" and s.outcome == Outcome.BLOCKED for s in steps)
    assert network.route_calls == 0


def test_no_network_does_not_probe(tmp_path):
    network = SyntheticNetwork()
    network.current = NetworkSnapshot()
    steps = inspect(
        tmp_path,
        None,
        network=network,
        transport=httpx.MockTransport(lambda _: pytest.fail("must not probe")),
    )
    assert "Windows 网络快照" in Report(steps=steps).summary()


@pytest.mark.parametrize(
    "error,expected",
    [
        (
            httpx.ConnectError("private body", request=httpx.Request("GET", "https://x.test")),
            "network_unreachable",
        ),
        (httpx.ReadTimeout("private host"), "timeout"),
        (socket.gaierror("private DNS"), "dns_error"),
        (ssl.SSLError("private cert"), "tls_error"),
    ],
)
def test_probe_faults_safe_and_precise(tmp_path, error, expected):
    def fail(_):
        raise error

    steps = inspect(tmp_path, None, transport=httpx.MockTransport(fail))
    assert any(s.key == "probe_1" and s.code == expected for s in steps)
    assert "private" not in json.dumps([asdict(s) for s in steps])


def test_network_changes_invalidate_probe_conclusion(tmp_path):
    class Changing(SyntheticNetwork):
        def __init__(self):
            super().__init__()
            self.calls = 0

        def snapshot(self):
            self.calls += 1
            return self.current if self.calls == 1 else NetworkSnapshot()

    steps = inspect(tmp_path, None, network=Changing())
    assert any(s.code == "network_changed" and s.outcome == Outcome.BLOCKED for s in steps)
    assert not any(s.code == "already_authenticated" for s in steps)


def test_protocol_and_route_are_independent_readiness_checks(tmp_path):
    network = SyntheticNetwork(route=False)
    steps = inspect(
        tmp_path,
        "https://portal.example.edu/login",
        network=network,
        tls=lambda _: pytest.fail("route must pass first"),
    )
    assert any(s.key == "capability" and s.code == "protocol_unverified" for s in steps)
    assert any(s.key == "route" and s.outcome == Outcome.BLOCKED for s in steps)
    assert any(s.key == "tls" and s.outcome == Outcome.SKIPPED for s in steps)


def test_explicit_http_compatibility_is_reported_without_submitting(tmp_path):
    from campus_autoconnect.infrastructure.config import ConfigStore

    synthetic_config(tmp_path)
    store = ConfigStore(tmp_path / "config.json")
    profile = store.load()[0]
    store.save(
        [
            replace(
                profile,
                portal_page_url="http://portal.example.edu/a79.htm",
                bjut_api_origin="http://portal.example.edu:801",
                allow_http_auth=True,
            )
        ]
    )
    steps = []
    runner = InspectionRunner(
        tmp_path,
        steps.append,
        network=SyntheticNetwork(),
        transport=transport_for("http://portal.example.edu/a79.htm"),
        tls=lambda _: pytest.fail("HTTP compatibility must not attempt TLS or login"),
    )
    runner.inspect(threading.Event())
    assert any(s.code == "trusted_http" for s in steps)
    assert any(s.code == "adapter_configured" for s in steps)
    assert any(s.code == "explicit_http_compatibility" for s in steps)
    report = Report(steps=steps).payload()
    assert report["tool_credential_reads"] == report["tool_login_submissions"] == 0


def test_config_unchanged_and_report_contains_no_identifiers(tmp_path):
    synthetic_config(tmp_path)
    before = (tmp_path / "config.json").read_bytes()
    steps = inspect(tmp_path, "http://portal.example.edu/a79.htm?token=private-token")
    report = Report(steps=steps)
    writer = ReportWriter(tmp_path / "reports", report)
    writer.save(report)
    for name in ("report.json", "report.txt"):
        content = (writer.directory / name).read_text(encoding="utf-8-sig")
        for secret in ("private-token", "portal.example.edu", "Synthetic-Campus", "192.0.2.10"):
            assert secret not in content
    assert (tmp_path / "config.json").read_bytes() == before
    assert not any(tmp_path.glob("*.bak"))
    assert not any(tmp_path.glob("*.lock"))


def test_bad_primary_config_does_not_use_backup_or_repair(tmp_path):
    synthetic_config(tmp_path)
    path = tmp_path / "config.json"
    path.with_suffix(".json.bak").write_bytes(path.read_bytes())
    path.write_text('{"bad": true}', encoding="utf-8")
    steps = []
    runner = InspectionRunner(
        tmp_path,
        steps.append,
        network=SyntheticNetwork(),
        transport=transport_for("http://portal.example.edu/a79.htm"),
    )
    runner.inspect(threading.Event())
    assert any(s.key == "profile" and s.code == "config_error" for s in steps)
    assert not any(s.code == "profile_matched" for s in steps)
    assert path.read_text(encoding="utf-8") == '{"bad": true}'


def test_cancel_before_network_does_not_query(tmp_path):
    class Forbidden(SyntheticNetwork):
        def snapshot(self):
            pytest.fail("cancelled query")

    steps = []
    cancel = threading.Event()
    cancel.set()
    InspectionRunner(tmp_path, steps.append, network=Forbidden()).inspect(cancel)
    assert [s.key for s in steps] == ["submission"]


@pytest.mark.parametrize("content", ['{"x":1,"x":2}', '{"x":NaN}', "[] trailing"])
def test_untrusted_json_rejected(tmp_path, content):
    path = tmp_path / "input.json"
    path.write_text(content, encoding="utf-8")
    with pytest.raises(ValueError):
        read_json(path, 1024)


def test_tls_uses_explicit_trust_store_and_keeps_hostname_validation(monkeypatch):
    from contextlib import nullcontext

    import certifi

    original = ssl.create_default_context
    failure = ssl.SSLCertVerificationError(1, "private certificate text")
    failure.verify_code = 64

    class Context:
        def wrap_socket(self, _connection, *, server_hostname):
            assert server_hostname == "portal.example.edu"
            raise failure

    def context(*, cafile):
        assert cafile == certifi.where()
        real = original(cafile=cafile)
        assert real.check_hostname
        assert real.verify_mode == ssl.CERT_REQUIRED
        return Context()

    monkeypatch.setattr(ssl, "create_default_context", context)
    monkeypatch.setattr(socket, "create_connection", lambda *a, **k: nullcontext(object()))
    ok, code, facts = verify_tls("https://portal.example.edu/login")
    assert not ok
    assert code == "tls_identity_mismatch"
    assert facts == {"verify_code": 64}


def test_context_never_reads_or_mutates_credentials(tmp_path, monkeypatch):
    from campus_autoconnect.security.credentials import WindowsCredentialStore

    for name in ("get", "set", "delete", "exists"):
        monkeypatch.setattr(WindowsCredentialStore, name, lambda *a: pytest.fail("no vault access"))
    steps = []
    InspectionRunner(
        tmp_path,
        steps.append,
        network=SyntheticNetwork(),
        backend=lambda: object(),
        startup=lambda: {"installed": False},
    ).context()
    assert any(step.key == "vault" for step in steps)
    assert any(step.key == "background" for step in steps)
