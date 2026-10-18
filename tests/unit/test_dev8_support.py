import json
import sys
import threading
from dataclasses import replace

import pytest

from campus_autoconnect.core.errors import CampusError
from campus_autoconnect.core.models import AuthState, ErrorCode
from campus_autoconnect.infrastructure.capture_sanitizer import outcome, safe_post, safe_url
from campus_autoconnect.infrastructure.reports import ReportSession, installation_directory
from campus_autoconnect.services.application import ApplicationServices
from campus_autoconnect.services.browser_capture import BrowserCapture
from campus_autoconnect.services.support import SupportService

pytest_plugins = ["tests.unit.test_bjut_auth"]

pytestmark = pytest.mark.mock


def test_deep_check_uses_production_prepare_without_read_or_submission(bjut_service, credentials):
    service, requests, _, _ = bjut_service
    result = service.prepare_check()
    assert result.state == AuthState.AUTH_REQUIRED and result.code == ErrorCode.NONE
    assert [r.url.path for r in requests] == ["/a79.htm", "/eportal/portal/page/loadConfig"]
    assert credentials.reads == 0
    assert (
        not result.progress.credential_read_attempted
        and not result.progress.login_request_attempted
    )
    assert {e["kind"] for e in service.trace.snapshot()} == {"preparation"}


def test_deep_check_rechecks_network_after_preparation(bjut_service, credentials, monkeypatch):
    from campus_autoconnect.core.models import NetworkSnapshot

    service, requests, _, adapter = bjut_service
    original = adapter.prepare

    def prepare(*args):
        original(*args)
        service.network.current = NetworkSnapshot()

    monkeypatch.setattr(adapter, "prepare", prepare)
    assert service.prepare_check().code == ErrorCode.NETWORK_CHANGED
    assert len(requests) == 2 and credentials.reads == 0


def test_trace_observer_failure_does_not_change_login_or_request_count(
    bjut_service, credentials, monkeypatch
):
    service, requests, _, _ = bjut_service

    def fail(_):
        raise RuntimeError("should-not-affect-login")

    monkeypatch.setattr(service.trace, "record", fail)
    result = service.login()
    assert result.state == AuthState.AUTHENTICATED
    assert len(requests) == 3 and credentials.reads == 1
    assert service.trace.unavailable


def test_trace_and_saved_report_never_contain_identifiers_or_values(
    bjut_service, credentials, profiles, tmp_path
):
    auth, requests, _, _ = bjut_service
    support = SupportService(tmp_path, auth, tmp_path / "reports")
    app = ApplicationServices(profiles, credentials, auth, support=support)
    support.begin()
    result = auth.login()
    app.record_result(result)
    document = (support.session.directory / "diagnostic.json").read_text(encoding="utf-8")
    for private in (
        "portal.example.edu",
        "192.0.2.10",
        "Example-Campus",
        "PRIVATE_RESPONSE",
        credentials.values["shared"].username,
        credentials.values["shared"].password,
    ):
        assert private not in document
    payload = json.loads(document)
    trace = payload["actual_trace"]
    assert len({e["operation_id"] for e in trace}) == 1
    assert sum(e["event"] == "http_start" and e["role"] == "login" for e in trace) == 1
    assert any(e["facts"].get("accepted") is True for e in trace)
    for event in trace:
        if event["event"] == "http_start":
            expected = "submit" if event["role"] == "login" else "prepare"
            assert event["stage"] == expected
    assert len(requests) == 3


def test_report_io_failure_cannot_change_authentication_result(
    bjut_service, credentials, profiles, tmp_path, monkeypatch
):
    auth, _, _, _ = bjut_service
    support = SupportService(tmp_path, auth, tmp_path / "reports")
    app = ApplicationServices(profiles, credentials, auth, support=support)

    def fail(*_):
        raise OSError("synthetic-write-denied")

    monkeypatch.setattr(support.session, "write", fail)
    support.begin()
    result = auth.login()
    app.record_result(result)
    assert app.last_result.state == AuthState.AUTHENTICATED
    assert support.save_error
    assert "synthetic-write-denied" not in support.text()


def test_later_operation_does_not_overwrite_finished_monitoring_session(
    bjut_service, profiles, credentials, tmp_path
):
    from campus_autoconnect.core.models import ConnectivityResult
    from tests.unit.test_authentication import SequenceConnectivity

    auth, _, _, _ = bjut_service
    support = SupportService(tmp_path, auth, tmp_path / "reports")
    app = ApplicationServices(profiles, credentials, auth, support=support)
    support.begin()
    app.record_result(auth.login())
    support.finish()
    previous = support.session.directory
    content = (previous / "diagnostic.json").read_bytes()
    old_ids = {e["operation_id"] for e in auth.trace.snapshot()}
    auth.connectivity = SequenceConnectivity(ConnectivityResult(online=True))
    app.record_result(auth.check())
    assert support.session.directory != previous
    assert (previous / "diagnostic.json").read_bytes() == content
    assert support.payload()["actual_trace"]
    assert all(e["operation_id"] not in old_ids for e in support.payload()["actual_trace"])


def test_install_directory_uses_executable_not_cwd(tmp_path, monkeypatch):
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    monkeypatch.setattr(sys, "executable", str(tmp_path / "fixed" / "CampusAutoConnect.exe"))
    monkeypatch.chdir(tmp_path)
    assert installation_directory() == tmp_path / "fixed"
    assert ReportSession().root == tmp_path / "fixed" / "reports"


def test_capture_sanitizer_masks_values_paths_and_arbitrary_response():
    value = safe_url(
        "http://portal.example.edu:801/eportal/portal/login?user_account=private-user&user_password=private-password&login_method=1&token=private-token"
    )
    assert value["host"] == "portal.example.edu"
    output = json.dumps(value)
    assert all(s not in output for s in ("private-user", "private-password", "private-token"))
    assert safe_url("http://example.edu/personal-secret-path")["path"] == "/[other]"
    assert safe_post(
        "username=private-account&password=private-password", "application/x-www-form-urlencoded"
    )
    summary = outcome(
        b'{"result":1,"msg":"login success private-server-text","token":"private-token"}'
    )
    assert summary == {"result": 1, "text_signal": "login_success"}


def test_capture_wait_cancel_never_launches_browser(bjut_service, tmp_path):
    auth, _, _, _ = bjut_service
    support = SupportService(tmp_path, auth, tmp_path / "reports")
    capture = BrowserCapture(support)
    cancel = threading.Event()
    cancel.set()
    with pytest.raises(CampusError) as raised:
        capture.run(cancel, launcher=lambda _: pytest.fail("no browser"))
    assert raised.value.code == ErrorCode.CANCELLED
    assert not list(support.session.directory.glob("PortalCapture*"))


def test_capture_known_target_keeps_route_and_permission_gate(bjut_service, profiles, tmp_path):
    auth, _, _, _ = bjut_service
    support = SupportService(tmp_path, auth, tmp_path / "reports")
    capture = BrowserCapture(support)
    auth.network.route_safe = False
    with pytest.raises(CampusError) as raised:
        capture._target()
    assert raised.value.code == ErrorCode.ROUTE_UNCONFIRMED
    auth.network.route_safe = True
    p = profiles.list()[0]
    profiles.upsert(replace(p, allow_http_auth=False))
    with pytest.raises(CampusError) as raised:
        capture._target()
    assert raised.value.code == ErrorCode.UNTRUSTED_TARGET
