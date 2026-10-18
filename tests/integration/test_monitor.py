import json
import threading
import time
from dataclasses import replace

import pytest

from campus_autoconnect.core.errors import CampusError
from campus_autoconnect.core.models import AuthProgress, AuthResult, AuthStage, AuthState, ErrorCode
from campus_autoconnect.infrastructure.automation import AutomationStore
from campus_autoconnect.infrastructure.locking import FileMutex
from campus_autoconnect.services.automation import AutomationCoordinator, AutomationPolicy
from campus_autoconnect.services.monitor import MonitorControl, MonitorRuntime

pytestmark = pytest.mark.mock


class Events:
    warnings = ()

    def start(self, notify):
        self.notify = notify
        self.closed = False

    def close(self):
        self.closed = True


def wait_for(predicate):
    deadline = time.monotonic() + 4
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(0.005)
    assert predicate()


@pytest.fixture
def runtime(tmp_path, profiles, network):
    settings = AutomationStore(tmp_path / "automation.json")
    control = MonitorControl(tmp_path)

    class Authentication:
        calls = 0

        def login(self, cancel, *, authorize):
            self.calls += 1
            return AuthResult(AuthState.UNKNOWN, ErrorCode.PROTOCOL_UNVERIFIED, "Mock blocked")

    auth = Authentication()
    coordinator = AutomationCoordinator(
        auth, profiles, settings, policy=AutomationPolicy(settle_seconds=0.01)
    )
    return MonitorRuntime(coordinator, network, profiles, settings, control, events=Events())


def test_default_off_no_network_queries_and_cooperative_stop(runtime, network, credentials):
    failures = []
    stop = threading.Event()

    def run():
        try:
            runtime.run(stop=stop)
        except Exception as error:
            failures.append(type(error).__name__)

    thread = threading.Thread(target=run)
    thread.start()
    try:
        wait_for(lambda: runtime.control.status().get("state") == "DISABLED")
        assert runtime.control.status()["running"]
        assert network.calls == credentials.reads == 0
        assert runtime.coordinator.authentication.calls == 0
        with pytest.raises(CampusError) as error:
            runtime.run(duration=0.1)
        assert error.value.code == ErrorCode.BUSY
        assert runtime.control.request_stop()
    finally:
        stop.set()
        thread.join(4)
    assert not thread.is_alive()
    assert failures == []
    assert runtime.events.closed
    assert not runtime.control.status()["running"]


def test_background_query_projection_is_validated_and_does_not_echo_extra_fields(runtime):
    query = dict(
        backend="powershell",
        fallback_reason="native_unavailable",
        snapshot_ms=123,
        route_ms=2,
        account="MUST_NOT_APPEAR",
    )
    runtime.network.diagnostics = lambda: query
    runtime._write_status("a" * 32)
    result = runtime.control._current()["network_query"]
    assert result["backend"] == "powershell" and result["snapshot_ms"] == 123
    assert "MUST_NOT_APPEAR" not in str(result)
    payload = json.loads(runtime.control.status_path.read_text(encoding="utf-8"))
    for key, bad in (
        ("backend", "MUST_NOT_APPEAR"),
        ("fallback_reason", "MUST_NOT_APPEAR"),
        ("snapshot_ms", True),
        ("route_ms", -1),
    ):
        payload["network_query"] = {**query, key: bad}
        runtime.control.status_path.write_text(json.dumps(payload), encoding="utf-8")
        with pytest.raises(ValueError):
            runtime.control._current()


def test_brief_status_probe_does_not_abort_background_start(runtime, monkeypatch):
    held = FileMutex(runtime.control.lock_path)
    assert held.acquire()
    observed_busy, stop = threading.Event(), threading.Event()
    failures = []
    original = FileMutex._try_acquire

    def observe(self):
        acquired = original(self)
        if threading.current_thread().name == "probe-race" and not acquired:
            observed_busy.set()
        return acquired

    monkeypatch.setattr(FileMutex, "_try_acquire", observe)

    def run():
        try:
            runtime.run(stop=stop)
        except Exception as error:
            failures.append(type(error).__name__)

    thread = threading.Thread(target=run, name="probe-race")
    thread.start()
    try:
        assert observed_busy.wait(1)
        held.release()
        wait_for(lambda: runtime.coordinator.state.value == "DISABLED")
        assert runtime.coordinator.authentication.calls == 0
    finally:
        held.release()
        stop.set()
        thread.join(4)
    assert not thread.is_alive()
    assert failures == []


def test_enabled_runtime_reacts_to_disk_profile_and_switch_changes(runtime, profile, profiles):
    runtime.settings.set_enabled(True)
    profiles.upsert(replace(profile, auto_auth=True))
    thread = threading.Thread(target=lambda: runtime.run(duration=3))
    thread.start()
    try:
        wait_for(lambda: runtime.coordinator.state.value == "BLOCKED")
        assert runtime.coordinator.authentication.calls == 1
        runtime.events.notify("suspend")
        runtime.events.notify("resume")
        time.sleep(0.3)
        assert runtime.coordinator.authentication.calls == 1
        runtime.settings.set_enabled(False)
        wait_for(lambda: runtime.coordinator.state.value == "DISABLED")
    finally:
        runtime.control.request_stop()
        thread.join(4)
    assert not thread.is_alive()


def test_corrupted_automation_file_never_reaches_authentication(runtime):
    runtime.settings.path.write_text('{"enabled":"true"}')
    runtime.run(duration=0.3)
    assert runtime.coordinator.authentication.calls == 0
    assert not runtime.control.status()["running"]


def test_unexpected_runtime_failure_remains_visible_without_raw_exception(
    runtime, network, monkeypatch
):
    runtime.settings.set_enabled(True)

    def fail():
        raise RuntimeError("account=DO_NOT_ECHO")

    monkeypatch.setattr(network, "snapshot", fail)
    with pytest.raises(RuntimeError):
        runtime.run(duration=0.2)
    status = runtime.control.status()
    assert status["running"] is False
    assert status["error_code"] == "unknown"
    assert status["failure_type"] == "RuntimeError"
    assert "DO_NOT_ECHO" not in str(status)
    assert runtime.events.closed


def test_status_publication_failure_releases_mutex_and_closes_events(runtime, monkeypatch):
    def fail(*_):
        raise OSError("DO_NOT_LOG")

    monkeypatch.setattr(runtime.control, "write", fail)
    with pytest.raises(OSError):
        runtime.run(duration=0.2)
    assert runtime.events.closed
    assert not runtime.coordinator.working
    with FileMutex(runtime.control.lock_path):
        pass


def test_monitor_only_publishes_whitelisted_progress(runtime):
    progress = AuthProgress(
        stage=AuthStage.TARGET,
        profile_matched=True,
        credential_read_attempted=False,
        login_request_attempted=False,
    )
    runtime.coordinator.last_result = AuthResult(
        AuthState.UNKNOWN,
        ErrorCode.UNTRUSTED_TARGET,
        "DO_NOT_ECHO",
        progress=progress,
    )
    status = runtime.coordinator.status()
    status["last_authentication"]["private_host"] = "DO_NOT_ECHO"
    runtime.control.write("1" * 32, status)
    with FileMutex(runtime.control.lock_path):
        public = runtime.control.status()
    assert public["last_authentication"] == progress.diagnostic()
    assert "DO_NOT_ECHO" not in str(public)


@pytest.mark.parametrize(
    "field,value",
    [
        ("stage", "private-secret"),
        ("profile_matched", "true"),
        ("credential_read_attempted", 1),
        ("profile_issues", ["private-secret"]),
        ("zero_mac_allowed", "true"),
        ("zero_mac_observed", "private-secret"),
        ("zero_vlan_observed", 1),
    ],
)
def test_monitor_rejects_malformed_progress_without_echoing_it(field, value):
    raw = AuthProgress().diagnostic()
    raw[field] = value
    with pytest.raises(ValueError):
        MonitorControl._authentication(raw)
    assert MonitorControl._authentication(None) is None


def test_old_monitor_status_has_unknown_zero_context_facts():
    raw = AuthProgress().diagnostic()
    for field in ("zero_mac_allowed", "zero_mac_observed", "zero_vlan_observed"):
        raw.pop(field)
    public = MonitorControl._authentication(raw)
    assert public["zero_mac_allowed"] is False
    assert public["zero_mac_observed"] is None and public["zero_vlan_observed"] is None
