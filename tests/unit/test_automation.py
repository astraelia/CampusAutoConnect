import threading
import time
from dataclasses import replace

import pytest

from campus_autoconnect.core.models import (
    AuthResult,
    AuthState,
    ErrorCode,
    NetworkSnapshot,
)
from campus_autoconnect.infrastructure.automation import AutomationStore
from campus_autoconnect.services.automation import (
    AutomationCoordinator,
    AutomationPolicy,
    AutomationState,
    readiness,
)

pytestmark = pytest.mark.mock


class Clock:
    def __init__(self):
        self.now = 0.0

    def __call__(self):
        return self.now

    def advance(self, seconds):
        self.now += seconds


class Authentication:
    def __init__(self, snapshot, profile):
        self.snapshot, self.profile = snapshot, profile
        self.results = [AuthResult(AuthState.AUTHENTICATED, ErrorCode.NONE, "Mock online")]
        self.calls = 0
        self.started = threading.Event()
        self.gate = threading.Event()
        self.gate.set()

    def login(self, cancel, *, authorize):
        self.calls += 1
        self.started.set()
        assert self.gate.wait(3), "Mock worker was not released"
        if cancel.is_set():
            return AuthResult(AuthState.UNKNOWN, ErrorCode.CANCELLED, "Mock cancelled")
        if not authorize(self.snapshot, self.profile):
            return AuthResult(AuthState.UNKNOWN, ErrorCode.AUTOMATION_DISABLED, "Mock revoked")
        return self.results.pop(0) if len(self.results) > 1 else self.results[0]


def finish(coordinator):
    deadline = time.monotonic() + 3
    while coordinator.working and time.monotonic() < deadline:
        coordinator.tick()
        time.sleep(0.002)
    assert not coordinator.working


@pytest.fixture
def setup(tmp_path, snapshot, profile, profiles):
    profile = replace(profile, auto_auth=True)
    profiles.upsert(profile)
    settings = AutomationStore(tmp_path / "automation.json")
    settings.set_enabled(True)
    clock = Clock()
    auth = Authentication(snapshot, profile)
    recorded = []
    coordinator = AutomationCoordinator(
        auth, profiles, settings, clock=clock, record_result=recorded.append
    )
    coordinator.observe(snapshot, profile, enabled=True)
    return coordinator, auth, clock, settings, profile, recorded


def start(coordinator, clock):
    clock.advance(2)
    coordinator.tick()
    finish(coordinator)


@pytest.mark.parametrize("mode", ["disabled", "unknown", "profile_off", "profile_disabled"])
def test_both_authorizations_required_without_even_starting_task(setup, snapshot, mode):
    c, auth, clock, _, profile, _ = setup
    enabled = mode != "disabled"
    selected = (
        None
        if mode == "unknown"
        else replace(profile, auto_auth=mode != "profile_off", enabled=mode != "profile_disabled")
    )
    c.observe(snapshot, selected, enabled=enabled)
    start(c, clock)
    assert auth.calls == 0
    assert c.state in {AutomationState.DISABLED, AutomationState.UNTRUSTED}


def test_waits_for_stable_usable_ip_and_gateway(setup, snapshot):
    c, auth, clock, _, profile, _ = setup
    link_local = replace(
        snapshot,
        adapters=(
            replace(snapshot.adapters[0], ipv4=("169.254.2.3",), ipv6=("fe80::1",), gateways=()),
        ),
    )
    c.observe(link_local, profile, enabled=True)
    clock.advance(100)
    c.tick()
    assert c.state == AutomationState.WAITING_READY
    assert auth.calls == 0
    c.observe(snapshot, profile, enabled=True)
    clock.advance(1.9)
    c.tick()
    assert auth.calls == 0
    clock.advance(0.1)
    c.tick()
    finish(c)
    assert auth.calls == 1


@pytest.mark.parametrize(
    "code",
    [ErrorCode.TIMEOUT, ErrorCode.DNS_ERROR, ErrorCode.SERVER_ERROR, ErrorCode.NETWORK_UNREACHABLE],
)
def test_transient_errors_use_two_delays_then_latch(setup, snapshot, code):
    c, auth, clock, _, profile, _ = setup
    auth.results = [AuthResult(AuthState.UNKNOWN, code, "Mock temporary failure")]
    start(c, clock)
    assert c.state == AutomationState.BACKOFF
    assert c.status()["retry_in_seconds"] == 5
    clock.advance(4.9)
    c.tick()
    assert auth.calls == 1
    clock.advance(0.1)
    c.tick()
    finish(c)
    assert c.status()["retry_in_seconds"] == 15
    clock.advance(15)
    c.tick()
    finish(c)
    assert c.state == AutomationState.BLOCKED
    assert auth.calls == 3
    c.observe(NetworkSnapshot(), None, enabled=True)
    c.observe(snapshot, profile, enabled=True)
    c.invalidate("resume")
    clock.advance(1000)
    c.tick()
    assert auth.calls == 3


@pytest.mark.parametrize(
    "code",
    [
        ErrorCode.INVALID_CREDENTIALS,
        ErrorCode.MANUAL_ACTION,
        ErrorCode.PROTOCOL_CHANGED,
        ErrorCode.PROTOCOL_UNVERIFIED,
        ErrorCode.PORTAL_UNRECOGNIZED,
        ErrorCode.UNTRUSTED_TARGET,
        ErrorCode.TLS_ERROR,
        ErrorCode.ROUTE_UNCONFIRMED,
        ErrorCode.CREDENTIALS_MISSING,
        ErrorCode.CREDENTIAL_STORE,
        ErrorCode.UNKNOWN,
        ErrorCode.NONE,
    ],
)
def test_fatal_or_unknown_result_never_retries_after_reconnect_wake_or_toggle(
    setup, snapshot, code
):
    c, auth, clock, _, profile, _ = setup
    auth.results = [AuthResult(AuthState.AUTH_FAILED, code, "Mock blocked")]
    start(c, clock)
    assert c.state == AutomationState.BLOCKED
    c.observe(NetworkSnapshot(), None, enabled=True)
    c.invalidate("suspend")
    c.invalidate("resume")
    c.observe(snapshot, profile, enabled=False)
    c.observe(snapshot, profile, enabled=True)
    clock.advance(1000)
    c.tick()
    assert auth.calls == 1
    assert c.code == code


def test_online_waits_one_minute_before_new_check(setup):
    c, auth, clock, *_ = setup
    start(c, clock)
    assert c.state == AutomationState.ONLINE
    assert c.attempts == 0
    clock.advance(59.9)
    c.tick()
    assert auth.calls == 1
    clock.advance(0.1)
    c.tick()
    finish(c)
    assert auth.calls == 2


def test_resume_rechecks_online_and_suspend_defers_work(setup, snapshot):
    c, auth, clock, _, profile, _ = setup
    start(c, clock)
    c.invalidate("suspend")
    c.observe(snapshot, profile, enabled=True)
    clock.advance(120)
    c.tick()
    assert c.state == AutomationState.SUSPENDED
    assert auth.calls == 1
    c.invalidate("resume")
    c.observe(snapshot, profile, enabled=True)
    start(c, clock)
    assert auth.calls == 2


def test_switch_cancels_and_drains_old_work_then_discards_stale_completion(setup, snapshot):
    c, auth, clock, _, profile, recorded = setup
    auth.gate.clear()
    clock.advance(2)
    c.tick()
    assert auth.started.wait(1)
    c.invalidate()
    c.observe(NetworkSnapshot(), None, enabled=True)
    c.observe(snapshot, profile, enabled=True)
    clock.advance(20)
    c.tick()
    assert auth.calls == 1
    assert c.status()["operation_running"]
    auth.gate.set()
    finish(c)
    assert auth.calls == 2
    assert len(recorded) == 1
    assert recorded[0].state == AuthState.AUTHENTICATED


def test_stop_does_not_accept_delayed_success_or_launch_again(setup):
    c, auth, clock, _, _, recorded = setup
    auth.gate.clear()
    clock.advance(2)
    c.tick()
    assert auth.started.wait(1)
    c.stop()
    auth.gate.set()
    finish(c)
    clock.advance(1000)
    c.tick()
    assert c.state == AutomationState.STOPPED
    assert auth.calls == 1
    assert recorded == []


def test_reading_disk_switch_again_blocks_pending_authorization(setup):
    c, auth, clock, settings, _, _ = setup
    auth.gate.clear()
    clock.advance(2)
    c.tick()
    assert auth.started.wait(1)
    settings.set_enabled(False)
    auth.gate.set()
    finish(c)
    assert c.code == ErrorCode.AUTOMATION_DISABLED
    assert auth.calls == 1


def test_busy_operation_does_not_consume_authentication_attempt_budget(setup):
    c, auth, clock, *_ = setup
    auth.results = [AuthResult(AuthState.UNKNOWN, ErrorCode.BUSY, "Mock another process")]
    start(c, clock)
    assert c.attempts == 0
    assert c.state == AutomationState.BACKOFF
    clock.advance(10)
    c.tick()
    finish(c)
    assert c.attempts == 0


def test_transient_budget_is_not_reset_by_disconnects_or_global_toggles(setup, snapshot):
    c, auth, clock, _, profile, _ = setup
    auth.results = [AuthResult(AuthState.UNKNOWN, ErrorCode.TIMEOUT, "Mock temporary")]
    for _ in range(3):
        start(c, clock)
        c.observe(NetworkSnapshot(), None, enabled=True)
        c.observe(snapshot, profile, enabled=False)
        c.observe(snapshot, profile, enabled=True)
        clock.advance(100)
    c.tick()
    assert c.state == AutomationState.BLOCKED
    assert auth.calls == 3


def test_reconnect_and_resume_do_not_skip_transient_backoff(setup, snapshot):
    c, auth, clock, _, profile, _ = setup
    auth.results = [AuthResult(AuthState.UNKNOWN, ErrorCode.TIMEOUT, "Mock temporary")]
    start(c, clock)
    c.observe(NetworkSnapshot(), None, enabled=True)
    c.invalidate("resume")
    c.observe(snapshot, profile, enabled=True)
    clock.advance(2)
    c.tick()
    assert auth.calls == 1
    clock.advance(3)
    c.tick()
    finish(c)
    assert auth.calls == 2


def test_active_virtual_interface_is_blocked_before_any_task(setup, snapshot):
    c, auth, clock, _, profile, _ = setup
    virtual = replace(snapshot.adapters[0], index=8, hardware=False, ssid=None, gateways=())
    c.observe(replace(snapshot, adapters=(*snapshot.adapters, virtual)), profile, enabled=True)
    start(c, clock)
    assert c.code == ErrorCode.ROUTE_UNCONFIRMED
    assert auth.calls == 0


def test_dns_and_warning_changes_are_part_of_network_identity(snapshot):
    assert (
        snapshot.fingerprint != replace(snapshot, warnings=("ssid_permission_denied",)).fingerprint
    )
    assert (
        snapshot.fingerprint
        != replace(
            snapshot, adapters=(replace(snapshot.adapters[0], dns=("192.0.2.99",)),)
        ).fingerprint
    )


@pytest.mark.parametrize(
    "kwargs",
    [
        {"retry_delays": (1, 2, 3)},
        {"snapshot_interval": 0},
        {"online_interval": 0},
        {"settle_seconds": -1},
        {"retry_delays": (float("nan"),)},
    ],
)
def test_invalid_policy_rejected(kwargs):
    with pytest.raises(ValueError):
        AutomationPolicy(**kwargs)


def test_ambiguous_wifi_and_warning_fail_closed(snapshot):
    second = replace(snapshot.adapters[0], index=8)
    assert (
        readiness(replace(snapshot, adapters=(*snapshot.adapters, second)))[0]
        == AutomationState.UNTRUSTED
    )
    assert (
        readiness(replace(snapshot, warnings=("ssid_permission_denied",)))[0]
        == AutomationState.UNTRUSTED
    )
