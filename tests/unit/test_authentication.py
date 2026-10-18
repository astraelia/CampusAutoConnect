from dataclasses import replace

import httpx
import pytest

from campus_autoconnect.adapters.base import AdapterReply
from campus_autoconnect.adapters.bjut import BJUTPortalAdapter
from campus_autoconnect.core.models import AuthState, ConnectivityResult, ErrorCode, NetworkSnapshot
from campus_autoconnect.core.state_machine import StateMachine
from campus_autoconnect.infrastructure.automation import AutomationStore
from campus_autoconnect.infrastructure.locking import FileMutex
from campus_autoconnect.services.authentication import AuthenticationService
from campus_autoconnect.services.connectivity import make_client
from tests.mocks.portal_adapter import SyntheticPortalAdapter

pytestmark = pytest.mark.mock


class SequenceConnectivity:
    def __init__(self, *results):
        self.results = list(results)
        self.calls = 0

    def check(self, cancel=None):
        self.calls += 1
        return self.results.pop(0) if len(self.results) > 1 else self.results[0]


@pytest.fixture
def adapter():
    return SyntheticPortalAdapter(
        lambda: make_client(
            transport=httpx.MockTransport(lambda _: httpx.Response(200, json={"ok": True}))
        )
    )


@pytest.fixture
def service(network, profiles, credentials, adapter):
    connectivity = SequenceConnectivity(
        ConnectivityResult(portal_url="https://portal.example.edu/mock-login"),
        ConnectivityResult(online=True),
    )
    return AuthenticationService(
        network, profiles, credentials, connectivity, {"bjut": lambda: adapter}
    )


def test_unknown_wifi_never_reads_or_authenticates(
    service, network, credentials, adapter, snapshot
):
    network.current = replace(
        snapshot, adapters=(replace(snapshot.adapters[0], ssid="BJUT-UNTRUSTED"),)
    )
    result = service.login()
    assert result.code == ErrorCode.UNTRUSTED_NETWORK
    assert credentials.reads == 0
    assert adapter.calls == 0


def test_disabled_wifi_never_reads_credentials(service, profiles, profile, credentials):
    profiles.upsert(replace(profile, enabled=False))
    assert service.login().code == ErrorCode.UNTRUSTED_NETWORK
    assert credentials.reads == 0


def test_online_avoids_all_credential_reads(service, credentials, adapter):
    service.connectivity = SequenceConnectivity(ConnectivityResult(online=True))
    result = service.login()
    assert result.state == AuthState.AUTHENTICATED
    assert result.code == ErrorCode.ALREADY_AUTHENTICATED
    assert credentials.reads == adapter.calls == 0


def test_untrusted_redirect_blocked_before_secrets(service, credentials, adapter):
    service.connectivity = SequenceConnectivity(
        ConnectivityResult(portal_url="https://evil.example.test/")
    )
    assert service.login().code == ErrorCode.UNTRUSTED_TARGET
    assert credentials.reads == adapter.calls == 0


def test_mock_success_and_state_history(service, credentials, adapter):
    result = service.login()
    assert result.state == AuthState.AUTHENTICATED
    assert result.history == (
        AuthState.DISCONNECTED,
        AuthState.NETWORK_CONNECTED,
        AuthState.CHECKING,
        AuthState.AUTH_REQUIRED,
        AuthState.AUTHENTICATING,
        AuthState.AUTHENTICATED,
    )
    assert credentials.reads == adapter.calls == 1


def test_response_acceptance_alone_never_success(service):
    service.connectivity = SequenceConnectivity(
        ConnectivityResult(portal_url="https://portal.example.edu/mock-login")
    )
    assert service.login().state == AuthState.UNKNOWN


def test_check_never_reads_credentials(service, credentials):
    assert service.check().state == AuthState.AUTH_REQUIRED
    assert credentials.reads == 0


def test_automatic_switch_revoked_before_read(service, credentials, network, adapter, tmp_path):
    settings = AutomationStore(tmp_path / "automation.json")
    settings.set_enabled(True)

    def revoke(call):
        if call == 2:
            settings.set_enabled(False)

    network.on_snapshot = revoke
    result = service.login(authorize=lambda *_: settings.load().enabled)
    assert result.code == ErrorCode.AUTOMATION_DISABLED
    assert credentials.reads == adapter.calls == 0


def test_automatic_switch_revoked_after_read_prevents_submission(
    service, credentials, network, adapter, tmp_path
):
    settings = AutomationStore(tmp_path / "automation.json")
    settings.set_enabled(True)

    def revoke(call):
        if call == 4:  # A new post-probe snapshot precedes the original credential gates.
            settings.set_enabled(False)

    network.on_snapshot = revoke
    result = service.login(authorize=lambda *_: settings.load().enabled)
    assert result.code == ErrorCode.AUTOMATION_DISABLED
    assert credentials.reads == 1
    assert adapter.calls == 0


def test_cross_process_operation_lock_rejects_before_probes_or_credentials(
    service, credentials, adapter, tmp_path
):
    lock_path = tmp_path / "authentication.lock"
    service._operation_lock = FileMutex(lock_path)
    with FileMutex(lock_path):
        assert service.login().code == ErrorCode.BUSY
        assert service.connectivity.calls == 0
        assert credentials.reads == adapter.calls == 0
    assert service.login().state == AuthState.AUTHENTICATED


def test_global_automation_off_does_not_block_explicit_manual_login(service, tmp_path):
    settings = AutomationStore(tmp_path / "automation.json")
    assert not settings.load().enabled
    assert service.login().state == AuthState.AUTHENTICATED


def test_real_bjut_unverified_never_reads_credentials(service, credentials):
    service.adapters = {"bjut": BJUTPortalAdapter}
    result = service.login()
    assert result.code == ErrorCode.PROTOCOL_UNVERIFIED
    assert result.state == AuthState.AUTH_FAILED
    assert credentials.reads == 0


def test_bjut_direct_authentication_is_fail_closed(credentials):
    adapter = BJUTPortalAdapter()
    reply = adapter.authenticate("https://portal.example.edu/", credentials.values["shared"])
    assert not reply.accepted
    assert reply.code == ErrorCode.PROTOCOL_UNVERIFIED
    assert adapter.get_status() == AuthState.AUTH_FAILED


def test_route_unconfirmed_prevents_secrets(service, network, credentials, adapter):
    network.route_safe = False
    assert service.login().code == ErrorCode.ROUTE_UNCONFIRMED
    assert credentials.reads == adapter.calls == 0


def test_network_change_before_secret_read(service, network, credentials, snapshot, adapter):
    def switch(call):
        if call == 3:
            network.current = replace(
                snapshot, adapters=(replace(snapshot.adapters[0], ssid="Other"),)
            )

    network.on_snapshot = switch
    assert service.login().code == ErrorCode.NETWORK_CHANGED
    assert credentials.reads == adapter.calls == 0


def test_network_change_after_secret_read_prevents_submission(
    service, network, credentials, snapshot, adapter
):
    def switch(call):
        if call == 4:
            network.current = replace(
                snapshot, adapters=(replace(snapshot.adapters[0], ssid="Other"),)
            )

    network.on_snapshot = switch
    assert service.login().code == ErrorCode.NETWORK_CHANGED
    assert credentials.reads == 1
    assert adapter.calls == 0


def test_no_network(service, network, credentials):
    network.current = NetworkSnapshot()
    assert service.login().state == AuthState.DISCONNECTED
    assert credentials.reads == 0


def test_missing_credentials(service, credentials):
    credentials.delete("shared")
    assert service.login().code == ErrorCode.CREDENTIALS_MISSING


@pytest.mark.parametrize(
    "code",
    [
        ErrorCode.INVALID_CREDENTIALS,
        ErrorCode.MANUAL_ACTION,
        ErrorCode.SERVER_ERROR,
        ErrorCode.PROTOCOL_CHANGED,
        ErrorCode.UNKNOWN,
    ],
)
def test_error_categories_and_no_retry(service, adapter, monkeypatch, code):
    calls = []

    def fail(*_):
        calls.append(1)
        return AdapterReply(False, code, "合成测试拒绝")

    monkeypatch.setattr(adapter, "authenticate", fail)
    result = service.login()
    assert result.code == code
    assert result.state == AuthState.AUTH_FAILED
    assert len(calls) == 1


def test_cancel_and_concurrent_call(service, cancel, credentials):
    cancel.set()
    assert service.login(cancel).code == ErrorCode.CANCELLED
    service._lock.acquire()
    try:
        assert service.login().code == ErrorCode.BUSY
    finally:
        service._lock.release()
    assert credentials.reads == 0


def test_invalid_state_transition_is_rejected():
    with pytest.raises(ValueError):
        StateMachine().transition(AuthState.AUTHENTICATED)


def test_cancel_at_final_snapshot_prevents_submission(service, network, cancel, adapter):
    network.on_snapshot = lambda call: cancel.set() if call == 4 else None
    assert service.login(cancel).code == ErrorCode.CANCELLED
    assert adapter.calls == 0


def test_network_changes_during_verification_is_unknown(service, network, snapshot):
    def switch(call):
        if call == 5:
            network.current = replace(
                snapshot, adapters=(replace(snapshot.adapters[0], ssid="Other"),)
            )

    network.on_snapshot = switch
    result = service.login()
    assert result.state == AuthState.UNKNOWN
    assert result.code == ErrorCode.NETWORK_CHANGED


def test_tls_error_with_redirect_prevents_credentials(service, credentials, adapter):
    service.connectivity = SequenceConnectivity(
        ConnectivityResult(
            portal_url="https://portal.example.edu/mock-login",
            code=ErrorCode.TLS_ERROR,
        )
    )
    assert service.login().code == ErrorCode.TLS_ERROR
    assert credentials.reads == adapter.calls == 0


def test_independent_credentials_never_fall_back_to_shared(
    service, profiles, profile, credentials, adapter
):
    profiles.upsert(replace(profile, credential_ref="independent"))
    assert service.login().code == ErrorCode.CREDENTIALS_MISSING
    assert adapter.calls == 0


def test_adapter_cannot_substitute_untrusted_target(service, adapter, credentials, monkeypatch):
    from campus_autoconnect.adapters.base import AdapterDetection

    monkeypatch.setattr(
        adapter,
        "detect",
        lambda *_: AdapterDetection(
            True,
            target_url="https://evil.example.test/steal",
        ),
    )
    assert service.login().code == ErrorCode.UNTRUSTED_TARGET
    assert credentials.reads == adapter.calls == 0


def test_config_changed_after_secret_read_prevents_submission(
    service, network, profiles, profile, adapter
):
    def change(call):
        if call == 4:
            profiles.upsert(replace(profile, enabled=False))

    network.on_snapshot = change
    assert service.login().code == ErrorCode.NETWORK_CHANGED
    assert adapter.calls == 0


def test_route_changed_immediately_before_submit_prevents_request(
    service, network, adapter, monkeypatch
):
    answers = iter((True, False))
    monkeypatch.setattr(network, "route_allows", lambda *_: next(answers))
    assert service.login().code == ErrorCode.ROUTE_UNCONFIRMED
    assert adapter.calls == 0


def test_unexpected_error_has_no_raw_network_or_secret(service, network, credentials, monkeypatch):
    def fail():
        raise RuntimeError("password=DO_NOT_LOG 192.0.2.44")

    monkeypatch.setattr(network, "snapshot", fail)
    result = service.login()
    assert result.code == ErrorCode.UNKNOWN
    assert "DO_NOT_LOG" not in result.message
    assert "192.0.2.44" not in result.message
    assert credentials.reads == 0
