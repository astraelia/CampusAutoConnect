import threading

import pytest
from PySide6.QtCore import QThread, QTimer, QUrl

from campus_autoconnect.core.models import AuthResult, AuthState, ErrorCode
from campus_autoconnect.core.observation import OperationTrace
from campus_autoconnect.services.application import ApplicationServices
from campus_autoconnect.services.support import SupportService
from campus_autoconnect.ui.main_window import MainWindow

pytestmark = pytest.mark.mock


@pytest.fixture
def integrated(qtbot, profiles, credentials, snapshot, tmp_path):
    class Authentication:
        trace = OperationTrace()

        def check(self, _):
            return AuthResult(
                AuthState.AUTH_FAILED,
                ErrorCode.CREDENTIALS_MISSING,
                "请检查当前引用的凭据。",
                snapshot,
            )

        login = check

    authentication = Authentication()
    services = ApplicationServices(profiles, credentials, authentication)
    services.support = SupportService(tmp_path, authentication, tmp_path / "reports")
    window = MainWindow(services, initial_check=False)
    qtbot.addWidget(window)
    window.show()
    return window


def test_saved_credentials_restart_status_never_refills_inputs(
    integrated, credentials, profiles, qtbot
):
    window = integrated
    panel = window.credentials_panel
    assert credentials.reads == 0
    panel.username.setText("new-private-account")
    panel.password.setText("new-private-password")
    window.save_credentials()
    assert panel.password.text() == ""
    qtbot.waitUntil(lambda: not window.busy)
    assert "已保存并复核" in panel.status.text()
    assert panel.username.text() == "" and panel.password.text() == ""
    reads = credentials.reads
    services = ApplicationServices(profiles, credentials, None)
    restarted = MainWindow(services, initial_check=False)
    qtbot.addWidget(restarted)
    restarted._credential_reference_changed("shared")
    qtbot.waitUntil(lambda: not restarted.busy)
    assert "上次保存/检查记录" in restarted.credentials_panel.status.text()
    assert "本次启动尚未重新检查" in restarted.credentials_panel.status.text()
    assert credentials.reads == reads
    assert restarted.credentials_panel.password.text() == ""


def test_user_failure_navigates_to_diagnosis_then_credential_page(integrated, qtbot):
    window = integrated
    window._network_action(True)
    qtbot.waitUntil(lambda: not window.busy)
    assert window.tabs.currentWidget() == window.pages["logs"]
    window.navigate_problem()
    assert window.tabs.currentWidget() == window.pages["credentials"]


def test_help_is_searchable_and_links_only_navigate(integrated, credentials):
    window = integrated
    help_panel = window.help_panel
    assert len(help_panel.chapters) == 12
    help_panel.search.setText("保存账号密码")
    assert help_panel.topics.count() == 1
    assert "已保存并复核" in help_panel.reader.toPlainText()
    help_panel.link(QUrl("page:credentials"))
    assert window.tabs.currentWidget() == window.pages["credentials"]
    help_panel.link(QUrl("https://evil.example.invalid/"))
    assert window.tabs.currentWidget() == window.pages["credentials"]
    assert credentials.reads == 0


def test_checking_saved_status_does_not_discard_new_input(integrated, qtbot):
    panel = integrated.credentials_panel
    panel.username.setText("unsaved-new-account")
    panel.password.setText("unsaved-new-password")
    integrated.check_credentials()
    qtbot.waitUntil(lambda: not integrated.busy)
    assert "已找到" in panel.status.text()
    assert panel.username.text() == "unsaved-new-account"
    assert panel.password.text() == "unsaved-new-password"


def test_capture_worker_stop_is_responsive_and_returns_to_capture(integrated, qtbot, monkeypatch):
    window = integrated
    started = threading.Event()

    def run(cancel):
        assert QThread.currentThread() != window.thread()
        window.browser_capture.state = "recording"
        started.set()
        assert cancel.wait(3)
        return {"request_count": 0, "login_request_observed": False}

    monkeypatch.setattr(window.browser_capture, "run", run)
    window.start_browser_capture()
    pulse = threading.Event()
    QTimer.singleShot(10, pulse.set)
    try:
        qtbot.waitUntil(started.is_set)
        qtbot.waitUntil(pulse.is_set)
        assert window.capture_panel.stop.isEnabled()
        assert not window.login_button.isEnabled()
    finally:
        window._cancel.set()
        qtbot.waitUntil(lambda: not window.busy)
    assert "空记录" in window.capture_panel.state.text()
    assert window.tabs.currentWidget() == window.pages["capture"]


def test_stale_receipt_callback_does_not_overwrite_another_reference(
    integrated, qtbot, monkeypatch
):
    from campus_autoconnect.services.credential_management import CredentialStatus

    window = integrated
    entered, release = threading.Event(), threading.Event()

    def snapshot(reference):
        entered.set()
        assert release.wait(3)
        return CredentialStatus("confirmed")

    monkeypatch.setattr(window.services.credential_management, "snapshot", snapshot)
    window._credential_reference_changed("shared")
    try:
        qtbot.waitUntil(entered.is_set)
        window.credentials_panel.reference.setText("independent")
    finally:
        release.set()
        qtbot.waitUntil(lambda: not window.busy)
    assert "已保存并复核" not in window.credentials_panel.status.text()
