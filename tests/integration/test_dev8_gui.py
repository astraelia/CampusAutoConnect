import threading

import pytest
from PySide6.QtCore import Qt, QThread, QTimer, QUrl

from campus_autoconnect.core.models import AuthResult, AuthState, ErrorCode
from campus_autoconnect.core.observation import OperationTrace
from campus_autoconnect.services.application import ApplicationServices
from campus_autoconnect.services.support import SupportService
from campus_autoconnect.ui.main_window import MainWindow

pytestmark = pytest.mark.mock


@pytest.fixture
def integrated(qtbot, profiles, credentials, network, tmp_path):
    class Authentication:
        trace = OperationTrace()

        def __init__(self) -> None:
            self.network = network

        def check(self, _):
            return AuthResult(
                AuthState.AUTH_FAILED,
                ErrorCode.CREDENTIALS_MISSING,
                "请检查当前引用的凭据。",
                self.network.current,
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
    help_panel.search.setText("网页抓包、自动跳转")
    assert "page:profiles" in help_panel.filtered[0][1]
    help_panel.link(QUrl("page:profiles"))
    assert window.tabs.currentWidget() == window.pages["profiles"]
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


def test_capture_worker_stop_is_responsive_in_wifi_editor(integrated, qtbot, monkeypatch):
    window = integrated
    assert "capture" not in window.pages
    editor = window._create_profile_editor(current_ssid="Example-Campus")
    qtbot.addWidget(editor)
    editor.show()
    panel = editor.capture_panel
    assert panel is not None
    started = threading.Event()
    capture = window.browser_capture

    def run(cancel, *, wifi_ssid):
        assert QThread.currentThread() != window.thread()
        assert wifi_ssid == "Example-Campus"
        capture.state = "recording"
        capture._wifi_ssid = wifi_ssid
        started.set()
        assert cancel.wait(3)
        capture.last_payload = {"requests": []}
        return {"request_count": 0, "login_request_observed": False}

    monkeypatch.setattr(capture, "run", run)
    qtbot.mouseClick(panel.start, Qt.LeftButton)
    pulse = threading.Event()
    QTimer.singleShot(10, pulse.set)
    try:
        qtbot.waitUntil(started.is_set)
        qtbot.waitUntil(pulse.is_set)
        assert panel.stop.isEnabled()
        assert not window.login_button.isEnabled()
        qtbot.mouseClick(panel.probe, Qt.LeftButton)
        assert capture.probe_requested.is_set()
        editor.reject()
        assert editor.isVisible()
    finally:
        window._cancel.set()
        qtbot.waitUntil(lambda: not window.busy)
    assert "空记录" in panel.state.text() and "未抓到完整登录" in panel.state.text()
    assert editor.isVisible() and panel.start.isEnabled()


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


def test_saved_credentials_require_hold_and_can_be_masked_again(integrated, credentials, qtbot):
    window = integrated
    window.show_page("credentials")
    panel = window.credentials_panel
    button = panel.reveal_button
    assert panel.saved_username.text() == panel.saved_password.text() == "********"
    qtbot.mouseClick(button, Qt.LeftButton)
    assert credentials.reads == 0
    qtbot.mousePress(button, Qt.LeftButton)
    qtbot.waitUntil(lambda: not window.busy and button.text() == "隐藏")
    qtbot.mouseRelease(button, Qt.LeftButton)
    assert panel.saved_username.text() == credentials.values["shared"].username
    assert panel.saved_password.text() == credentials.values["shared"].password
    assert credentials.reads == 1 and not panel.password.text()
    qtbot.mouseClick(button, Qt.LeftButton)
    assert button.text() == "显示" and panel.saved_password.text() == "********"
    qtbot.mousePress(button, Qt.LeftButton)
    qtbot.waitUntil(lambda: not window.busy and button.text() == "隐藏")
    qtbot.mouseRelease(button, Qt.LeftButton)
    window.show_page("overview")
    assert panel.saved_username.text() == panel.saved_password.text() == "********"


def test_wifi_editor_fills_from_integrated_capture(integrated, qtbot, tmp_path, monkeypatch):
    window = integrated
    editor = window._create_profile_editor(current_ssid="Example-Campus")
    qtbot.addWidget(editor)
    panel = editor.capture_panel
    assert panel is not None
    editor.show()
    capture = window.browser_capture
    started = threading.Event()
    path = tmp_path / "PortalCapture_session.json"

    def run(cancel, *, wifi_ssid):
        assert wifi_ssid == "Example-Campus"
        assert QThread.currentThread() != window.thread()
        started.set()
        assert cancel.wait(3)
        path.write_text("{}", encoding="utf-8")
        capture.saved_path = path
        return {"request_count": 3}

    definitions = (
        "Example-Campus",
        "https://campus.example.edu/a79.htm",
        "https://campus.example.edu:802",
    )
    monkeypatch.setattr(capture, "run", run)
    monkeypatch.setattr(capture, "wifi_configuration", lambda: definitions)
    qtbot.mouseClick(panel.start, Qt.LeftButton)
    try:
        qtbot.waitUntil(started.is_set)
        assert panel.stop.isEnabled()
    finally:
        qtbot.mouseClick(panel.stop, Qt.LeftButton)
        qtbot.waitUntil(lambda: not window.busy)
    assert (editor.ssid_edit.text(), editor.page_edit.text(), editor.api_edit.text()) == definitions
    assert editor.hosts_edit.text() == "campus.example.edu, campus.example.edu:802"
    assert not editor.allow_http.isChecked() and not editor.auto_auth.isChecked()
    assert str(path) in panel.path.text() and panel.open.isEnabled()
    assert "已回填" in panel.state.text()
