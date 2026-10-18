import threading
import time

import pytest
from PySide6.QtCore import QThread, QTimer
from PySide6.QtNetwork import QLocalSocket
from PySide6.QtWidgets import QApplication

from campus_autoconnect.core.errors import CampusError
from campus_autoconnect.core.models import AuthResult, AuthState, ErrorCode
from campus_autoconnect.infrastructure.desktop import DesktopPreferences
from campus_autoconnect.services.application import ApplicationServices
from campus_autoconnect.services.desktop import DesktopService
from campus_autoconnect.ui.instance import GuiInstance
from campus_autoconnect.ui.main_window import MainWindow
from campus_autoconnect.ui.theme import app_icon, apply_theme
from campus_autoconnect.ui.tray import TrayController

pytestmark = pytest.mark.mock


@pytest.fixture
def window(qtbot, profiles, credentials, tmp_path):
    services = ApplicationServices(profiles, credentials, None, desktop=DesktopService(tmp_path))
    widget = MainWindow(services, initial_check=False)
    qtbot.addWidget(widget)
    widget.show()
    return widget


def test_capture_analysis_runs_in_worker_and_does_not_read_credentials(window, qtbot, monkeypatch):
    entered, release = threading.Event(), threading.Event()
    from PySide6.QtWidgets import QFileDialog

    def analyze(path):
        assert QThread.currentThread() != window.thread()
        entered.set()
        assert release.wait(3)
        return {
            "request_count": 16,
            "http_count": 16,
            "https_count": 0,
            "login_request_observed": True,
            "server_success_summary_observed": True,
            "sensitive_query_values_hidden": True,
            "transport_status": "仅观察到 HTTP，当前 HTTPS 安全规则仍阻止真实认证。",
        }

    monkeypatch.setattr(QFileDialog, "getOpenFileName", lambda *_: ("synthetic.json", ""))
    monkeypatch.setattr(window.services, "analyze_capture", analyze)
    window.analyze_capture()
    pulse = threading.Event()
    QTimer.singleShot(10, pulse.set)
    try:
        qtbot.waitUntil(entered.is_set)
        qtbot.waitUntil(pulse.is_set)
        assert window.busy and not window.capture_button.isEnabled()
    finally:
        release.set()
        qtbot.waitUntil(lambda: not window.busy)
    assert "HTTP 16" in window.capture_summary.text()
    assert "不能代替" in window.capture_summary.text()
    assert window.services.credentials.reads == 0
    assert window.services.last_result is None


def test_close_to_tray_preserves_window_and_clears_unsaved_password(window, qtbot):
    window.tray_available = True
    window.credentials_panel.password.setText("synthetic-unsaved")
    with qtbot.waitSignal(window.hidden_to_tray):
        window.close()
    assert not window.isVisible()
    assert not window._quitting
    assert window.credentials_panel.password.text() == ""
    window.tray_available = False


def test_exit_waits_for_work_and_background_before_emitting_ready(window, qtbot):
    stopped = threading.Event()

    class Automation:
        def stop_and_wait(self):
            time.sleep(0.08)
            stopped.set()

    window.services.automation = Automation()
    window._start(lambda: time.sleep(0.08), lambda _: None, "working")
    pulse = threading.Event()
    QTimer.singleShot(15, pulse.set)
    with qtbot.waitSignal(window.exit_ready, timeout=3000):
        window.request_exit()
        assert not stopped.is_set()
        qtbot.waitUntil(pulse.is_set)
        assert not window._allow_close
    assert stopped.is_set() and not window.busy
    assert not window.isVisible()


def test_passive_status_does_not_overwrite_unsaved_global_choice(window):
    panel = window.automation_panel
    snapshot = {
        "enabled": False,
        "monitor": {"state": "DISABLED", "error_code": "none"},
        "startup": {"available": False},
    }
    panel.show_status(snapshot)
    panel.enabled.setChecked(True)
    panel.show_status(snapshot)
    assert panel.enabled.isChecked()
    panel.mark_saved()
    panel.show_status(snapshot)
    assert not panel.enabled.isChecked()


def test_failed_shutdown_restores_hidden_window_and_reports_failure(window, qtbot):
    class Automation:
        def stop_and_wait(self):
            raise CampusError(ErrorCode.TIMEOUT, "后台仍在结束有界查询，请稍候再点击退出。")

    window.services.automation = Automation()
    window.hide()
    window.request_exit()
    qtbot.waitUntil(lambda: not window.busy)
    assert window.isVisible()
    assert not window._quitting and not window._allow_close
    assert "后台仍在" in window.message.text()
    assert window.exit_button.isEnabled()
    window.services.automation = None


def test_full_exit_waits_for_native_thread_cleanup_not_only_finished_signal(
    window, qtbot, monkeypatch
):
    class Automation:
        def stop_and_wait(self):
            pass

    window.services.automation = Automation()
    observed, release = threading.Event(), threading.Event()
    window.request_exit()
    target = window._thread
    original = QThread.wait

    def wait(thread, timeout):
        if thread is target and not release.is_set():
            observed.set()
            return False
        return original(thread, timeout)

    monkeypatch.setattr(QThread, "wait", wait)
    try:
        qtbot.waitUntil(observed.is_set)
        assert window.busy and not window._allow_close
        assert not window.exit_button.isEnabled()
    finally:
        release.set()
        qtbot.waitUntil(lambda: not window.busy)
    assert window._allow_close


def test_preferences_save_is_async_and_does_not_change_automation(window, qtbot, tmp_path):
    window.show_page("settings")
    window.theme.setCurrentIndex(window.theme.findData("dark"))
    window.close_to_tray.setChecked(False)
    with qtbot.waitSignal(window.preferences_changed):
        window.save_preferences()
    qtbot.waitUntil(lambda: not window.busy)
    assert window.preferences == DesktopPreferences("dark", False)
    assert window.services.desktop.load_preferences() == window.preferences
    assert not (tmp_path / "automation.json").exists()


def test_stale_status_cannot_undo_switch_after_user_saves(window, qtbot):
    entered, release = threading.Event(), threading.Event()
    snapshot = {
        "enabled": False,
        "monitor": {"state": "DISABLED", "error_code": "none"},
        "startup": {"available": False},
    }

    class Automation:
        enabled = False

        def snapshot(self):
            entered.set()
            assert release.wait(2)
            return snapshot

        def set_enabled(self, enabled):
            self.enabled = enabled

        def stop_and_wait(self):
            pass

    automation = Automation()
    window.services.automation = automation
    window._automation_complete(snapshot)
    window.poll_status()
    try:
        qtbot.waitUntil(entered.is_set)
        window.automation_panel.enabled.setChecked(True)
        window.save_automation()
        qtbot.waitUntil(lambda: not window.busy)
        assert automation.enabled
    finally:
        release.set()
        qtbot.waitUntil(lambda: window._poll_thread is None)
    assert window.automation_panel.enabled.isChecked()


def test_tray_actions_use_same_workers_and_tooltip_has_no_network_identifiers(
    window, qtbot, monkeypatch
):
    monkeypatch.setattr("PySide6.QtWidgets.QSystemTrayIcon.isSystemTrayAvailable", lambda: False)

    class Authentication:
        calls = 0

        def check(self, _):
            self.calls += 1
            time.sleep(0.08)
            return AuthResult(AuthState.UNKNOWN, ErrorCode.UNTRUSTED_NETWORK, "synthetic")

    window.services.authentication = Authentication()
    tray = TrayController(window)
    tray.actions["check"].trigger()
    assert window.busy
    tray.update_actions()
    assert not tray.actions["login"].isEnabled()
    qtbot.waitUntil(lambda: not window.busy)
    assert window.services.authentication.calls == 1
    assert "untrusted_network" in tray.tray.toolTip()
    assert "SSID" not in tray.tray.toolTip()
    tray.close()


def test_gui_single_instance_only_accepts_show_message(qapp, qtbot, tmp_path):
    first = GuiInstance(tmp_path)
    second = GuiInstance(tmp_path)
    assert first.acquire()
    try:
        with qtbot.waitSignal(first.activated, timeout=3000):
            assert not second.acquire()
        assert first.mutex._stream is not None
    finally:
        second.close()
        first.close()
    third = GuiInstance(tmp_path)
    assert third.acquire()
    third.close()


def test_icon_available_at_all_common_sizes_and_theme_can_be_reset(qapp):
    icon = app_icon()
    assert not icon.isNull()
    assert {size.width() for size in icon.availableSizes()} == {16, 24, 32, 48, 64, 128, 256}
    before = QApplication.palette()
    try:
        apply_theme(qapp, "dark")
        assert qapp.palette().window().color().lightness() < 60
        apply_theme(qapp, "light")
        assert qapp.palette().window().color().lightness() > 200
        apply_theme(qapp, "system")
    finally:
        qapp.setPalette(before)


def test_window_activation_handles_fragmented_messages_and_rejects_other_commands(
    qapp, qtbot, tmp_path
):
    instance = GuiInstance(tmp_path)
    assert instance.acquire()
    observed = []
    instance.activated.connect(lambda: observed.append(True))
    socket = QLocalSocket()
    try:
        socket.connectToServer(instance.name)
        assert socket.waitForConnected(1000)
        assert socket.write(b"sh") == 2
        qtbot.waitUntil(lambda: socket.bytesToWrite() == 0)
        qtbot.wait(30)
        assert observed == []
        with qtbot.waitSignal(instance.activated, timeout=2000):
            assert socket.write(b"ow") == 2
            qtbot.waitUntil(lambda: socket.bytesToWrite() == 0)
        socket.abort()
        socket.connectToServer(instance.name)
        assert socket.waitForConnected(1000)
        assert socket.write(b"login") == 5
        qtbot.waitUntil(lambda: socket.bytesToWrite() == 0)
        qtbot.wait(30)
        assert observed == [True]
    finally:
        socket.abort()
        instance.close()
