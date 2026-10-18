import threading
import time
from dataclasses import replace

import pytest
from PySide6.QtCore import Qt, QThread, QTimer
from PySide6.QtWidgets import QApplication, QDialog, QLineEdit, QMessageBox

from campus_autoconnect.core.models import (
    AuthProgress,
    AuthResult,
    AuthStage,
    AuthState,
    ErrorCode,
    ProfileIssue,
)
from campus_autoconnect.infrastructure.automation import AutomationStore
from campus_autoconnect.services.application import ApplicationServices
from campus_autoconnect.services.automation_application import AutomationService
from campus_autoconnect.services.monitor import MonitorControl
from campus_autoconnect.ui.main_window import MainWindow
from campus_autoconnect.ui.profile_editor import ProfileEditor

pytestmark = pytest.mark.mock


@pytest.fixture
def window(qtbot, profiles, credentials):
    class FakeAuthentication:
        def check(self, cancel=None):
            time.sleep(0.08)
            return AuthResult(AuthState.UNKNOWN, ErrorCode.UNTRUSTED_NETWORK, "Mock: 未知档案")

        login = check

    services = ApplicationServices(profiles, credentials, FakeAuthentication())
    widget = MainWindow(services, initial_check=False)
    qtbot.addWidget(widget)
    widget.show()
    return widget


def test_password_hidden_and_never_loaded(window, credentials):
    assert window.credentials_panel.password.echoMode() == QLineEdit.Password
    assert window.credentials_panel.password.text() == ""
    assert window.credentials_panel.username.text() == ""
    assert credentials.reads == 0
    assert "synthetic-password" not in window.message.text()


def test_save_update_delete_credentials(window, qtbot, credentials, monkeypatch):
    window.show_page("credentials")
    panel = window.credentials_panel
    panel.username.setText("synthetic-updated")
    panel.password.setText("new-synthetic-secret")
    qtbot.mouseClick(panel.save_button, Qt.LeftButton)
    assert panel.password.text() == ""
    qtbot.waitUntil(lambda: not window.busy)
    assert credentials.values["shared"].username == "synthetic-updated"
    assert "new-synthetic-secret" not in panel.status.text()
    monkeypatch.setattr(QMessageBox, "question", lambda *_: QMessageBox.Yes)
    qtbot.mouseClick(panel.delete_button, Qt.LeftButton)
    qtbot.waitUntil(lambda: not window.busy)
    assert not credentials.exists("shared")


def test_worker_keeps_event_loop_responsive_and_returns_on_main_thread(window, qtbot):
    timer_fired = threading.Event()
    callback_threads = []

    def done(result):
        callback_threads.append(QThread.currentThread())
        window._network_complete(result)

    QTimer.singleShot(15, timer_fired.set)
    window._start(window.services.authentication.check, done, "Mock checking")
    qtbot.waitUntil(timer_fired.is_set)
    assert window.busy
    qtbot.waitUntil(lambda: not window.busy)
    assert callback_threads == [QApplication.instance().thread()]
    assert "untrusted_network" in window.network_status.text()


def test_profile_editor_preserves_exact_ssid_and_refs(qtbot, profile):
    dialog = ProfileEditor(profile=profile)
    qtbot.addWidget(dialog)
    dialog.ssid_edit.setText(" Example SSID ")
    dialog.ref_edit.setText("independent")
    dialog._save()
    assert dialog.result() == QDialog.Accepted
    assert dialog.result_profile.ssid == " Example SSID "
    assert dialog.result_profile.credential_ref == "independent"


def test_profile_editor_http_requires_explicit_checkbox(qtbot, profile):
    dialog = ProfileEditor(profile=profile)
    qtbot.addWidget(dialog)
    dialog.page_edit.setText("http://portal.example.edu/a79.htm")
    dialog.api_edit.setText("http://portal.example.edu:801/")
    assert not dialog.allow_http.isChecked()
    dialog.allow_http.setChecked(True)
    dialog._save()
    assert dialog.result() == QDialog.Accepted
    assert dialog.result_profile.allow_http_auth
    assert dialog.result_profile.bjut_api_origin == "http://portal.example.edu:801"


def test_capture_editor_fill_does_not_implicitly_grant_http(qtbot, profile, monkeypatch):
    from PySide6.QtWidgets import QFileDialog

    dialog = ProfileEditor(profile=profile)
    qtbot.addWidget(dialog)
    dialog.allow_http.setChecked(True)
    monkeypatch.setattr(QFileDialog, "getOpenFileName", lambda *_: ("synthetic.json", ""))
    monkeypatch.setattr(
        "campus_autoconnect.ui.profile_editor.capture_endpoints",
        lambda _: ("http://portal.example.edu/a79.htm", "http://portal.example.edu:801"),
    )
    dialog._from_capture()
    assert not dialog.allow_http.isChecked()
    assert dialog.page_edit.text() == "http://portal.example.edu/a79.htm"
    assert dialog.api_edit.text() == "http://portal.example.edu:801"
    assert not profile.allow_http_auth


def test_endpoint_edit_requires_new_consent_and_defaults_auto_auth_off(qtbot, profile):
    existing = replace(
        profile,
        auto_auth=True,
        allow_http_auth=True,
        portal_page_url="http://portal.example.edu/a79.htm",
        bjut_api_origin="http://portal.example.edu:801",
    )
    dialog = ProfileEditor(profile=existing)
    qtbot.addWidget(dialog)
    assert dialog.allow_http.isChecked() and dialog.auto_auth.isChecked()
    dialog.api_edit.setText("http://portal.example.edu:803")
    assert not dialog.allow_http.isChecked() and not dialog.auto_auth.isChecked()
    assert "尚未明确允许 HTTP" in dialog.setup_status.text()
    dialog.allow_http.setChecked(True)
    dialog._save()
    assert dialog.result() == QDialog.Accepted
    assert dialog.result_profile.allow_http_auth and not dialog.result_profile.auto_auth
    assert dialog.result_profile.credential_ref == existing.credential_ref
    assert existing.auto_auth and existing.bjut_api_origin.endswith(":801")


@pytest.mark.parametrize("field", ["ssid_edit", "page_edit", "api_edit", "hosts_edit"])
def test_zero_mac_permission_is_bound_to_network_and_targets(qtbot, profile, field):
    existing = replace(
        profile,
        auto_auth=True,
        allow_http_auth=True,
        allow_zero_mac=True,
        portal_page_url="http://portal.example.edu/a79.htm",
        bjut_api_origin="http://portal.example.edu:801",
    )
    dialog = ProfileEditor(profile=existing)
    qtbot.addWidget(dialog)
    assert dialog.allow_zero_mac.isChecked() and dialog.auto_auth.isChecked()
    widget = getattr(dialog, field)
    widget.setText(widget.text() + "x")
    assert not dialog.allow_zero_mac.isChecked() and not dialog.auto_auth.isChecked()
    assert existing.allow_zero_mac


def test_zero_mac_permission_is_saved_only_by_explicit_editor_action(qtbot, profile):
    existing = replace(
        profile,
        auto_auth=True,
        portal_page_url="https://portal.example.edu/a79.htm",
        bjut_api_origin="https://portal.example.edu:802",
    )
    dialog = ProfileEditor(profile=existing)
    qtbot.addWidget(dialog)
    assert not dialog.allow_zero_mac.isChecked()
    dialog.allow_zero_mac.setChecked(True)
    assert not dialog.auto_auth.isChecked()
    dialog._save()
    assert dialog.result_profile.allow_zero_mac and not dialog.result_profile.auto_auth
    assert not existing.allow_zero_mac


@pytest.mark.parametrize("present", [True, False])
def test_overview_opens_exact_current_profile_asynchronously(
    window, qtbot, profiles, profile, snapshot, credentials, monkeypatch, present
):
    if not present:
        profiles.remove(profile.profile_id)
    progress = AuthProgress(
        stage=AuthStage.TARGET,
        profile_matched=present,
        profile_issues=(ProfileIssue.PAGE_MISSING, ProfileIssue.API_MISSING) if present else (),
        credential_read_attempted=False,
        login_request_attempted=False,
    )
    window._network_complete(
        AuthResult(
            AuthState.UNKNOWN,
            ErrorCode.UNTRUSTED_TARGET,
            "合成数据：认证配置尚未完成。",
            network=snapshot,
            progress=progress,
        )
    )
    assert window.setup_button.isEnabled()
    assert "未发起" in window.network_reason.text()
    if present:
        assert "待补全" in window.network_status.text()
        assert "未填写认证页" in window.network_reason.text()
        assert "待补全" in window.table.item(0, 5).text()
    read = profiles.list
    timer_fired, opened = [], []

    def slow_read():
        time.sleep(0.06)
        return read()

    monkeypatch.setattr(profiles, "list", slow_read)
    monkeypatch.setattr(
        window, "edit_profile", lambda **kwargs: opened.append((kwargs, QThread.currentThread()))
    )
    QTimer.singleShot(10, lambda: timer_fired.append(True))
    qtbot.mouseClick(window.setup_button, Qt.LeftButton)
    qtbot.waitUntil(lambda: bool(timer_fired))
    assert window.busy
    qtbot.waitUntil(lambda: bool(opened) and not window.busy)
    assert opened[0][0]["profile"] == (profile if present else None)
    assert opened[0][0]["current_ssid"] == snapshot.ssid
    assert opened[0][1] == QApplication.instance().thread()
    assert credentials.reads == 0


def test_gui_add_edit_remove_profiles(window, qtbot, profile, monkeypatch):
    window.show_page("profiles")

    class AcceptedEditor:
        def __init__(self, *_args, **kwargs):
            old = kwargs.get("profile")
            self.result_profile = (
                replace(profile, profile_id="new", ssid="Study", display_name="学习室")
                if old is None
                else replace(old, display_name="已编辑")
            )

        def exec(self):
            return QDialog.Accepted

    monkeypatch.setattr("campus_autoconnect.ui.main_window.ProfileEditor", AcceptedEditor)
    qtbot.mouseClick(window.add_button, Qt.LeftButton)
    qtbot.waitUntil(lambda: not window.busy)
    assert window.table.rowCount() == 2
    window.table.selectRow(1)
    qtbot.mouseClick(window.edit_button, Qt.LeftButton)
    qtbot.waitUntil(lambda: not window.busy)
    assert window.services.profiles.match("Study").display_name == "已编辑"
    window.table.selectRow(1)
    monkeypatch.setattr(QMessageBox, "question", lambda *_: QMessageBox.Yes)
    qtbot.mouseClick(window.remove_button, Qt.LeftButton)
    qtbot.waitUntil(lambda: not window.busy)
    assert window.table.rowCount() == 1


def test_error_display_has_no_exception_secret(window, qtbot):
    def fail():
        raise RuntimeError("password=DO_NOT_SHOW_ME")

    window._start(fail, lambda _: None, "checking")
    qtbot.waitUntil(lambda: not window.busy)
    assert "DO_NOT_SHOW_ME" not in window.message.text()
    assert "操作失败" in window.message.text()


def test_diagnostic_projection_hides_identifiers(window, snapshot):
    window.services.last_result = AuthResult(
        AuthState.UNKNOWN,
        ErrorCode.UNKNOWN,
        "unused",
        snapshot,
        "https://portal.example.edu/?token=DO_NOT_SHARE",
    )
    serialized = str(window.services.diagnostics())
    assert all(
        x not in serialized
        for x in ("Example-Campus", "192.0.2.10", "portal.example.edu", "DO_NOT_SHARE")
    )


def test_m2_settings_run_off_main_thread_and_do_not_start_runtime(window, qtbot, tmp_path):
    observed_threads = []

    class Startup:
        calls = 0

        def status(self):
            self.calls += 1
            observed_threads.append(QThread.currentThread())
            time.sleep(0.08)
            return {"installed": False, "owned": False, "configured": False, "enabled": False}

    settings = AutomationStore(tmp_path / "automation.json")
    startup = Startup()
    control = MonitorControl(tmp_path)
    window.services.automation = AutomationService(settings, control, startup, None)
    panel = window.automation_panel
    panel.show()
    window.show_page("automation")
    assert not panel.save_button.isEnabled()
    timer_fired = threading.Event()
    QTimer.singleShot(10, timer_fired.set)
    qtbot.mouseClick(panel.refresh_button, Qt.LeftButton)
    qtbot.waitUntil(timer_fired.is_set)
    assert window.busy
    qtbot.waitUntil(lambda: not window.busy)
    assert panel.save_button.isEnabled()
    assert not panel.enabled.isChecked()
    assert "STOPPED" in panel.status.text()
    assert observed_threads and observed_threads[0] != QApplication.instance().thread()
    panel.enabled.setChecked(True)
    qtbot.mouseClick(panel.save_button, Qt.LeftButton)
    qtbot.waitUntil(lambda: not window.busy)
    assert settings.load().enabled
    assert not control.status()["running"]
    assert startup.calls == 1
    # Manual network controls remain available after disabling the global preference.
    panel.enabled.setChecked(False)
    qtbot.mouseClick(panel.save_button, Qt.LeftButton)
    qtbot.waitUntil(lambda: not window.busy)
    assert window.login_button.isEnabled()
    assert not settings.load().enabled


def test_stopped_monitor_and_old_task_have_specific_repair_guidance(window):
    window._automation_complete(
        {
            "enabled": True,
            "monitor": {"state": "STOPPED", "error_code": "none"},
            "startup": dict(installed=True, owned=True, configured=False, enabled=True),
        }
    )
    panel = window.automation_panel
    assert "当前不会自动认证" in panel.status.text()
    assert "修复旧版登录启动" in panel.status.text()
    assert panel.startup_repair_button.isEnabled()
    window._automation_complete(
        {
            "enabled": True,
            "monitor": {"state": "STOPPED", "error_code": "none"},
            "startup": dict(installed=True, owned=False, configured=False, enabled=True),
        }
    )
    assert not panel.startup_repair_button.isEnabled()
    assert "归属无法确认" in panel.status.text()


def test_explicit_save_and_start_runs_in_worker(window, qtbot, tmp_path, monkeypatch):
    calls = []
    settings = AutomationStore(tmp_path / "automation.json")

    class Startup:
        def status(self):
            return dict.fromkeys(("installed", "owned", "configured", "enabled"), False)

        def enable(self):
            raise AssertionError("This action must not install a startup task")

        repair = disable = enable

    automation = AutomationService(settings, MonitorControl(tmp_path), Startup(), None)
    monkeypatch.setattr(
        automation, "start_background", lambda: calls.append(QThread.currentThread())
    )
    window.services.automation = automation
    window._automation_complete(automation.overview())
    panel = window.automation_panel
    panel.enabled.setChecked(True)
    window.show_page("automation")
    qtbot.mouseClick(panel.save_start_button, Qt.LeftButton)
    qtbot.waitUntil(lambda: not window.busy)
    assert settings.load().enabled
    assert calls and calls[0] != QApplication.instance().thread()
    assert not panel._dirty


def test_zero_context_status_is_visible_without_raw_network_identifiers(window):
    window._network_complete(
        AuthResult(
            AuthState.AUTH_FAILED,
            ErrorCode.ZERO_MAC_PERMISSION_REQUIRED,
            "认证页返回全零 MAC；请明确允许本档案兼容后手动测试。",
            progress=AuthProgress(
                stage=AuthStage.PREPARE,
                zero_mac_observed=True,
                credential_read_attempted=False,
                login_request_attempted=False,
            ),
        )
    )
    assert "尚未允许本档案兼容" in window.network_reason.text()
    assert "未发起" in window.network_reason.text()
    assert "zero_mac_permission_required" in window.network_status.text()
