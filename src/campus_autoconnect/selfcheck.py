"""Explicit isolated Windows checks. Never sends a campus login or uses real credentials."""

import argparse
import json
import os
import platform
import re
import sys
import tempfile
import time
import uuid
from contextlib import contextmanager
from pathlib import Path

from campus_autoconnect import __version__
from campus_autoconnect.core.errors import CampusError


@contextmanager
def isolated_data():
    previous = os.environ.get("LOCALAPPDATA")
    with tempfile.TemporaryDirectory(prefix="campus-m3-check-") as directory:
        os.environ["LOCALAPPDATA"] = directory
        try:
            yield Path(directory) / "CampusAutoConnect"
        finally:
            if previous is None:
                os.environ.pop("LOCALAPPDATA", None)
            else:
                os.environ["LOCALAPPDATA"] = previous


def runtime_check() -> dict:
    import ssl

    import httpx
    from PySide6 import __version__ as qt_version

    from campus_autoconnect.infrastructure.launch import monitor_command
    from campus_autoconnect.security.credentials import WindowsCredentialStore

    launch = monitor_command()
    launch.validate()
    context = ssl.create_default_context()
    client = httpx.Client(trust_env=False, verify=True, follow_redirects=False)
    client.close()
    import playwright

    driver = Path(playwright.__file__).parent / "driver"
    return {
        "playwright_driver_available": (driver / "node.exe").is_file()
        and (driver / "package/cli.js").is_file(),
        "background_executable_available": True,
        "tls_certificate_verification": context.verify_mode == ssl.CERT_REQUIRED,
        "windows_vault_backend_available": type(WindowsCredentialStore._backend()).__name__
        == "WinVaultKeyring",
        "qt_version": qt_version,
        "httpx_version": httpx.__version__,
    }


def browser_check() -> dict:
    from campus_autoconnect.selfcheck_browser import run

    return run()


def network_check() -> dict:
    from campus_autoconnect.selfcheck_network import run

    return run()


def background_check() -> dict:
    from campus_autoconnect.infrastructure.locking import FileMutex
    from campus_autoconnect.services.application import build_services

    with isolated_data():
        automation = build_services().automation
        report = {"default_off": not automation.settings.load().enabled}
        try:
            automation.start_background(duration=12)
            deadline = time.monotonic() + 6
            status = automation.control.status()
            while status.get("state") != "DISABLED" and time.monotonic() < deadline:
                time.sleep(0.05)
                status = automation.control.status()
            report["running_disabled"] = status.get("state") == "DISABLED"
            duplicate = FileMutex(automation.control.lock_path)
            report["singleton_enforced"] = not duplicate.acquire()
            duplicate.release()
            automation.stop_and_wait(timeout=20)
            report["stopped"] = not automation.control.status()["running"]
        finally:
            automation.stop_and_wait(timeout=20)
        return report


def credential_check() -> dict:
    from campus_autoconnect.core.models import Credentials
    from campus_autoconnect.security.credentials import WindowsCredentialStore

    store = WindowsCredentialStore()
    # WinVaultKeyring moves an existing service credential when another user is saved.
    # A separate service is necessary even though the reference is already random.
    store.SERVICE = "CampusAutoConnect/selfcheck/" + uuid.uuid4().hex
    reference = "m3-smoke-" + uuid.uuid4().hex
    first = Credentials("synthetic-m3", "synthetic-m3-password")
    second = Credentials("synthetic-m3-updated", "synthetic-m3-updated-password")
    report = {}
    try:
        store.set(reference, first)
        report["created"] = store.get(reference) == first
        store.set(reference, second)
        report["updated"] = store.get(reference) == second
    finally:
        store.delete(reference)
        report["deleted"] = not store.exists(reference)
    return report


def startup_check() -> dict:
    from campus_autoconnect.core.network import _run_powershell
    from campus_autoconnect.infrastructure.startup import WindowsStartupService

    prefix = "CampusAutoConnect-M3-Smoke-" + uuid.uuid4().hex + "-"
    disable_before_repair = False

    def temporary_runner(script, payload):
        name = "$name = 'CampusAutoConnect-M2-' + $sid"
        trigger = "$trigger.Delay = 'PT0S'"
        if script.count(name) != 1 or script.count(trigger) != 1:
            raise ValueError("Temporary task check requires review")
        script = script.replace(name, f"$name = '{prefix}' + $sid")
        script = script.replace(trigger, trigger + "\n    $trigger.Enabled = $false")
        script = script.replace(
            "$xml.Task.Triggers.LogonTrigger.Enabled -ne 'false' -and",
            "$xml.Task.Triggers.LogonTrigger.Enabled -eq 'false' -and",
        )
        if disable_before_repair:
            before = "$existing = Find-ManagedTask\n$before = Inspect-ManagedTask $existing"
            if script.count(before) != 1:
                raise ValueError("Temporary repair check requires review")
            script = script.replace(
                before,
                "Disable-ScheduledTask -TaskPath '\\' -TaskName $name | Out-Null\n" + before,
            )
        script = script.replace(
            "ConvertTo-Json -Compress -InputObject (Inspect-ManagedTask $existing)",
            """
if ($existing) {
    $checkXml = [xml](Export-ScheduledTask -TaskPath '\\' -TaskName $name)
    if ($checkXml.Task.Triggers.LogonTrigger.Enabled -ne 'false') {
        throw 'Temporary trigger must remain disabled'
    }
}
ConvertTo-Json -Compress -InputObject (Inspect-ManagedTask $existing)
""",
        )
        return _run_powershell(script, payload)

    startup = WindowsStartupService(runner=temporary_runner)
    report = {}
    try:
        if startup.status()["installed"]:
            raise ValueError("Temporary task collision")
        with tempfile.TemporaryDirectory(prefix="campus-old-program-") as old_directory:
            # A never-executed placeholder gives the temporary task an old path.
            # Its trigger is disabled by temporary_runner before registration.
            old_executable = Path(old_directory) / "CampusAutoConnect.exe"
            old_executable.touch()
            old = WindowsStartupService(executable=old_executable, runner=temporary_runner)
            fields = ("installed", "owned", "configured", "enabled")
            registered = old.enable()
            report["registered_disabled_trigger"] = all(registered[key] for key in fields)
            status = startup.status()
            report["legacy_task_recognized"] = status["owned"] and not status["configured"]
            repaired = startup.repair()
            report["repaired_current_program"] = all(repaired[key] for key in fields)
            current = startup.status()
            report["current_user_limited_and_owned"] = all(current[key] for key in fields)
            disable_before_repair = True
            repaired = startup.repair()
            report["repair_preserves_disabled"] = (
                repaired["installed"]
                and repaired["owned"]
                and repaired["configured"]
                and not repaired["enabled"]
            )
            disable_before_repair = False
    finally:
        report["removed"] = not startup.disable()["installed"]
    return report


def startup_ui_check() -> dict:
    """Exercise the actual --startup dispatcher with isolated data and auto-auth off."""
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    from PySide6.QtCore import QCoreApplication, QEvent, QTimer
    from PySide6.QtWidgets import QApplication

    from campus_autoconnect import entry
    from campus_autoconnect.services.application import build_services
    from campus_autoconnect.ui import app as desktop_app

    with isolated_data() as directory:
        services = build_services(directory, report_root=directory / "reports")

        class NoTaskChanges:
            def status(self):
                return dict(installed=False, owned=False, configured=False, enabled=False)

        services.automation.startup = NoTaskChanges()
        original_window, original_builder = desktop_app.MainWindow, desktop_app.build_services
        checks, windows, apps = {}, [], []
        deadline = time.monotonic() + 25

        class ProbeWindow(original_window):
            def __init__(self, *args, **kwargs):
                super().__init__(*args, **kwargs)
                windows.append(self)
                apps.append(QApplication.instance())
                timer = QTimer(self)
                timer.setInterval(50)

                def poll():
                    if self.busy or self._quitting:
                        return
                    overview = services.automation.cached_status
                    if overview and overview["monitor"]["state"] == "DISABLED":
                        checks["startup_dispatch_used"] = self.startup
                        checks["background_running_disabled"] = overview["monitor"]["running"]
                        checks[
                            "global_auth_still_off"
                        ] = not services.automation.settings.load().enabled
                        checks["tray_or_visible_fallback"] = (
                            not self.isVisible() if self.tray_available else self.isVisible()
                        )
                        checks["presentation"] = "tray" if self.tray_available else "visible_window"
                        checks["no_automatic_report_session"] = not any(
                            path.is_dir() for path in services.support.session.root.iterdir()
                        )
                        timer.stop()
                        self.request_exit()
                    elif time.monotonic() >= deadline:
                        checks["startup_ready_within_deadline"] = False
                        timer.stop()
                        self.request_exit()

                timer.timeout.connect(poll)
                timer.start()

        desktop_app.MainWindow = ProbeWindow
        desktop_app.build_services = lambda: services
        try:
            checks["entry_exit_zero"] = entry._dispatch(["--startup"]) == 0
            checks["background_stopped_on_exit"] = not services.automation.control.status()[
                "running"
            ]
            return checks
        finally:
            desktop_app.MainWindow, desktop_app.build_services = original_window, original_builder
            services.automation.stop_and_wait(timeout=20)
            services.support.close()
            for window in windows:
                window.deleteLater()
            QCoreApplication.sendPostedEvents(None, QEvent.DeferredDelete)


def gui_check(screenshots: Path | None) -> dict:
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    from PySide6.QtCore import QCoreApplication, QEvent
    from PySide6.QtWidgets import QApplication

    from campus_autoconnect.core.models import (
        AuthProgress,
        AuthResult,
        AuthStage,
        AuthState,
        ErrorCode,
        NetworkAdapter,
        NetworkProfile,
        NetworkSnapshot,
        ProfileIssue,
    )
    from campus_autoconnect.services.application import build_services
    from campus_autoconnect.ui.app import configure_application
    from campus_autoconnect.ui.instance import GuiInstance
    from campus_autoconnect.ui.main_window import MainWindow
    from campus_autoconnect.ui.profile_editor import ProfileEditor
    from campus_autoconnect.ui.theme import app_icon, apply_theme

    app = QApplication([])
    configure_application(app)
    with isolated_data() as directory:
        first, second = GuiInstance(directory), GuiInstance(directory)
        report = {"gui_singleton_lock": first.acquire()}
        activated = []
        first.activated.connect(lambda: activated.append(True))
        try:
            report["duplicate_gui_reuses_window"] = not second.acquire()
            deadline = time.monotonic() + 3
            while not activated and time.monotonic() < deadline:
                app.processEvents()
                time.sleep(0.005)
            report["activation_message_received"] = bool(activated)
        finally:
            second.close()
            first.close()
            app.processEvents()
            second.deleteLater()
            first.deleteLater()
            QCoreApplication.sendPostedEvents(None, QEvent.DeferredDelete)
        services = build_services(directory, report_root=directory / "reports")
        # No native network queries, credentials, startup tasks or monitor are used here.
        services.profiles.upsert(NetworkProfile("synthetic", "示例宿舍", "Example-Campus-Dorm"))
        window = MainWindow(services, initial_check=False)
        window._automation_complete(
            {
                "enabled": False,
                "monitor": {"state": "STOPPED", "error_code": "none"},
                "startup": dict.fromkeys(("installed", "owned", "configured", "enabled"), False),
            }
        )
        window._network_complete(
            AuthResult(
                AuthState.UNKNOWN,
                ErrorCode.UNTRUSTED_TARGET,
                "演示数据：HTTP 认证入口尚未获得本档案明确许可。",
                network=NetworkSnapshot(
                    (
                        NetworkAdapter(
                            7,
                            "Example Wi-Fi",
                            "synthetic",
                            True,
                            ssid="Example-Campus-Dorm",
                            ipv4=("192.0.2.10",),
                        ),
                    )
                ),
                progress=AuthProgress(
                    stage=AuthStage.TARGET,
                    profile_matched=True,
                    profile_issues=(
                        ProfileIssue.PAGE_MISSING,
                        ProfileIssue.API_MISSING,
                        ProfileIssue.HTTP_PERMISSION,
                    ),
                    credential_read_attempted=False,
                    login_request_attempted=False,
                ),
            )
        )
        report["legacy_setup_guidance_visible"] = (
            "档案待补全" in window.network_status.text()
            and "未发起" in window.network_reason.text()
            and window.setup_button.isEnabled()
        )
        report["profile_readiness_visible"] = "待补全" in window.table.item(0, 5).text()
        window._network_complete(
            AuthResult(
                AuthState.AUTH_FAILED,
                ErrorCode.ZERO_MAC_PERMISSION_REQUIRED,
                "演示数据：认证页返回全零 MAC，请在当前网络档案明确允许兼容后手动测试。",
                network=services.last_result.network,
                progress=AuthProgress(
                    stage=AuthStage.PREPARE,
                    profile_matched=True,
                    portal_page_configured=True,
                    api_origin_configured=True,
                    http_auth_allowed=True,
                    zero_mac_observed=True,
                    credential_read_attempted=False,
                    login_request_attempted=False,
                ),
            )
        )
        report["zero_mac_guidance_visible"] = "尚未允许本档案兼容" in window.network_reason.text()
        window._automation_complete(
            {
                "enabled": True,
                "monitor": {"state": "STOPPED", "error_code": "none"},
                "startup": dict(installed=True, owned=True, configured=False, enabled=True),
            }
        )
        report["stopped_monitor_guidance_visible"] = (
            "当前不会自动认证" in window.automation_panel.status.text()
        )
        report["legacy_startup_repair_available"] = (
            window.automation_panel.startup_repair_button.isEnabled()
        )
        window._capture_complete(
            {
                "request_count": 16,
                "http_count": 16,
                "https_count": 0,
                "login_request_observed": True,
                "server_success_summary_observed": True,
                "sensitive_query_values_hidden": True,
                "transport_status": "演示数据：HTTP 兼容需在精确网络档案中明确允许。",
            }
        )
        report["embedded_help_chapters"] = len(window.help_panel.chapters) == 12
        report["embedded_capture_controls"] = window.capture_panel.start.text().startswith(
            "开始抓包"
        )
        report["credential_status_separate"] = "留空" in window.credentials_panel.draft.text()
        report["capture_summary_available"] = "HTTP 16" in window.capture_summary.text()
        services.support.report_overview()
        window.refresh_support_view()
        report["report_retention_default_safe"] = (
            window.report_settings.enabled.isChecked()
            and window.report_settings.days.value() == 7
            and not window.report_settings.include_capture.isChecked()
        )
        report.update({"icon_available": not app_icon().isNull(), "tab_count": window.tabs.count()})
        window.show()
        for theme in ("light", "dark"):
            apply_theme(app, theme)
            for page in window.pages:
                window.show_page(page)
                app.processEvents()
                if screenshots is not None:
                    screenshots.mkdir(parents=True, exist_ok=True)
                    if not window.grab().save(str(screenshots / f"m3-{theme}-{page}.png")):
                        raise OSError("Screenshot failed")
                    if page == "settings":
                        scroll = window.pages[page]
                        scroll.verticalScrollBar().setValue(scroll.verticalScrollBar().maximum())
                        app.processEvents()
                        if not window.grab().save(
                            str(screenshots / f"v1-{theme}-report-settings.png")
                        ):
                            raise OSError("Screenshot failed")
                        scroll.verticalScrollBar().setValue(0)
            editor = ProfileEditor(
                window,
                profile=NetworkProfile(
                    "synthetic",
                    "示例宿舍",
                    "Example-Campus-Dorm",
                    portal_page_url="http://portal.example.edu/a79.htm",
                    bjut_api_origin="http://portal.example.edu:801",
                ),
            )
            editor.show()
            app.processEvents()
            report["http_permission_default_off"] = not editor.allow_http.isChecked()
            report["zero_mac_permission_default_off"] = not editor.allow_zero_mac.isChecked()
            report["http_editor_available"] = editor.capture_button.isVisible()
            if screenshots is not None and not editor.grab().save(
                str(screenshots / f"m3-{theme}-http-editor.png")
            ):
                raise OSError("Screenshot failed")
            editor.reject()
            editor.deleteLater()
        window.tray_available = True
        window.close()
        report["close_to_tray_hides"] = not window.isVisible() and not window._quitting
        window.tray_available = False
        window.request_exit()
        deadline = time.monotonic() + 10
        while not window._allow_close and time.monotonic() < deadline:
            app.processEvents()
            time.sleep(0.005)
        report["full_exit_ready"] = window._allow_close and not window.busy
        report["password_never_loaded"] = window.credentials_panel.password.text() == ""
        window.deleteLater()
        QCoreApplication.sendPostedEvents(None, QEvent.DeferredDelete)
        return report


def main(arguments: list[str]) -> int:
    parser = argparse.ArgumentParser(description="隔离的 Windows 本机检查，不执行校园认证")
    parser.add_argument(
        "mode",
        choices=(
            "runtime",
            "gui",
            "background",
            "startup",
            "startup-ui",
            "credentials",
            "browser",
            "network",
        ),
    )
    parser.add_argument("--screenshots", type=Path)
    args = parser.parse_args(arguments)
    report = {
        "version": __version__,
        "frozen": bool(getattr(sys, "frozen", False)),
        "windows": platform.version(),
        "check": args.mode,
        "real_campus_authentication": "not_attempted",
    }
    try:
        checks = (
            gui_check(args.screenshots)
            if args.mode == "gui"
            else {
                "browser": browser_check,
                "runtime": runtime_check,
                "background": background_check,
                "startup": startup_check,
                "startup-ui": startup_ui_check,
                "credentials": credential_check,
                "network": network_check,
            }[args.mode]()
        )
        report["results"] = checks
        report["passed"] = all(value is not False for value in checks.values())
    except Exception as exc:
        report["passed"] = False
        report["failure_type"] = type(exc).__name__
        if isinstance(exc, CampusError):
            report["error_code"] = exc.code.value
        if isinstance(exc, ImportError):
            missing = getattr(exc, "name", None)
            if (
                missing
                in {
                    "unittest",
                    "unittest.mock",
                    "PySide6.QtCore",
                    "PySide6.QtGui",
                    "PySide6.QtWidgets",
                    "PySide6.QtNetwork",
                }
                or isinstance(missing, str)
                and re.fullmatch(
                    r"(?:campus_autoconnect|shibokensupport|PySide6)(?:\.[A-Za-z_][A-Za-z_0-9]*)*",
                    missing,
                )
            ):
                report["missing_component"] = missing
            frame = exc.__traceback__
            while frame is not None:
                name = Path(frame.tb_frame.f_code.co_filename).name
                if re.fullmatch(r"[A-Za-z_][A-Za-z_0-9]*\.py", name):
                    report["import_location"] = f"{name}:{frame.tb_lineno}"
                frame = frame.tb_next
    print(json.dumps(report, ensure_ascii=True, indent=2))
    return 0 if report["passed"] else 1
