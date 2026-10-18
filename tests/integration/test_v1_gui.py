import threading
from datetime import UTC, datetime, timedelta

import pytest
from PySide6.QtCore import QThread, QTimer
from PySide6.QtWidgets import QMessageBox

from campus_autoconnect.services.application import ApplicationServices
from campus_autoconnect.services.support import SupportService
from campus_autoconnect.ui.instance import GuiInstance
from campus_autoconnect.ui.main_window import MainWindow

pytestmark = pytest.mark.mock


@pytest.fixture
def window(qtbot, profiles, credentials, tmp_path):
    from campus_autoconnect.core.observation import OperationTrace

    auth = type("Authentication", (), {"trace": OperationTrace()})()
    services = ApplicationServices(profiles, credentials, auth)
    services.support = SupportService(tmp_path, auth, tmp_path / "reports")
    widget = MainWindow(services, initial_check=False)
    qtbot.addWidget(widget)
    widget.show()
    yield widget
    widget.services.support.close()


def test_report_settings_are_async_and_dont_enable_authentication(window, qtbot):
    panel = window.report_settings
    panel.days.setValue(3)
    panel.count.setValue(8)
    window.save_report_policy()
    qtbot.waitUntil(lambda: not window.busy)
    policy = window.services.support.maintenance.store.load()
    assert policy.days == 3 and policy.max_sessions == 8 and not policy.include_capture
    assert not (window.services.support.directory / "automation.json").exists()
    assert window.services.credentials.reads == 0


def test_cleanup_confirmation_can_cancel_without_deleting(window, qtbot, monkeypatch):
    from campus_autoconnect.infrastructure.reports import ReportSession

    report = ReportSession(window.services.support.session.root)
    report.write("diagnostic.json", {"synthetic": True})
    report.close()
    import os

    stamp = (datetime.now(UTC) - timedelta(days=10)).timestamp()
    os.utime(report.directory / "diagnostic.json", (stamp, stamp))
    confirmations = []
    monkeypatch.setattr(
        QMessageBox, "question", lambda *args: confirmations.append(args[2]) or QMessageBox.No
    )
    window.preview_report_cleanup()
    qtbot.waitUntil(lambda: not window.busy)
    assert confirmations and report.directory.exists()
    monkeypatch.setattr(QMessageBox, "question", lambda *_: QMessageBox.Yes)
    window.preview_report_cleanup()
    qtbot.waitUntil(lambda: not report.directory.exists())
    qtbot.waitUntil(lambda: not window.busy)


def test_slow_cleanup_does_not_block_gui_and_can_show_failures(window, qtbot, monkeypatch):
    support = window.services.support
    started, release, pulse = threading.Event(), threading.Event(), threading.Event()

    def overview():
        assert QThread.currentThread() != window.thread()
        started.set()
        assert release.wait(3)
        return support.report_overview_original()

    support.report_overview_original = support.report_overview
    monkeypatch.setattr(support, "report_overview", overview)
    window.refresh_report_statistics()
    QTimer.singleShot(10, pulse.set)
    try:
        qtbot.waitUntil(started.is_set)
        qtbot.waitUntil(pulse.is_set)
        assert not window.report_settings.cleanup.isEnabled()
    finally:
        release.set()
        qtbot.waitUntil(lambda: not window.busy)


def test_scheduled_duplicate_does_not_restore_existing_window(qtbot, tmp_path):
    first, second = GuiInstance(tmp_path), GuiInstance(tmp_path)
    activated = []
    boot = []
    first.activated.connect(lambda: activated.append(True))
    first.startup_requested.connect(lambda: boot.append(True))
    try:
        assert first.acquire()
        assert not second.acquire(activate=False)
        qtbot.waitUntil(lambda: bool(boot))
        assert not activated and boot == [True]
    finally:
        second.close()
        first.close()
