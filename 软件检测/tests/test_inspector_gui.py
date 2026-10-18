from campus_inspector.gui import MainWindow
from campus_inspector.records import Outcome, Step
from campus_inspector.session import Session
from PySide6.QtCore import QThread
from PySide6.QtWidgets import QApplication


def make_window(qtbot, tmp_path, *, delay=0.05):
    class FakeRunner:
        def __init__(self, _directory, emit, **_kwargs):
            self.emit = emit

        def context(self):
            pass

        def inspect(self, cancel):
            assert QThread.currentThread() != QApplication.instance().thread()
            cancel.wait(delay)
            self.emit(
                Step(
                    "internet",
                    "合成网络检查",
                    Outcome.PASS,
                    "already_authenticated",
                    "仅虚构数据。",
                    run=1,
                )
            )

    window = MainWindow(
        tmp_path,
        session_factory=lambda directory, emit: Session(directory, emit, runner_factory=FakeRunner),
    )
    window.path_edit.clear()
    qtbot.addWidget(window)
    window.show()
    return window


def test_gui_async_report_and_safe_copy(qtbot, tmp_path):
    window = make_window(qtbot, tmp_path)
    window.begin(False)
    assert window.thread is not None
    assert not window.start.isEnabled()
    qtbot.waitUntil(lambda: window.thread is None, timeout=10000)
    assert window.report is not None
    assert window.copy.isEnabled()
    window.copy_report()
    assert "互联网可用" in QApplication.clipboard().text()
    assert (window.session.writer.directory / "report.txt").is_file()
    QApplication.clipboard().clear()


def test_close_waits_for_worker_and_does_not_destroy_thread(qtbot, tmp_path):
    window = make_window(qtbot, tmp_path, delay=0.2)
    window.begin(False)
    window.close()
    assert window._closing
    qtbot.waitUntil(lambda: window.thread is None, timeout=10000)
    assert not window.isVisible()
