"""Small desktop launcher; blocking work and report I/O stay on one worker thread."""

import os
import sys
import threading
from collections.abc import Callable
from pathlib import Path

from PySide6.QtCore import QObject, QSize, Qt, QThread, QTimer, QUrl, Signal, Slot
from PySide6.QtGui import QColor, QDesktopServices, QFont, QFontDatabase
from PySide6.QtWidgets import (
    QApplication,
    QFileDialog,
    QGridLayout,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMainWindow,
    QPlainTextEdit,
    QPushButton,
    QSplitter,
    QStyle,
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
    QWidget,
)

from campus_autoconnect.infrastructure.config import user_data_dir
from campus_inspector import __version__
from campus_inspector.processes import default_target
from campus_inspector.records import Evidence, Outcome, Report, Step
from campus_inspector.session import Session


def configure_fonts(app: QApplication) -> None:
    app.setStyle("Fusion")
    if not QFontDatabase.families():
        font = Path(os.environ.get("SYSTEMROOT", r"C:\Windows")) / "Fonts/msyh.ttc"
        if font.is_file():
            QFontDatabase.addApplicationFont(str(font))
    for family in ("Microsoft YaHei UI", "Microsoft YaHei"):
        if family in QFontDatabase.families():
            app.setFont(QFont(family, 10))
            break


class Worker(QObject):
    progress = Signal(object)
    completed = Signal(object)
    finished = Signal()

    def __init__(self, session: Session, path: Path | None, monitor: bool) -> None:
        super().__init__()
        self.session = session
        self.path = path
        self.monitor = monitor
        self.cancel = threading.Event()

    @Slot()
    def run(self) -> None:
        try:
            self.completed.emit(self.session.execute(self.path, self.cancel, monitor=self.monitor))
        finally:
            self.finished.emit()


class MainWindow(QMainWindow):
    def __init__(
        self, directory: Path | None = None, *, session_factory: Callable = Session
    ) -> None:
        super().__init__()
        configure_fonts(QApplication.instance())
        self.directory = directory if directory is not None else user_data_dir()
        self.thread: QThread | None = None
        self.worker: Worker | None = None
        self.session: Session | None = None
        self.report: Report | None = None
        self._closing = False
        self._monitor = False
        self.session_factory = session_factory
        self.setWindowTitle(f"校园网软件检测 · {__version__}")
        self.setWindowIcon(self.style().standardIcon(QStyle.SP_ComputerIcon))
        self.resize(1180, 820)
        center = QWidget()
        self.setCentralWidget(center)
        layout = QVBoxLayout(center)
        layout.setContentsMargins(22, 18, 22, 18)
        title = QLabel("校园网软件检测")
        title.setStyleSheet("font-size: 24px; font-weight: 600;")
        layout.addWidget(title)
        intro = QLabel("独立启动监测与分步复查 · 保留原软件源码 · 不读取认证凭据、不发送登录请求")
        intro.setWordWrap(True)
        layout.addWidget(intro)
        selector = QHBoxLayout()
        self.path_edit = QLineEdit()
        self.path_edit.setPlaceholderText("选择完整解压目录中的 CampusAutoConnect.exe")
        initial = default_target(
            Path(sys.executable).parent
            if getattr(sys, "frozen", False)
            else Path(__file__).resolve().parents[1]
        )
        if initial:
            self.path_edit.setText(str(initial))
        self.browse = QPushButton("选择软件…")
        selector.addWidget(self.path_edit, 1)
        selector.addWidget(self.browse)
        layout.addLayout(selector)
        actions = QGridLayout()
        self.check = QPushButton("仅分步检查")
        self.start = QPushButton("监测并启动原软件")
        self.recheck = QPushButton("再次分步复查")
        self.exe_check = QPushButton("采集 EXE 新一次检测")
        self.marker = QPushButton("标记操作时间")
        self.stop = QPushButton("结束监测并保存")
        self.copy = QPushButton("复制脱敏报告")
        self.open_folder = QPushButton("打开报告目录")
        buttons = [
            self.check,
            self.start,
            self.recheck,
            self.exe_check,
            self.marker,
            self.stop,
            self.copy,
            self.open_folder,
        ]
        for i, button in enumerate(buttons):
            button.setMinimumHeight(34)
            actions.addWidget(button, i // 4, i % 4)
        layout.addLayout(actions)
        self.status = QLabel("尚未开始。可先选软件，再点击“监测并启动原软件”。")
        self.status.setTextFormat(Qt.PlainText)
        self.status.setWordWrap(True)
        self.status.setStyleSheet("font-size: 15px; padding: 6px 0;")
        layout.addWidget(self.status)
        self.boundary = QLabel(
            "独立复查不等于 EXE 内部轨迹；共享日志无法归属某个进程或某次点击。\n"
            "“采集 EXE 新一次检测”会另做一次联网检测，建议原软件空闲时使用。"
        )
        self.boundary.setWordWrap(True)
        layout.addWidget(self.boundary)
        splitter = QSplitter(Qt.Vertical)
        self.tree = QTreeWidget()
        self.tree.setHeaderLabels(["检查环节", "结果", "证据来源", "说明"])
        self.tree.setRootIsDecorated(False)
        self.tree.setAlternatingRowColors(True)
        self.tree.setWordWrap(True)
        self.tree.setColumnWidth(0, 190)
        self.tree.setColumnWidth(1, 72)
        self.tree.setColumnWidth(2, 150)
        self.tree.header().setSectionResizeMode(3, QHeaderView.Stretch)
        self.details = QPlainTextEdit()
        self.details.setReadOnly(True)
        self.details.setPlaceholderText(
            "选择一行查看安全原因、时间及脱敏事实；结束后可复制完整报告。"
        )
        splitter.addWidget(self.tree)
        splitter.addWidget(self.details)
        splitter.setSizes([420, 130])
        layout.addWidget(splitter, 1)
        self.location = QLabel("报告存放于 LOCALAPPDATA / CampusAutoConnect / diagnostics。")
        self.location.setWordWrap(True)
        self.location.setTextFormat(Qt.PlainText)
        layout.addWidget(self.location)
        self.browse.clicked.connect(self.choose)
        self.check.clicked.connect(lambda: self.begin(False))
        self.start.clicked.connect(lambda: self.begin(True))
        self.stop.clicked.connect(self.request_stop)
        self.recheck.clicked.connect(self.request_recheck)
        self.exe_check.clicked.connect(self.request_exe)
        self.marker.clicked.connect(self.mark)
        self.copy.clicked.connect(self.copy_report)
        self.open_folder.clicked.connect(self.show_folder)
        self.tree.currentItemChanged.connect(self.show_step)
        self._set_busy(False)

    def _set_busy(self, busy: bool) -> None:
        self.path_edit.setEnabled(not busy)
        self.browse.setEnabled(not busy)
        self.check.setEnabled(not busy)
        self.start.setEnabled(not busy)
        self.stop.setEnabled(busy)
        for button in (self.recheck, self.exe_check, self.marker):
            button.setEnabled(busy and self._monitor)
        self.copy.setEnabled(not busy and self.report is not None)
        self.open_folder.setEnabled(self.session is not None)

    @Slot()
    def choose(self) -> None:
        path, _ = QFileDialog.getOpenFileName(
            self, "选择校园网软件", self.path_edit.text(), "校园网软件 (CampusAutoConnect.exe)"
        )
        if path:
            self.path_edit.setText(path)

    def begin(self, monitor: bool) -> None:
        if self.thread is not None:
            return
        value = self.path_edit.text().strip()
        if monitor and not value:
            self.status.setText("请先选择要启动的 CampusAutoConnect.exe。")
            return
        self.tree.clear()
        self.details.clear()
        self.report = None
        self._monitor = monitor
        self.session = self.session_factory(self.directory, lambda _: None)
        self.worker = Worker(self.session, Path(value) if value else None, monitor)
        self.session.emit = self.worker.progress.emit
        self.thread = QThread(self)
        self.worker.moveToThread(self.thread)
        self.thread.started.connect(self.worker.run)
        self.worker.progress.connect(self.add_step)
        self.worker.completed.connect(self.complete)
        self.worker.finished.connect(self.thread.quit)
        self.worker.finished.connect(self.worker.deleteLater)
        self.thread.finished.connect(self.thread_finished)
        self.status.setText("正在检查。Windows 网络查询可能需要十余秒，可请求结束。")
        self.location.setText(str(self.session.writer.directory))
        self._set_busy(True)
        self.thread.start()

    @Slot(object)
    def add_step(self, step: Step) -> None:
        item = QTreeWidgetItem([step.title, step.outcome.value, step.evidence.value, step.detail])
        item.setSizeHint(0, QSize(0, 46))
        item.setToolTip(3, step.detail)
        item.setData(0, Qt.UserRole, step)
        colors = {Outcome.BLOCKED: "#b65800", Outcome.ERROR: "#c02d3b", Outcome.PASS: "#16814b"}
        if step.outcome in colors:
            item.setForeground(1, QColor(colors[step.outcome]))
        self.tree.addTopLevelItem(item)
        while self.tree.topLevelItemCount() > 800:
            self.tree.takeTopLevelItem(0)
        self.tree.scrollToBottom()
        self.status.setText(f"{step.title} · {step.outcome.value} · {step.code}")
        if step.key == "monitor" and step.code == "monitor_ready":
            self.status.setText("监测中：现在可在原软件操作，结束后返回这里保存报告。")

    @Slot(object)
    def complete(self, report: Report) -> None:
        self.report = report
        self.status.setText(report.summary())
        if self.session and self.session.save_failed:
            self.status.setText(report.summary() + " 报告写入失败，请复制窗口中的报告。")

    @Slot()
    def thread_finished(self) -> None:
        # Qt finished may precede native thread-local cleanup on Windows.
        if self.thread is not None and not self.thread.wait(0):
            QTimer.singleShot(20, self.thread_finished)
            return
        if self.thread is not None:
            self.thread.deleteLater()
        self.thread = None
        self.worker = None
        self._set_busy(False)
        if self._closing:
            self.close()

    @Slot()
    def request_stop(self) -> None:
        if self.worker:
            self.worker.cancel.set()
            self.status.setText("已请求结束，正在等待有界系统查询完成；不会关闭原软件。")
            self.stop.setEnabled(False)
            for button in (self.recheck, self.exe_check, self.marker):
                button.setEnabled(False)

    @Slot()
    def request_recheck(self) -> None:
        if self.session:
            self.session.recheck_requested.set()
            self.status.setText("已排队再次复查，当前任务结束后执行。")

    @Slot()
    def request_exe(self) -> None:
        if self.session:
            self.session.exe_requested.set()
            self.status.setText("已排队执行 EXE 的另一次检测；它与 GUI 上一次操作分别记录。")

    @Slot()
    def mark(self) -> None:
        if self.session:
            self.session.mark()
            self.status.setText("已记录当前操作时间，任务执行结束后将显示。")

    @Slot()
    def copy_report(self) -> None:
        if self.report is not None:
            QApplication.clipboard().setText(self.report.text())
            self.status.setText("已复制完整脱敏报告，可直接粘贴反馈。")

    @Slot()
    def show_folder(self) -> None:
        if self.session:
            location = self.session.writer.directory
            if location.is_dir():
                QDesktopServices.openUrl(QUrl.fromLocalFile(str(location)))

    @Slot(object, object)
    def show_step(self, current, _previous) -> None:
        if current is None:
            return
        step = current.data(0, Qt.UserRole)
        if isinstance(step, Step):
            self.details.setPlainText(
                f"时间：{step.at}\n来源：{step.evidence.value} · 第 {step.run} 轮\n"
                f"原因：{step.code} · 耗时 {step.elapsed_ms} ms\n{step.detail}\n"
                + "\n".join(f"{key}: {value}" for key, value in step.facts.items())
            )

    def closeEvent(self, event) -> None:
        if self.thread is not None:
            self._closing = True
            self.request_stop()
            event.ignore()
            return
        event.accept()


def main() -> int:
    app = QApplication.instance() or QApplication([])
    app.setApplicationName("CampusInspector")
    app.setOrganizationName("CampusAutoConnect")
    app.setFont(app.font())
    window = MainWindow()
    window.show()
    return app.exec()


def preview(directory: Path) -> None:
    """Synthetic preview only; never loads the user's configuration or runs a check."""
    app = QApplication.instance() or QApplication([])
    window = MainWindow(directory=directory / "synthetic")
    window.path_edit.setText("请选择 CampusAutoConnect.exe（此图使用虚构数据）")
    for step in (
        Step(
            "network",
            "Windows 网络快照",
            Outcome.PASS,
            "network_connected",
            "已取得网络快照；SSID 及 IP 均不写入报告。",
        ),
        Step(
            "probe_1",
            "联网探测点 1",
            Outcome.WARNING,
            "portal_redirect",
            "发现跳转线索；未跟随跳转，未保存响应体。",
        ),
        Step(
            "trust",
            "Portal 目标安全检查",
            Outcome.BLOCKED,
            "http_disallowed",
            "发现 HTTP 认证线索；现有规则仅允许可信 HTTPS。",
        ),
        Step(
            "capability",
            "协议认证准备",
            Outcome.SKIPPED,
            "http_disallowed",
            "前置目标检查阻塞，本项未执行。",
        ),
        Step(
            "app_event",
            "观察到主程序事件",
            Outcome.INFO,
            "untrusted_target",
            "来自共享事件日志，无法归属于某个 PID 或某次点击。",
            Evidence.SHARED_LOG,
        ),
    ):
        window.add_step(step)
    window.status.setText("演示：最近一次独立复查停在 Portal 目标安全检查。")
    window.show()
    window.tree.setCurrentItem(window.tree.topLevelItem(2))
    app.processEvents()
    directory.mkdir(parents=True, exist_ok=True)
    if not window.grab().save(str(directory / "软件检测-预览.png")):
        raise OSError("preview failed")
    window.close()
    app.processEvents()
