"""Tabbed desktop window; external operations and shutdown run on Qt workers."""

import json
import threading
from collections.abc import Callable
from pathlib import Path
from urllib.parse import urlsplit

from PySide6.QtCore import QObject, Qt, QThread, QTimer, QUrl, Signal, Slot
from PySide6.QtGui import QDesktopServices
from PySide6.QtWidgets import (
    QAbstractItemView,
    QApplication,
    QCheckBox,
    QComboBox,
    QDialog,
    QDialogButtonBox,
    QFileDialog,
    QGroupBox,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QMainWindow,
    QMessageBox,
    QPlainTextEdit,
    QPushButton,
    QScrollArea,
    QTableWidget,
    QTableWidgetItem,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

from campus_autoconnect import __version__
from campus_autoconnect.core.errors import CampusError
from campus_autoconnect.core.models import (
    AUTH_STAGE_LABELS,
    AuthResult,
    AuthState,
    Credentials,
    ErrorCode,
    NetworkProfile,
)
from campus_autoconnect.core.portal import PROFILE_ISSUE_LABELS, profile_setup_summary
from campus_autoconnect.infrastructure.config import validate_ref
from campus_autoconnect.infrastructure.desktop import DesktopPreferences
from campus_autoconnect.services.application import ApplicationServices
from campus_autoconnect.services.browser_capture import BrowserCapture
from campus_autoconnect.services.credential_management import CredentialStatus
from campus_autoconnect.ui.automation_settings import AutomationPanel
from campus_autoconnect.ui.profile_editor import ProfileEditor
from campus_autoconnect.ui.settings import CredentialsPanel
from campus_autoconnect.ui.support_pages import (
    CapturePanel,
    DiagnosticPanel,
    HelpPanel,
    ReportSettingsPanel,
)
from campus_autoconnect.ui.theme import app_icon

_STATE_LABELS = {
    "DISCONNECTED": "未连接",
    "NETWORK_CONNECTED": "网络已连接",
    "CHECKING": "正在检测",
    "AUTH_REQUIRED": "需要认证",
    "AUTHENTICATING": "正在认证",
    "AUTHENTICATED": "互联网可用",
    "AUTH_FAILED": "认证未完成",
    "UNKNOWN": "状态待确认",
}


class _Worker(QObject):
    succeeded = Signal(object)
    failed = Signal(str)
    finished = Signal()

    def __init__(self, action: Callable) -> None:
        super().__init__()
        self.action: Callable | None = action

    @Slot()
    def run(self) -> None:
        try:
            self.succeeded.emit(self.action())
        except CampusError as exc:
            self.failed.emit(exc.message)
        except ValueError:
            self.failed.emit("输入或配置无效，请检查字段及档案是否重复。")
        except Exception as exc:
            self.failed.emit(f"操作失败（{type(exc).__name__}），未显示可能含敏感信息的底层异常。")
        finally:
            self.action = None
            self.finished.emit()


class MainWindow(QMainWindow):
    exit_ready = Signal()
    hidden_to_tray = Signal()
    preferences_changed = Signal(object)
    status_changed = Signal(str)

    def __init__(
        self, services: ApplicationServices, *, initial_check: bool = True, startup: bool = False
    ) -> None:
        super().__init__()
        self.services = services
        self.startup = startup
        self._startup_pending = False
        self._thread: QThread | None = None
        self._worker: _Worker | None = None
        self._callback: Callable | None = None
        self._cancel = threading.Event()
        self._profiles: list[NetworkProfile] = []
        self.preferences = DesktopPreferences()
        self.tray_available = False
        self._quitting = self._allow_close = self._shutdown_started = self._shutdown_success = False
        self._after_task: Callable | None = None
        self._poll_thread: QThread | None = None
        self._poll_worker: _Worker | None = None
        self._automation_revision = self._poll_revision = 0
        self._initial_check = initial_check
        self.setWindowTitle("校园 Wi-Fi 连接助手 · Campus AutoConnect")
        self.setWindowIcon(app_icon())
        self.resize(980, 720)
        self.setMinimumSize(760, 520)
        root = QWidget()
        layout = QVBoxLayout(root)
        layout.setContentsMargins(24, 18, 24, 18)
        layout.setSpacing(14)
        header = QHBoxLayout()
        logo = QLabel()
        logo.setPixmap(app_icon().pixmap(56, 56))
        header.addWidget(logo)
        title = QLabel("校园 Wi-Fi 连接助手")
        title.setStyleSheet("font-size: 23px; font-weight: 600;")
        header.addWidget(title)
        header.addStretch()
        header.addWidget(QLabel(f"v{__version__}"))
        layout.addLayout(header)
        subtitle = QLabel("当前校园网连接与登录自动连接已实测；HTTP 兼容需在网络档案中明确允许。")
        subtitle.setWordWrap(True)
        layout.addWidget(subtitle)
        self.tabs = QTabWidget()
        layout.addWidget(self.tabs, 1)
        self.pages: dict[str, QWidget] = {}
        page_layouts = {}
        for key, label in (
            ("overview", "连接概览"),
            ("profiles", "网络档案"),
            ("credentials", "安全凭据"),
            ("automation", "后台与启动"),
            ("logs", "诊断与监测"),
            ("capture", "抓包与分析"),
            ("settings", "外观设置"),
            ("help", "使用帮助"),
        ):
            page = QWidget()
            page_layouts[key] = QVBoxLayout(page)
            page_layouts[key].setContentsMargins(14, 14, 14, 14)
            scroll = QScrollArea()
            scroll.setWidgetResizable(True)
            scroll.setWidget(page)
            self.pages[key] = scroll
            self.tabs.addTab(scroll, label)
        self.network_group = QGroupBox("当前网络")
        network_layout = QVBoxLayout(self.network_group)
        self.network_status = QLabel("尚未检测")
        self.network_status.setObjectName("network_status")
        self.network_status.setWordWrap(True)
        self.network_status.setStyleSheet("font-size: 22px; font-weight: 600; padding: 12px 0;")
        self.network_status.setTextFormat(Qt.PlainText)
        network_layout.addWidget(self.network_status)
        self.network_detail = QLabel("SSID：—    Portal 主机：—    最近检测：—")
        self.network_detail.setWordWrap(True)
        self.network_detail.setTextFormat(Qt.PlainText)
        network_layout.addWidget(self.network_detail)
        self.network_reason = QLabel("检测后显示具体原因和执行步骤。")
        self.network_reason.setWordWrap(True)
        self.network_reason.setTextFormat(Qt.PlainText)
        network_layout.addWidget(self.network_reason)
        self.setup_button = QPushButton("配置当前网络…")
        self.setup_button.setObjectName("configure_current_network")
        self.setup_button.setEnabled(False)
        network_layout.addWidget(self.setup_button)
        buttons = QHBoxLayout()
        self.check_button = QPushButton("检测网络")
        self.check_button.setObjectName("check_network")
        self.login_button = QPushButton("手动测试认证")
        self.login_button.setObjectName("test_login")
        self.diagnose_button = QPushButton("查看脱敏诊断")
        self.cancel_button = QPushButton("取消本次操作")
        self.cancel_button.setEnabled(False)
        for button in (
            self.check_button,
            self.login_button,
            self.diagnose_button,
            self.cancel_button,
        ):
            buttons.addWidget(button)
        network_layout.addLayout(buttons)
        page_layouts["overview"].addWidget(self.network_group)
        self.overview_automation = QLabel("后台：尚未查询。自动认证默认关闭。")
        self.overview_automation.setTextFormat(Qt.PlainText)
        self.overview_automation.setWordWrap(True)
        page_layouts["overview"].addWidget(self.overview_automation)
        guidance = QLabel(
            "开始使用\n\n1. 点击“检测网络”，确认当前连接状态。\n"
            "2. 点击“配置当前网络”，从本人脱敏抓包填写认证页和服务地址。\n"
            "3. 核对后明确允许 HTTP；升级程序不会自动给旧档案授予许可。\n"
            "4. 前往“安全凭据”录入纯账号或带一次正确后缀的完整账号，先手动测试。\n\n"
            "人工核验清单与问题反馈模板位于成品目录的“使用与核验”文件夹。"
        )
        guidance.setWordWrap(True)
        page_layouts["overview"].addWidget(guidance)
        page_layouts["overview"].addStretch()
        self.automation_panel = AutomationPanel()
        self.automation_panel.setVisible(services.automation is not None)
        page_layouts["automation"].addWidget(self.automation_panel)
        page_layouts["automation"].addStretch()
        self.credentials_panel = CredentialsPanel()
        page_layouts["credentials"].addWidget(self.credentials_panel)
        page_layouts["credentials"].addStretch()
        self.profile_group = QGroupBox("可信 Wi-Fi 档案 · 精确 SSID 匹配")
        profile_layout = QVBoxLayout(self.profile_group)
        self.table = QTableWidget(0, 6)
        self.table.setObjectName("profiles")
        self.table.setHorizontalHeaderLabels(
            ["显示名称", "SSID", "启用", "自动认证", "凭据引用", "认证配置"]
        )
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SingleSelection)
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.table.setMinimumHeight(150)
        self.table.verticalHeader().hide()
        profile_layout.addWidget(self.table)
        profile_buttons = QHBoxLayout()
        self.add_current_button = QPushButton("添加当前 Wi-Fi")
        self.add_button = QPushButton("手动添加")
        self.edit_button = QPushButton("编辑档案")
        self.remove_button = QPushButton("删除档案")
        for button in (
            self.add_current_button,
            self.add_button,
            self.edit_button,
            self.remove_button,
        ):
            profile_buttons.addWidget(button)
        profile_layout.addLayout(profile_buttons)
        transfers = QHBoxLayout()
        self.import_button = QPushButton("导入档案…")
        self.export_button = QPushButton("导出档案…")
        transfers.addWidget(self.import_button)
        transfers.addWidget(self.export_button)
        transfers.addStretch()
        profile_layout.addLayout(transfers)
        profile_note = QLabel(
            "导出包含网络名称和可信主机，不含账号密码。导入生成新凭据引用，全部停用，需逐项复核。"
        )
        profile_note.setWordWrap(True)
        profile_layout.addWidget(profile_note)
        page_layouts["profiles"].addWidget(self.profile_group)
        self.logs = QPlainTextEdit()
        self.logs.setReadOnly(True)
        self.logs.setPlaceholderText(
            "仅展示最近 200 条经过白名单校验的事件；不显示账号或网络标识。"
        )
        self.logs_refresh = QPushButton("刷新脱敏事件")
        self.copy_diagnostics = QPushButton("复制脱敏诊断")
        self.capture_button = QPushButton("分析抓包文件…")
        log_buttons = QHBoxLayout()
        log_buttons.addWidget(self.logs_refresh)
        log_buttons.addWidget(self.copy_diagnostics)
        log_buttons.addWidget(self.capture_button)
        page_layouts["logs"].addLayout(log_buttons)
        self.capture_summary = QLabel("选择本地脱敏 JSON，查看认证流程与证据缺项。不会自动登录。")
        self.capture_summary.setWordWrap(True)
        self.capture_summary.setTextFormat(Qt.PlainText)
        page_layouts["logs"].addWidget(self.capture_summary)
        page_layouts["logs"].addWidget(self.logs, 1)
        self.theme = QComboBox()
        for label, value in (("跟随系统", "system"), ("浅色", "light"), ("深色", "dark")):
            self.theme.addItem(label, value)
        self.close_to_tray = QCheckBox("关闭窗口时收起到托盘；使用“退出程序”停止后台并退出")
        self.close_to_tray.setChecked(True)
        self.preferences_save = QPushButton("保存外观与关闭方式")
        for widget in (QLabel("主题"), self.theme, self.close_to_tray, self.preferences_save):
            page_layouts["settings"].addWidget(widget)
        self.diagnostics_panel = DiagnosticPanel()
        self.report_settings = ReportSettingsPanel()
        self.report_settings.setEnabled(services.support is not None)
        page_layouts["settings"].addWidget(self.report_settings)
        self.capture_panel = CapturePanel()
        self.help_panel = HelpPanel()
        page_layouts["logs"].insertWidget(0, self.diagnostics_panel)
        page_layouts["capture"].addWidget(self.capture_panel)
        page_layouts["capture"].addWidget(self.capture_button)
        page_layouts["capture"].addWidget(self.capture_summary)
        page_layouts["help"].addWidget(self.help_panel)
        self.help_panel.navigate.connect(self.show_page)
        self.browser_capture = BrowserCapture(services.support) if services.support else None
        self._capture_running = False
        self._credential_reference_revision = 0
        self._credential_action = False
        self._credential_operation_reference = None
        self._navigate_network_result = False
        self._last_reference = "shared"
        self.message = QLabel("档案保存后立即生效。自动认证还需开启全局开关并运行后台。")
        self.message.setObjectName("message")
        self.message.setWordWrap(True)
        self.message.setTextFormat(Qt.PlainText)
        footer = QHBoxLayout()
        footer.addWidget(self.message, 1)
        self.exit_button = QPushButton("退出程序")
        footer.addWidget(self.exit_button)
        layout.addLayout(footer)
        self.setCentralWidget(root)
        self.setStyleSheet(
            "QGroupBox { font-weight: 600; margin-top: 10px; padding-top: 15px; }"
            "QGroupBox::title { subcontrol-origin: margin; left: 10px; }"
            "QLineEdit, QPushButton { min-height: 26px; }"
            "QPushButton { padding: 3px 10px; }"
            "QTabBar::tab { padding: 9px 13px; }"
            "QTableWidget { gridline-color: palette(mid); }"
        )
        self.check_button.clicked.connect(lambda: self._network_action(False))
        self.login_button.clicked.connect(lambda: self._network_action(True))
        self.setup_button.clicked.connect(self.configure_current_network)
        self.cancel_button.clicked.connect(self._cancel.set)
        self.diagnose_button.clicked.connect(self.show_diagnostics)
        self.add_button.clicked.connect(lambda: self.edit_profile())
        self.add_current_button.clicked.connect(self.add_current)
        self.edit_button.clicked.connect(self.edit_selected)
        self.remove_button.clicked.connect(self.remove_profile)
        self.import_button.clicked.connect(self.import_profiles)
        self.export_button.clicked.connect(self.export_profiles)
        self.logs_refresh.clicked.connect(self.refresh_logs)
        self.copy_diagnostics.clicked.connect(self.copy_safe_diagnostics)
        self.capture_button.clicked.connect(self.analyze_capture)
        self.preferences_save.clicked.connect(self.save_preferences)
        self.exit_button.clicked.connect(self.request_exit)
        panel = self.credentials_panel
        panel.save_button.clicked.connect(self.save_credentials)
        panel.delete_button.clicked.connect(self.delete_credentials)
        panel.check_button.clicked.connect(self.check_credentials)
        self.table.itemSelectionChanged.connect(self._selection_changed)
        automation = self.automation_panel
        automation.refresh_button.clicked.connect(self.refresh_automation)
        automation.save_button.clicked.connect(self.save_automation)
        automation.save_start_button.clicked.connect(lambda: self.save_automation(start=True))
        automation.startup_enabled.clicked.connect(
            lambda checked: self.automation_action(
                "startup_enable" if checked else "startup_disable"
            )
        )
        for button, command in (
            (automation.start_button, "start"),
            (automation.stop_button, "stop"),
            (automation.startup_enable_button, "startup_enable"),
            (automation.startup_repair_button, "startup_repair"),
            (automation.startup_disable_button, "startup_disable"),
        ):
            button.clicked.connect(
                lambda _checked=False, command=command: self.automation_action(command)
            )
        self.credentials_panel.reference.textChanged.connect(self._credential_reference_changed)
        diag = self.diagnostics_panel
        diag.begin.clicked.connect(self.begin_monitoring)
        diag.inspect.clicked.connect(self.inspect_network)
        diag.deep.clicked.connect(self.deep_diagnostics)
        diag.finish.clicked.connect(self.finish_monitoring)
        diag.copy.clicked.connect(self.copy_monitoring)
        diag.open.clicked.connect(self.open_report_directory)
        diag.fix.clicked.connect(self.navigate_problem)
        reports = self.report_settings
        reports.save.clicked.connect(self.save_report_policy)
        reports.refresh.clicked.connect(self.refresh_report_statistics)
        reports.cleanup.clicked.connect(self.preview_report_cleanup)
        reports.protected.clicked.connect(self.protect_current_report)
        self.capture_panel.start.clicked.connect(self.start_browser_capture)
        self.capture_panel.stop.clicked.connect(self._cancel.set)
        self.capture_panel.retry.clicked.connect(self.retry_capture_save)
        self.capture_panel.probe.clicked.connect(
            lambda: self.browser_capture.probe_requested.set() if self.browser_capture else None
        )
        self._support_timer = QTimer(self)
        self._support_timer.setInterval(500)
        self._support_timer.timeout.connect(self.refresh_support_view)
        self._support_timer.start()
        self.refresh_profiles()
        self._poll_timer = QTimer(self)
        self._poll_timer.setInterval(3000)
        self._poll_timer.timeout.connect(self.poll_status)
        if initial_check:
            QTimer.singleShot(0, self.initialize)

    @property
    def busy(self) -> bool:
        return self._thread is not None

    def _set_busy(self, busy: bool) -> None:
        enabled = not busy and not self._quitting
        self.credentials_panel.setEnabled(enabled)
        self.profile_group.setEnabled(enabled)
        self.automation_panel.setEnabled(enabled)
        self.report_settings.setEnabled(enabled and self.services.support is not None)
        self.check_button.setEnabled(enabled)
        self.login_button.setEnabled(enabled)
        self.setup_button.setEnabled(
            enabled and bool(self.services.last_result and self.services.last_result.network.ssid)
        )
        self.cancel_button.setEnabled(busy)
        for button in (self.preferences_save, self.logs_refresh, self.capture_button):
            button.setEnabled(enabled)
        for button in (
            self.diagnostics_panel.begin,
            self.diagnostics_panel.inspect,
            self.diagnostics_panel.deep,
            self.diagnostics_panel.finish,
            self.capture_panel.start,
        ):
            button.setEnabled(enabled and self.services.support is not None)
        self.capture_panel.stop.setEnabled(self._capture_running)
        self.capture_panel.probe.setEnabled(self._capture_running)
        self.capture_panel.retry.setEnabled(
            enabled and bool(self.browser_capture and self.browser_capture.last_payload)
        )
        self.exit_button.setEnabled(not self._quitting)

    def _start(
        self, action: Callable, callback: Callable, label: str, *, cancellable: bool = False
    ) -> None:
        if self.busy:
            return
        self._automation_revision += 1
        self._cancel.clear()
        self._set_busy(True)
        self.cancel_button.setEnabled(cancellable)
        self.message.setText(label)
        thread = QThread(self)
        worker = _Worker(action)
        worker.moveToThread(thread)
        self._thread, self._worker = thread, worker
        self._callback = callback
        thread.started.connect(worker.run)
        worker.succeeded.connect(self._task_complete)
        worker.failed.connect(self._task_error)
        worker.finished.connect(thread.quit)
        worker.finished.connect(worker.deleteLater)
        thread.finished.connect(self._finished)
        thread.start()

    @Slot(object)
    def _task_complete(self, result: object) -> None:
        if self._callback is not None:
            self._callback(result)

    @Slot(str)
    def _task_error(self, message: str) -> None:
        self.message.setText(message)
        if self._credential_action:
            if (
                self._credential_operation_reference
                == self.credentials_panel.reference.text().strip()
            ):
                self.credentials_panel.status.setText(message)
            self._credential_action = False
        if self._capture_running:
            self._capture_running = False
            self.capture_panel.state.setText(message)
        if self._shutdown_started:
            self._quitting = self._shutdown_started = False
            self.showNormal()
            self.raise_()
            self.activateWindow()
            if self._initial_check:
                self._poll_timer.start()

    @Slot()
    def _finished(self) -> None:
        thread = self._thread
        if thread is not None and not thread.wait(0):
            # finished is emitted before all native thread/TLS cleanup has completed.
            QTimer.singleShot(10, self._finished)
            return
        self._worker = None
        self._thread = None
        if thread is not None:
            thread.deleteLater()
        self._callback = None
        self._set_busy(False)
        if self._quitting:
            self._continue_exit()
        elif self._after_task is not None:
            callback, self._after_task = self._after_task, None
            QTimer.singleShot(0, callback)

    def show_page(self, name: str) -> None:
        if name in self.pages:
            self.tabs.setCurrentWidget(self.pages[name])

    def initialize(self) -> None:
        reference = self.credentials_panel.reference.text().strip()

        def load():
            preferences = (
                self.services.desktop.load_preferences()
                if self.services.desktop
                else self.preferences
            )
            startup_error = None
            if self.startup and self.services.automation:
                try:
                    self.services.automation.ensure_background()
                except CampusError as exc:
                    startup_error = exc.message
            overview = self.services.automation.overview() if self.services.automation else None
            status = self.services.credential_management.snapshot(reference)
            if self.services.support:
                self.services.support.maintain_reports()
                from campus_autoconnect.infrastructure.lifecycle import start_watcher

                start_watcher(self.services.support.session)
            return preferences, overview, status, startup_error

        def loaded(result):
            preferences, overview, status, startup_error = result
            self.credentials_panel.status.setText(status.label())
            self._preferences_loaded(preferences)
            if overview is not None:
                self._automation_complete(overview)
            self._poll_timer.start()
            if not self._profiles:
                self.show_page("help")
            if startup_error:
                self.message.setText("登录启动已打开界面；" + startup_error)
                self.showNormal()
            elif self.startup:
                self.message.setText("登录启动已完成；托盘与后台状态可在“后台与启动”查看。")
            else:
                self._after_task = lambda: self._network_action(False, navigate=False)

        self._start(load, loaded, "正在加载桌面设置与后台状态…")

    def _preferences_loaded(self, preferences: DesktopPreferences) -> None:
        self.preferences = preferences
        self.theme.setCurrentIndex(self.theme.findData(preferences.theme))
        self.close_to_tray.setChecked(preferences.close_to_tray)
        self.preferences_changed.emit(preferences)

    def save_preferences(self) -> None:
        if self.services.desktop is None:
            return
        preferences = DesktopPreferences(self.theme.currentData(), self.close_to_tray.isChecked())

        def saved(_):
            self._preferences_loaded(preferences)
            self.message.setText("外观与关闭方式已保存。")

        self._start(
            lambda: self.services.desktop.save_preferences(preferences), saved, "正在保存桌面偏好…"
        )

    def refresh_logs(self) -> None:
        if self.services.desktop is not None:
            self._start(
                self.services.desktop.read_logs, self.logs.setPlainText, "正在读取脱敏事件…"
            )

    def copy_safe_diagnostics(self) -> None:
        QApplication.clipboard().setText(
            json.dumps(self.services.diagnostics(), ensure_ascii=False, indent=2)
        )
        self.message.setText("脱敏诊断已复制，可粘贴到问题反馈模板。")

    def analyze_capture(self) -> None:
        path, _ = QFileDialog.getOpenFileName(self, "选择脱敏抓包结果", "", "抓包 JSON (*.json)")
        if path:
            self._start(
                lambda: self.services.analyze_capture(Path(path)),
                self._capture_complete,
                "正在本地分析抓包结构…",
            )

    def _capture_complete(self, report: dict) -> None:
        self.capture_summary.setText(
            f"相关请求 {report['request_count']} 条：HTTP {report['http_count']} 条，"
            f"HTTPS {report['https_count']} 条。\n"
            f"登录请求：{'已捕获' if report['login_request_observed'] else '未捕获'}；"
            f"服务端成功摘要：{'有' if report['server_success_summary_observed'] else '未确认'}。\n"
            f"{report['transport_status']}\n"
            "服务端成功摘要不能代替登录后的独立联网验证。原始参数值未保存。\n"
            + (
                "所选文件的敏感字段未全部隐藏，请私下保管原件。"
                if not report["sensitive_query_values_hidden"]
                else ""
            )
        )
        self.message.setText("抓包分析完成，仅在本地显示结构结果。")

    def import_profiles(self) -> None:
        path, _ = QFileDialog.getOpenFileName(
            self, "导入档案（全部停用，无凭据）", "", "JSON (*.json)"
        )
        if not path:
            return

        def imported(count):
            self.refresh_profiles()
            self.message.setText(f"已导入 {count} 个停用档案；请复核 SSID、可信主机和新凭据引用。")

        self._start(
            lambda: self.services.profiles.import_from(Path(path)), imported, "正在校验并导入档案…"
        )

    def export_profiles(self) -> None:
        if (
            QMessageBox.question(
                self, "导出档案", "导出文件包含 SSID 和可信主机，不含账号密码。请仅保存在可信位置。"
            )
            != QMessageBox.Yes
        ):
            return
        path, _ = QFileDialog.getSaveFileName(
            self, "导出网络档案", "campus-profiles.json", "JSON (*.json)"
        )
        if path:
            self._start(
                lambda: self.services.profiles.export_to(Path(path)),
                lambda _: self.message.setText("档案已导出；安全凭据未导出。"),
                "正在导出档案…",
            )

    def _automation_complete(self, overview: dict) -> None:
        self.automation_panel.show_status(overview)
        monitor = overview["monitor"]
        label = self.automation_panel.status.text()
        self.overview_automation.setText(label)
        self.status_changed.emit(f"后台 {monitor['state']} · {monitor['error_code']}")

    def poll_status(self) -> None:
        if (
            self._poll_thread is not None
            or self.busy
            or self._quitting
            or self.services.automation is None
        ):
            return
        thread = QThread(self)

        def poll():
            if self.services.support:
                self.services.support.maintain_reports()
            return self.services.automation.snapshot()

        worker = _Worker(poll)
        worker.moveToThread(thread)
        self._poll_thread, self._poll_worker = thread, worker
        self._poll_revision = self._automation_revision
        thread.started.connect(worker.run)
        worker.succeeded.connect(self._poll_complete)
        worker.failed.connect(self._poll_error)
        worker.finished.connect(thread.quit)
        worker.finished.connect(worker.deleteLater)
        thread.finished.connect(self._poll_finished)
        thread.start()

    @Slot(str)
    def _poll_error(self, message: str) -> None:
        if self._poll_revision == self._automation_revision and not self._quitting:
            self.overview_automation.setText("后台状态暂不可读取；可在“后台与启动”主动刷新。")

    @Slot(object)
    def _poll_complete(self, overview: dict) -> None:
        if self._poll_revision == self._automation_revision and not self._quitting:
            self._automation_complete(overview)

    @Slot()
    def _poll_finished(self) -> None:
        thread = self._poll_thread
        if thread is not None and not thread.wait(0):
            QTimer.singleShot(10, self._poll_finished)
            return
        self._poll_thread = self._poll_worker = None
        if thread is not None:
            thread.deleteLater()
        if self._quitting:
            self._continue_exit()

    def refresh_profiles(self) -> None:
        try:
            self._profiles = self.services.profiles.list()
            self.table.setRowCount(len(self._profiles))
            for row, profile in enumerate(self._profiles):
                values = (
                    profile.display_name,
                    profile.ssid,
                    "是" if profile.enabled else "否",
                    "允许" if profile.auto_auth else "关闭",
                    profile.credential_ref,
                    profile_setup_summary(profile),
                )
                for column, value in enumerate(values):
                    item = QTableWidgetItem(value)
                    item.setToolTip(value)
                    self.table.setItem(row, column, item)
            if warning := self.services.profiles.store.warning:
                self.message.setText(warning)
        except CampusError as exc:
            self.message.setText(exc.message)

    def selected_profile(self) -> NetworkProfile | None:
        row = self.table.currentRow()
        return self._profiles[row] if 0 <= row < len(self._profiles) else None

    def _selection_changed(self) -> None:
        profile = self.selected_profile()
        if profile:
            self.credentials_panel.reference.setText(profile.credential_ref)

    def edit_profile(self, profile: NetworkProfile | None = None, current_ssid: str = "") -> None:
        dialog = ProfileEditor(self, profile=profile, current_ssid=current_ssid)
        if dialog.exec() == QDialog.Accepted and dialog.result_profile:
            self._start(
                lambda: self.services.profiles.upsert(dialog.result_profile),
                lambda _: self._profiles_saved(),
                "正在保存档案…",
            )

    def edit_selected(self) -> None:
        profile = self.selected_profile()
        if profile is None:
            self.message.setText("请先选择要编辑的档案。")
            return
        self.edit_profile(profile)

    def configure_current_network(self) -> None:
        result = self.services.last_result
        if result is None or not result.network.ssid:
            self.message.setText("请先检测网络，确认当前唯一 SSID。")
            return
        ssid = result.network.ssid

        def load():
            profiles = self.services.profiles.list()
            if self.services.profiles.store.warning:
                raise CampusError(
                    ErrorCode.CONFIG_ERROR, "档案配置不可用，请先按使用手册修复配置。"
                )
            matches = [profile for profile in profiles if profile.ssid == ssid]
            enabled = [profile for profile in matches if profile.enabled]
            if len(enabled) == 1:
                return enabled[0]
            if len(matches) > 1:
                raise CampusError(
                    ErrorCode.UNTRUSTED_NETWORK,
                    "当前 SSID 对应多个档案，请在“网络档案”中明确选择要编辑的条目。",
                )
            return matches[0] if matches else None

        def loaded(profile):
            self._after_task = lambda: self.edit_profile(profile=profile, current_ssid=ssid)

        self._start(load, loaded, "正在读取当前网络的档案；不读取凭据…")

    def _profiles_saved(self) -> None:
        self.refresh_profiles()
        self.message.setText(
            "档案已保存；列表显示配置缺项。请重新检测并先手动测试；概览诊断仍对应上次操作。"
        )

    def add_current(self) -> None:
        result = self.services.last_result
        if not result or not result.network.ssid:
            self.message.setText("请先检测网络；未识别唯一 SSID 时可手动添加。")
            return
        self.edit_profile(current_ssid=result.network.ssid)

    def remove_profile(self) -> None:
        profile = self.selected_profile()
        if profile is None:
            self.message.setText("请先选择档案。")
            return
        if (
            QMessageBox.question(self, "删除档案", "删除所选档案？对应安全凭据需单独删除。")
            != QMessageBox.Yes
        ):
            return
        self._start(
            lambda: self.services.profiles.remove(profile.profile_id),
            lambda _: self._profiles_saved(),
            "正在删除档案…",
        )

    def _reference(self) -> str | None:
        try:
            return validate_ref(self.credentials_panel.reference.text().strip())
        except ValueError as exc:
            self.message.setText(str(exc))
            return None

    def save_credentials(self) -> None:
        panel = self.credentials_panel
        reference = self._reference()
        if reference is None:
            return
        if not panel.username.text().strip() or not panel.password.text():
            self.message.setText("请输入账号和新密码。")
            return
        credentials = Credentials(panel.username.text().strip(), panel.password.text())
        panel.password.clear()
        self._credential_action = True
        self._credential_operation_reference = reference
        panel.status.setText("正在保存并回读核对 Windows 安全存储…")
        self._start(
            lambda: self.services.credential_management.save(reference, credentials),
            lambda status: self._credential_status_for(reference, status, clear_inputs=True),
            "正在保存安全凭据…",
        )

    def _credential_status(self, text: str) -> None:
        self.credentials_panel.status.setText(text)
        self.message.setText(text)

    def _credential_status_for(
        self, reference: str, status: CredentialStatus, *, clear_inputs: bool = False
    ) -> None:
        self._credential_action = False
        if reference != self.credentials_panel.reference.text().strip():
            return
        self._credential_status(status.label())
        if clear_inputs:
            self.credentials_panel.username.clear()
            self.credentials_panel.password.clear()
            self.credentials_panel.draft.setText("输入框仅用于新增或更新；留空不会删除已有凭据。")

    def _credential_reference_changed(self, _text: str) -> None:
        self._credential_reference_revision += 1
        revision = self._credential_reference_revision
        reference = self.credentials_panel.reference.text().strip()
        if reference != self._last_reference:
            self.credentials_panel.username.clear()
            self.credentials_panel.password.clear()
            self._last_reference = reference
        self.credentials_panel.status.setText("凭据引用已改变；尚未检查当前 Windows 记录。")
        try:
            validate_ref(reference)
        except ValueError:
            return
        if self.busy:
            return

        def loaded(status):
            if revision == self._credential_reference_revision:
                self.credentials_panel.status.setText(status.label())

        self._start(
            lambda: self.services.credential_management.snapshot(reference),
            loaded,
            "正在读取上次确认记录；不访问已保存账号密码…",
        )

    def refresh_support_view(self) -> None:
        support = self.services.support
        if support is None:
            return
        content = support.text()
        if self.diagnostics_panel.output.toPlainText() != content:
            self.diagnostics_panel.output.setPlainText(content)
        saved = (
            "保存失败；可复制结果"
            if support.save_error
            else "已保存"
            if support.last_saved
            else "尚未保存"
        )
        self.diagnostics_panel.path.setText(f"报告（{saved}）：{support.session.directory}")
        if support.maintenance_status is not None:
            self.report_settings.show_status(support.maintenance_status)
        if support.maintenance_error:
            self.report_settings.status.setText(
                "报告自动清理未完成；可主动刷新检查目录权限或清理设置。"
            )
        self.report_settings.protected.blockSignals(True)
        self.report_settings.protected.setChecked(support.session.protected)
        self.report_settings.protected.blockSignals(False)
        if self._capture_running and self.browser_capture:
            states = {
                "waiting": "等待在途认证结束",
                "recording": "正在记录专用浏览器",
                "navigation_failed": "页面访问未完成，可重新打开认证页",
                "partial": "记录中；部分请求未能解析",
                "failed": "抓包失败",
            }
            self.capture_panel.state.setText(
                states.get(self.browser_capture.state, "正在结束抓包")
                + f" · 已记录 {self.browser_capture.count} 条；停止后保存分析。"
            )

    def begin_monitoring(self) -> None:
        if self.services.support:
            self._start(
                self.services.support.begin,
                lambda _: self.message.setText("监测已开始；后续操作记录将保存到程序目录。"),
                "正在检查报告目录…",
            )

    def inspect_network(self) -> None:
        if self.services.support:
            self.show_page("logs")
            self._start(
                lambda: self.services.support.inspect(self._cancel),
                lambda _: self.refresh_support_view(),
                "正在独立分步复查（不登录）…",
                cancellable=True,
            )

    def deep_diagnostics(self) -> None:
        if self.services.support:
            self.show_page("logs")
            self._start(
                lambda: self.services.support.prepare(self._cancel),
                lambda result: self.message.setText(result.message),
                "正在核对实时页面和协议；不读取凭据、不登录…",
                cancellable=True,
            )

    def finish_monitoring(self) -> None:
        if self.services.support:
            self._start(
                self.services.support.finish,
                lambda ok: self.message.setText(
                    "诊断报告已保存到程序目录。" if ok else "诊断报告保存失败，结果仍可复制。"
                ),
                "正在保存诊断报告…",
            )

    def copy_monitoring(self) -> None:
        if self.services.support:
            QApplication.clipboard().setText(self.services.support.text())
            self.message.setText("脱敏监测报告已复制；浏览器本地目标记录不在此剪贴内容中。")

    def open_report_directory(self) -> None:
        if self.services.support:
            directory = self.services.support.session.directory
            if directory.is_dir():
                QDesktopServices.openUrl(QUrl.fromLocalFile(str(directory)))
            else:
                self.message.setText("尚未生成报告目录，请先开始监测或保存报告。")

    def refresh_report_statistics(self) -> None:
        if self.services.support:
            self._start(
                self.services.support.report_overview,
                self.report_settings.show_status,
                "正在检查报告目录…",
            )

    def save_report_policy(self) -> None:
        if self.services.support:
            policy = self.report_settings.policy()

            def saved(status):
                self.report_settings._dirty = False
                self.report_settings.show_status(status)
                self.message.setText("报告清理设置已保存；旧报告仍需先预览确认。")

            self._start(
                lambda: self.services.support.save_report_policy(policy),
                saved,
                "正在保存报告清理设置…",
            )

    def protect_current_report(self, checked: bool) -> None:
        if self.services.support:
            self._start(
                lambda: self.services.support.protect_report(checked),
                self.report_settings.show_status,
                "正在更新报告保留标记…",
            )

    def preview_report_cleanup(self) -> None:
        if self.services.support:
            self._start(
                self.services.support.preview_cleanup,
                self._report_cleanup_preview,
                "正在预览符合清理规则的报告…",
            )

    def _report_cleanup_preview(self, preview: dict) -> None:
        if not preview["candidate_count"] and not preview["legacy_count"]:
            self.message.setText("没有符合清理规则的报告；活动、保留标记和未纳入的抓包已跳过。")
            return
        answer = QMessageBox.question(
            self,
            "确认清理报告",
            f"按已保存规则清理 {preview['candidate_count']} 组报告，"
            f"约 {preview['candidate_bytes'] / (1024 * 1024):.2f} MiB。\n"
            f"将 {preview['legacy_count']} 组旧报告纳入今后的清理规则。\n"
            "活动、保留标记和未纳入的抓包会话会跳过。是否继续？",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No,
        )
        if answer == QMessageBox.Yes:
            self._after_task = lambda: self._start(
                lambda: self.services.support.cleanup_reports(preview),
                self.report_settings.show_status,
                "正在清理已确认的报告…",
            )

    def navigate_problem(self) -> None:
        result = self.services.last_result
        if result is None:
            self.show_page("help")
        elif result.progress.profile_issues or result.code in {
            ErrorCode.UNTRUSTED_NETWORK,
            ErrorCode.UNTRUSTED_TARGET,
        }:
            self.show_page("profiles")
        elif result.code in {
            ErrorCode.CREDENTIALS_MISSING,
            ErrorCode.CREDENTIAL_STORE,
            ErrorCode.CREDENTIAL_VERIFY,
        }:
            self.show_page("credentials")
        else:
            self.help_panel.search.setText(
                "路由" if result.code == ErrorCode.ROUTE_UNCONFIRMED else result.code.value
            )
            self.show_page("help")

    def start_browser_capture(self) -> None:
        if self.browser_capture is None or self.busy:
            return
        self.show_page("capture")
        self._capture_running = True
        self._start(
            lambda: self.browser_capture.run(self._cancel),
            self._browser_capture_complete,
            "正在准备专用浏览器；期间暂停本应用的新认证提交…",
            cancellable=True,
        )

    def retry_capture_save(self) -> None:
        if self.browser_capture and not self.busy:
            self._start(
                self.browser_capture.retry_save,
                self._browser_capture_complete,
                "正在重试保存内存中的脱敏抓包记录…",
            )

    def _browser_capture_complete(self, summary: dict) -> None:
        self._capture_running = False
        self.capture_panel.output.setPlainText(json.dumps(summary, ensure_ascii=False, indent=2))
        count = summary.get("request_count", 0)
        self.capture_panel.state.setText(
            f"已保存 {count} 条记录并完成结构分析。"
            if count
            else "已保存空记录；未捕获到登录，不代表成功。"
        )
        self.message.setText(
            "抓包已结束，可打开报告目录。主机/端口仅保留在本地抓包文件，请私下保管。"
        )
        self.show_page("capture")
        self.refresh_support_view()

    def delete_credentials(self) -> None:
        reference = self._reference()
        if reference is None:
            return
        if (
            QMessageBox.question(
                self, "删除凭据", "删除当前引用的凭据？共享此引用的档案将无法认证。"
            )
            != QMessageBox.Yes
        ):
            return
        self._start(
            lambda: self.services.credential_management.delete(reference),
            lambda status: self._credential_status_for(reference, status, clear_inputs=True),
            "正在删除安全凭据…",
        )

    def check_credentials(self) -> None:
        reference = self._reference()
        if reference is not None:
            self._start(
                lambda: self.services.credential_management.check(reference),
                lambda status: self._credential_status_for(reference, status),
                "正在主动检查安全存储…",
            )

    def _network_action(self, login: bool, *, navigate: bool = True) -> None:
        if self.busy or self._quitting:
            return
        self._navigate_network_result = navigate
        method = self.services.authentication.login if login else self.services.authentication.check

        def run():
            result = method(self._cancel)
            self.services.record_result(result)
            return result

        self.network_status.setText("正在认证…" if login else "正在检测网络…")
        self._start(
            run,
            self._network_complete,
            "操作进行中，可取消本次操作…",
            cancellable=True,
        )

    @Slot(object)
    def _network_complete(self, result: AuthResult) -> None:
        # Production workers already recorded/persisted this result. Direct preview/test
        # projections only update memory and never perform report IO on the GUI thread.
        self.services.last_result = result
        matches = [p for p in self._profiles if p.enabled and p.ssid == result.network.ssid]
        if (
            len(matches) == 1
            and not self.credentials_panel.username.text()
            and not self.credentials_panel.password.text()
            and self.credentials_panel.reference.text() != matches[0].credential_ref
        ):
            self.credentials_panel.reference.setText(matches[0].credential_ref)
            self._after_task = lambda: self._credential_reference_changed(
                self.credentials_panel.reference.text()
            )
        label = _STATE_LABELS[result.state.value]
        progress = result.progress
        if (
            result.state != AuthState.AUTHENTICATED
            and progress.profile_matched
            and progress.profile_issues
        ):
            label = "当前网络档案待补全"
        self.network_status.setText(f"{label}  ·  {result.code.value}")
        details = [result.message, "执行步骤：" + AUTH_STAGE_LABELS[progress.stage]]
        if progress.zero_mac_observed is True:
            details.append(
                "页面返回全零 MAC："
                + ("已按本档案许可兼容。" if progress.zero_mac_allowed else "尚未允许本档案兼容。")
            )
        if progress.zero_vlan_observed is True:
            details.append("页面返回 VLAN=0：按兼容规则保留该值，仍需实时配置核对。")
        if progress.profile_matched and progress.profile_issues:
            details.append(
                "配置缺项："
                + "；".join(PROFILE_ISSUE_LABELS[x] for x in progress.profile_issues)
                + "。点击“配置当前网络”补全，保存后重新检测。"
            )
        read = {True: "已尝试读取", False: "未读取", None: "未记录"}
        submit = {True: "已尝试发起", False: "未发起", None: "未记录"}
        details.append(
            f"安全凭据：{read[progress.credential_read_attempted]}；"
            f"登录请求：{submit[progress.login_request_attempted]}。"
        )
        self.network_reason.setText("\n".join(details))
        self.setup_button.setEnabled(bool(result.network.ssid) and not self.busy)
        host = urlsplit(result.portal_url).hostname if result.portal_url else "—"
        self.network_detail.setText(
            f"SSID：{result.network.ssid or '未识别'}    Portal 主机：{host}\n"
            f"最近检测（UTC）：{result.checked_at}"
        )
        self.message.setText(result.message)
        self.status_changed.emit(f"{label} · {result.code.value}")
        if self._navigate_network_result and result.state not in {
            AuthState.AUTHENTICATED,
            AuthState.AUTH_REQUIRED,
        }:
            self.show_page("logs")
        self.refresh_support_view()

    def show_diagnostics(self) -> None:
        dialog = QDialog(self)
        dialog.setWindowTitle("脱敏诊断 · 不含账号、SSID、IP 或响应体")
        dialog.resize(650, 470)
        layout = QVBoxLayout(dialog)
        text = QPlainTextEdit(json.dumps(self.services.diagnostics(), ensure_ascii=False, indent=2))
        text.setReadOnly(True)
        layout.addWidget(text)
        buttons = QDialogButtonBox(QDialogButtonBox.Close)
        buttons.rejected.connect(dialog.reject)
        layout.addWidget(buttons)
        dialog.exec()

    def refresh_automation(self) -> None:
        if self.services.automation is not None:
            self._start(
                self.services.automation.overview,
                self._automation_complete,
                "正在查询自动认证和登录任务状态…",
            )

    def ensure_startup_monitor(self) -> None:
        if not self._startup_pending and not self._quitting:
            self._startup_pending = True
            self._start_when_idle()

    def _start_when_idle(self) -> None:
        if self._quitting:
            self._startup_pending = False
            return
        if self.busy:
            QTimer.singleShot(100, self._start_when_idle)
            return
        self._startup_pending = False
        if self.services.automation:

            def ensure():
                self.services.automation.ensure_background()
                return self.services.automation.overview()

            self._start(ensure, self._automation_complete, "正在确认登录启动后台…")

    def save_automation(self, _checked: bool = False, *, start: bool = False) -> None:
        if self.services.automation is not None:
            enabled = self.automation_panel.enabled.isChecked()
            self._start(
                lambda: (
                    self.services.automation.save_and_start(enabled)
                    if start
                    else self.services.automation.set_enabled(enabled)
                ),
                lambda _: self._automation_saved(enabled, started=start),
                "正在保存并启动后台…" if start else "正在保存全局开关…",
            )

    def _automation_saved(self, enabled: bool, *, started: bool = False) -> None:
        self.automation_panel.mark_saved()
        self.message.setText(
            "全局自动认证许可已保存；仍需启用档案并运行后台。"
            if enabled
            else "全局自动认证已关闭；手动检测与认证仍可用。"
        )
        if started:
            self.message.setText("全局许可已保存，后台已确认运行；仍需当前档案允许自动认证。")
            self._after_task = self.refresh_automation

    def automation_action(self, command: str) -> None:
        automation = self.services.automation
        if automation is None:
            return
        actions = {
            "start": (automation.start_background, "后台进程已确认运行，可刷新查看状态。"),
            "stop": (automation.stop_background, "后台停止请求已处理，请刷新状态确认。"),
            "startup_enable": (automation.startup.enable, "登录启动任务已启用。"),
            "startup_repair": (
                automation.startup.repair,
                "登录启动任务已修复到当前程序，保留原启用状态；未立即运行任务。",
            ),
            "startup_disable": (automation.startup.disable, "登录启动任务已关闭。"),
        }
        action, message = actions[command]

        def completed(_):
            self.message.setText(message)
            self._after_task = self.refresh_automation

        self._start(action, completed, "正在处理后台或登录启动设置…")

    def request_exit(self) -> None:
        if self._quitting:
            return
        self._quitting = True
        self._after_task = None
        self._support_timer.stop()
        self._poll_timer.stop()
        self._cancel.set()
        self.credentials_panel.password.clear()
        self.message.setText("正在取消操作并停止后台，请等待有界查询结束…")
        self._continue_exit()

    def _continue_exit(self) -> None:
        if self.busy or self._poll_thread is not None:
            return
        if self._shutdown_success or (
            self.services.automation is None and self.services.support is None
        ):
            self._allow_close = True
            self.hide()
            self.close()
            self.exit_ready.emit()
        elif not self._shutdown_started:
            self._shutdown_started = True

            def stop():
                if self.services.automation:
                    self.services.automation.stop_and_wait()
                if self.services.support:
                    self.services.support.close()

            self._start(
                stop,
                self._shutdown_complete,
                "正在停止后台并完整退出…",
            )

    def _shutdown_complete(self, _: object) -> None:
        self._shutdown_success = True

    def closeEvent(self, event) -> None:
        self.credentials_panel.password.clear()
        if self._allow_close:
            event.accept()
        elif self.tray_available and self.preferences.close_to_tray and not self._quitting:
            self.hide()
            event.ignore()
            self.hidden_to_tray.emit()
        else:
            event.ignore()
            self.request_exit()
            if self._allow_close:
                event.accept()
