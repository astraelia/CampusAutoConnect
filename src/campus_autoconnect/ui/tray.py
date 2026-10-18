"""Tray UI delegates actions to the same asynchronous main-window services."""

from PySide6.QtCore import QObject, Slot
from PySide6.QtGui import QAction
from PySide6.QtWidgets import QMenu, QSystemTrayIcon

from campus_autoconnect import __version__
from campus_autoconnect.ui.main_window import MainWindow
from campus_autoconnect.ui.theme import app_icon


class TrayController(QObject):
    def __init__(self, window: MainWindow) -> None:
        super().__init__(window)
        self.window = window
        self.tray = QSystemTrayIcon(app_icon(), self)
        self.tray.setToolTip(f"校园 Wi-Fi 连接助手 · v{__version__}")
        self.menu = QMenu(window)
        self.actions: dict[str, QAction] = {}
        for key, label, callback in (
            ("show", "打开主窗口", self.restore),
            ("check", "检测网络", lambda: self.run_network(False)),
            ("login", "手动测试认证", lambda: self.run_network(True)),
            ("start", "启动后台监视", lambda: window.automation_action("start")),
            ("stop", "停止后台监视", lambda: window.automation_action("stop")),
            ("quit", "退出程序（停止后台）", window.request_exit),
        ):
            if key in {"start", "quit"}:
                self.menu.addSeparator()
            action = self.menu.addAction(label)
            action.triggered.connect(callback)
            self.actions[key] = action
        self.menu.aboutToShow.connect(self.update_actions)
        self.tray.setContextMenu(self.menu)
        self.tray.activated.connect(self._activated)
        self.tray.messageClicked.connect(self.restore)
        window.hidden_to_tray.connect(self.on_hidden)
        window.status_changed.connect(self.update_status)
        self._notified = False
        self.refresh_availability()

    def refresh_availability(self) -> None:
        available = QSystemTrayIcon.isSystemTrayAvailable()
        self.window.tray_available = available
        if available:
            self.tray.show()
        else:
            self.tray.hide()

    @Slot()
    def restore(self) -> None:
        self.window.showNormal()
        self.window.raise_()
        self.window.activateWindow()

    def _activated(self, reason) -> None:
        if reason in (QSystemTrayIcon.Trigger, QSystemTrayIcon.DoubleClick):
            self.restore()

    def run_network(self, login: bool) -> None:
        self.restore()
        self.window.show_page("overview")
        self.window._network_action(login)

    def update_actions(self) -> None:
        self.refresh_availability()
        enabled = not self.window.busy and not self.window._quitting
        for key in ("check", "login", "start", "stop"):
            self.actions[key].setEnabled(enabled)

    def on_hidden(self) -> None:
        self.refresh_availability()
        if not self.window.tray_available:
            self.restore()
        elif not self._notified:
            self._notified = True
            self.tray.showMessage("连接助手已收起", "从托盘打开窗口；选择“退出程序”会停止后台。")

    def update_status(self, text: str) -> None:
        self.tray.setToolTip("校园 Wi-Fi 连接助手\n" + text)

    def close(self) -> None:
        self.tray.hide()
