"""Current-user desktop, tray and orderly worker shutdown."""

import os
import sys
import time
from pathlib import Path

from PySide6.QtGui import QFont, QFontDatabase
from PySide6.QtWidgets import QApplication, QMessageBox

from campus_autoconnect import __version__
from campus_autoconnect.core.errors import CampusError
from campus_autoconnect.infrastructure.config import user_data_dir
from campus_autoconnect.infrastructure.logging import log_startup_timing
from campus_autoconnect.services.application import build_services
from campus_autoconnect.ui.instance import GuiInstance
from campus_autoconnect.ui.main_window import MainWindow
from campus_autoconnect.ui.theme import app_icon, apply_theme
from campus_autoconnect.ui.tray import TrayController


def configure_application(app: QApplication) -> None:
    app.setStyle("Fusion")
    app.setApplicationName("Campus AutoConnect")
    app.setOrganizationName("CampusAutoConnect")
    app.setWindowIcon(app_icon())
    app.styleHints().colorSchemeChanged.connect(
        lambda _: apply_theme(app, "system") if app.property("campus_theme") == "system" else None
    )
    # The offscreen Windows plugin may not enumerate system fonts. Load an installed font.
    if not QFontDatabase.families():
        font_path = Path(os.environ.get("SYSTEMROOT", r"C:\Windows")) / "Fonts" / "msyh.ttc"
        if font_path.is_file():
            QFontDatabase.addApplicationFont(str(font_path))
    if "Microsoft YaHei UI" in QFontDatabase.families():
        app.setFont(QFont("Microsoft YaHei UI", 9))


def main(*, startup: bool = False) -> int:
    started = time.monotonic()
    app = QApplication(sys.argv)
    configure_application(app)
    apply_theme(app, "system")
    instance = GuiInstance(user_data_dir())
    try:
        if not instance.acquire(activate=not startup):
            return 0
        window = MainWindow(build_services(), startup=startup)
    except CampusError as exc:
        instance.close()
        QMessageBox.critical(None, "启动失败", exc.message)
        return 1
    except Exception as exc:
        instance.close()
        QMessageBox.critical(
            None, "启动失败", f"启动失败（{type(exc).__name__}），请检查用户目录和运行环境。"
        )
        return 1
    app.setQuitOnLastWindowClosed(False)
    tray = TrayController(window)
    if startup:
        log_startup_timing(
            window.services.event_logger, "desktop_ready", time.monotonic() - started
        )
    instance.activated.connect(tray.restore)
    instance.startup_requested.connect(window.ensure_startup_monitor)
    window.preferences_changed.connect(lambda preferences: apply_theme(app, preferences.theme))

    def exit_application():
        tray.close()
        instance.close()
        app.quit()

    window.exit_ready.connect(exit_application)
    app.aboutToQuit.connect(instance.close)
    screen = window.screen().availableGeometry()
    window.resize(min(980, screen.width()), min(720, screen.height()))
    if startup and window.tray_available:
        tray.tray.showMessage(
            f"连接助手 v{__version__} 已启动", "已在托盘运行；自动认证仍受全局及网络档案许可控制。"
        )
    else:
        window.show()
    return app.exec()
