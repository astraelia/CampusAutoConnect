"""Render the actual Qt widgets with fictional data for reproducible visual QA."""

import os
import tempfile
from pathlib import Path

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtWidgets import QApplication

from campus_autoconnect.core.models import (
    AuthResult,
    AuthState,
    ErrorCode,
    NetworkAdapter,
    NetworkProfile,
    NetworkSnapshot,
)
from campus_autoconnect.core.profiles import ProfileService
from campus_autoconnect.infrastructure.automation import AutomationStore
from campus_autoconnect.infrastructure.config import ConfigStore
from campus_autoconnect.services.application import ApplicationServices
from campus_autoconnect.services.automation_application import AutomationService
from campus_autoconnect.services.monitor import MonitorControl
from campus_autoconnect.ui.app import configure_application
from campus_autoconnect.ui.main_window import MainWindow
from campus_autoconnect.ui.profile_editor import ProfileEditor


def main() -> None:
    app = QApplication([])
    configure_application(app)
    output = Path(__file__).resolve().parents[1] / "docs" / "screenshots"
    output.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="campus-preview-") as directory:
        profiles = ProfileService(ConfigStore(Path(directory) / "config.json"))
        profiles.upsert(
            NetworkProfile(
                "example_dorm",
                "示例宿舍",
                "Example-Campus-Dorm",
                trusted_portal_hosts=("portal.example.edu",),
            )
        )
        profiles.upsert(
            NetworkProfile(
                "example_study",
                "示例活动室",
                "Example-Campus-Study",
                enabled=False,
            )
        )
        # No credential or authentication operation is used by this renderer.
        services = ApplicationServices(profiles, None, None)

        class StartupPreview:
            def status(self):
                return dict.fromkeys(("installed", "enabled", "owned", "configured"), False)

        services.automation = AutomationService(
            AutomationStore(Path(directory) / "automation.json"),
            MonitorControl(Path(directory)),
            StartupPreview(),
            None,
        )
        window = MainWindow(services, initial_check=False)
        window.automation_panel.show_status(services.automation.overview())
        window._network_complete(
            AuthResult(
                AuthState.AUTH_FAILED,
                ErrorCode.PROTOCOL_UNVERIFIED,
                "示例数据 · BJUT 实测协议待确认，未读取凭据。",
                NetworkSnapshot(
                    (
                        NetworkAdapter(
                            7,
                            "Example Wi-Fi",
                            "example-guid",
                            True,
                            ssid="Example-Campus-Dorm",
                            ipv4=("192.0.2.10",),
                        ),
                    )
                ),
                "https://portal.example.edu/",
                checked_at="2026-10-16T10:00:00+00:00",
            )
        )
        window.show()
        app.processEvents()
        window.grab().save(str(output / "m2-settings.png"))
        window.centralWidget().verticalScrollBar().setValue(
            window.centralWidget().verticalScrollBar().maximum()
        )
        app.processEvents()
        window.grab().save(str(output / "m2-settings-bottom.png"))
        editor = ProfileEditor(profile=profiles.list()[0])
        editor.show()
        app.processEvents()
        editor.grab().save(str(output / "m2-profile-editor.png"))
        editor.close()
        window.close()
    print("Rendered fictional-data Qt windows to docs/screenshots.")


if __name__ == "__main__":
    main()
