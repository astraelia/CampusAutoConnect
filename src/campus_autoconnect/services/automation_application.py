"""GUI/CLI facade; enabling automation and registering startup are explicit actions."""

import os
import subprocess
import time
from collections.abc import Callable

from campus_autoconnect.core.errors import CampusError
from campus_autoconnect.core.models import ErrorCode
from campus_autoconnect.infrastructure.automation import AutomationStore
from campus_autoconnect.infrastructure.launch import monitor_command
from campus_autoconnect.infrastructure.startup import WindowsStartupService
from campus_autoconnect.services.monitor import MonitorControl, MonitorRuntime


class AutomationService:
    def __init__(
        self,
        settings: AutomationStore,
        control: MonitorControl,
        startup: WindowsStartupService,
        runtime_factory: Callable[[], MonitorRuntime],
    ) -> None:
        self.settings = settings
        self.control = control
        self.startup = startup
        self.runtime_factory = runtime_factory
        self.cached_status: dict | None = None

    def overview(self) -> dict:
        try:
            startup = self.startup.status()
        except CampusError:
            startup = {"available": False, "error_code": "startup_error"}
        self.cached_status = {
            "enabled": self.settings.load().enabled,
            "monitor": self.control.status(),
            "startup": startup,
        }
        return self.cached_status

    def set_enabled(self, enabled: bool) -> None:
        self.settings.set_enabled(enabled)

    def save_and_start(self, enabled: bool) -> None:
        """Explicit UI action; plain preference saves keep their previous semantics."""
        if enabled is not True:
            raise CampusError(
                ErrorCode.AUTOMATION_DISABLED,
                "请先勾选“全局允许自动认证”，或使用“仅保存开关”。",
            )
        self.settings.set_enabled(True)
        if not self.control.status()["running"]:
            try:
                self.start_background()
            except CampusError as exc:
                raise CampusError(exc.code, "全局开关已保存；" + exc.message) from None

    def snapshot(self) -> dict:
        """Cheap status poll; never runs Task Scheduler or performs network queries."""
        startup = (self.cached_status or {}).get("startup", {"available": False})
        self.cached_status = {
            "enabled": self.settings.load().enabled,
            "monitor": self.control.status(),
            "startup": startup,
        }
        return self.cached_status

    def start_background(self, duration: float | None = None) -> None:
        if duration is not None and not 0 < duration <= 86400:
            raise ValueError("后台运行时长无效。")
        if self.control.status()["running"]:
            raise CampusError(ErrorCode.BUSY, "后台已在运行。")
        launch = monitor_command()
        try:
            arguments = launch.argv()
            if duration is not None:
                arguments.extend(("--duration", str(duration)))
            process = subprocess.Popen(
                arguments,
                cwd=str(launch.executable.parent),
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                creationflags=subprocess.CREATE_NO_WINDOW,
                env={**os.environ, "PYINSTALLER_RESET_ENVIRONMENT": "1"},
            )
            deadline = time.monotonic() + 5
            while time.monotonic() < deadline:
                status = self.control.status()
                if status["running"] and status["state"] not in {"UNAVAILABLE", "STOPPED"}:
                    return
                if process.poll() is not None:
                    raise CampusError(
                        ErrorCode.UNKNOWN, "后台启动后已退出，请检查脱敏状态和运行环境。"
                    )
                time.sleep(0.05)
            raise CampusError(ErrorCode.TIMEOUT, "尚未确认后台启动，请刷新状态后再操作。")
        except OSError as exc:
            raise CampusError(ErrorCode.CONFIG_ERROR, "后台启动请求失败，请检查运行环境。") from exc

    def ensure_background(self) -> None:
        """Login startup adopts a live monitor without clearing its safety state."""
        if not self.control.status()["running"]:
            try:
                self.start_background()
            except CampusError as exc:
                if exc.code != ErrorCode.BUSY or not self.control.status()["running"]:
                    raise

    def stop_background(self) -> bool:
        return self.control.request_stop()

    def stop_and_wait(self, timeout: float = 25) -> None:
        """Cooperative bounded shutdown; never kills a process with active authentication."""
        self.control.request_stop()
        deadline = time.monotonic() + timeout
        while self.control.status()["running"]:
            if time.monotonic() >= deadline:
                raise CampusError(ErrorCode.TIMEOUT, "后台仍在结束有界查询，请稍候再点击退出。")
            time.sleep(0.1)

    def run(self, duration: float | None = None) -> None:
        self.runtime_factory().run(duration=duration)
