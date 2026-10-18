"""Desktop operations with an allowlisted log projection, never arbitrary log text."""

import re
from pathlib import Path

from campus_autoconnect.core.models import AuthState, ErrorCode
from campus_autoconnect.infrastructure.desktop import DesktopPreferences, DesktopStore
from campus_autoconnect.infrastructure.locking import FileMutex
from campus_autoconnect.infrastructure.logging import STARTUP_STAGES
from campus_autoconnect.services.automation import AutomationState

_LINE = re.compile(
    r"(?P<time>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2},\d{3}) INFO "
    r"(?P<kind>operation|automation) state=(?P<state>[A-Z_]+) code=(?P<code>[a-z_]+)"
    r"(?: attempt=(?P<attempt>[0-3]) runtime_error=(?P<runtime>[a-z_]+))?"
)
_TIMING = re.compile(
    r"\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2},\d{3} INFO timing kind=(?:check|login|preparation)"
    r" total_ms=(\d{1,8}) network_ms=(\d{1,8}) connectivity_ms=(\d{1,8})"
    r" prepare_ms=(\d{1,8}) submit_ms=(\d{1,8}) verify_ms=(\d{1,8})"
)
_STARTUP = re.compile(
    r"\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2},\d{3} INFO startup"
    r" stage=([a-z_]+) elapsed_ms=(\d{1,8})"
)


class DesktopService:
    def __init__(self, directory: Path) -> None:
        self.directory = directory
        self.preferences = DesktopStore(directory / "desktop.json")

    def load_preferences(self) -> DesktopPreferences:
        return self.preferences.load()

    def save_preferences(self, preferences: DesktopPreferences) -> None:
        self.preferences.save(preferences)

    def read_logs(self) -> str:
        path = self.directory / "logs" / "campus.log"
        try:
            with FileMutex(path.with_suffix(".log.lock"), timeout=1), path.open("rb") as stream:
                stream.seek(0, 2)
                size = stream.tell()
                stream.seek(max(0, size - 32768))
                data = stream.read(32768).decode("utf-8", errors="replace")
            lines = []
            for line in data.splitlines():
                timing = _TIMING.fullmatch(line)
                startup = _STARTUP.fullmatch(line)
                if timing and all(int(value) <= 86400000 for value in timing.groups()):
                    lines.append(line)
                    continue
                if startup and startup[1] in STARTUP_STAGES and int(startup[2]) <= 86400000:
                    lines.append(line)
                    continue
                match = _LINE.fullmatch(line)
                if match is None:
                    continue
                item = match.groupdict()
                try:
                    ErrorCode(item["code"])
                    if item["kind"] == "operation":
                        AuthState(item["state"])
                        if item["attempt"] is not None:
                            continue
                    else:
                        AutomationState(item["state"])
                        ErrorCode(item["runtime"])
                        if item["attempt"] is None:
                            continue
                except (ValueError, TypeError):
                    continue
                lines.append(line)
            return "\n".join(lines[-200:]) or "暂无可展示的脱敏事件。"
        except FileNotFoundError:
            return "暂无可展示的脱敏事件。"
