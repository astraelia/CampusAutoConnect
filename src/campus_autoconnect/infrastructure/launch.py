"""Literal launch arguments for source and frozen builds; no shell interpolation."""

import sys
from dataclasses import dataclass
from pathlib import Path

from campus_autoconnect.core.errors import CampusError
from campus_autoconnect.core.models import ErrorCode

SOURCE_ARGUMENTS = ("-X", "utf8", "-m", "campus_autoconnect.cli.main", "monitor", "run")
FROZEN_ARGUMENTS = ("--background",)
SOURCE_STARTUP_ARGUMENTS = ("-X", "utf8", "-m", "campus_autoconnect", "--startup")
FROZEN_STARTUP_ARGUMENTS = ("--startup",)


@dataclass(frozen=True)
class LaunchCommand:
    executable: Path
    arguments: tuple[str, ...]

    def validate(self) -> None:
        expected = {
            "pythonw.exe": (SOURCE_ARGUMENTS, SOURCE_STARTUP_ARGUMENTS),
            "campusautoconnect.exe": (FROZEN_ARGUMENTS, FROZEN_STARTUP_ARGUMENTS),
        }
        if (
            not self.executable.is_absolute()
            or not self.executable.is_file()
            or self.arguments not in expected.get(self.executable.name.lower(), ())
        ):
            raise CampusError(ErrorCode.STARTUP_ERROR, "后台运行程序或固定启动参数无效。")

    def argv(self) -> list[str]:
        self.validate()
        return [str(self.executable), *self.arguments]


def monitor_command() -> LaunchCommand:
    executable = Path(sys.executable)
    if getattr(sys, "frozen", False):
        return LaunchCommand(executable.with_name("CampusAutoConnect.exe"), FROZEN_ARGUMENTS)
    return LaunchCommand(executable.with_name("pythonw.exe"), SOURCE_ARGUMENTS)


def startup_command() -> LaunchCommand:
    launch = monitor_command()
    return LaunchCommand(
        launch.executable,
        FROZEN_STARTUP_ARGUMENTS if getattr(sys, "frozen", False) else SOURCE_STARTUP_ARGUMENTS,
    )
