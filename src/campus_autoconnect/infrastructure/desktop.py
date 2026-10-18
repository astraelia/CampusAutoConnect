"""Strict non-sensitive desktop preferences. They cannot enable authentication."""

import json
from dataclasses import asdict, dataclass
from pathlib import Path

from campus_autoconnect.core.errors import CampusError
from campus_autoconnect.core.models import ErrorCode
from campus_autoconnect.infrastructure.config import ConfigStore
from campus_autoconnect.infrastructure.files import read_text_shared
from campus_autoconnect.infrastructure.locking import FileMutex


@dataclass(frozen=True)
class DesktopPreferences:
    theme: str = "system"
    close_to_tray: bool = True


class DesktopStore:
    def __init__(self, path: Path) -> None:
        self.path = path

    @staticmethod
    def validate(raw: object) -> DesktopPreferences:
        if (
            not isinstance(raw, dict)
            or set(raw) != {"schema_version", "theme", "close_to_tray"}
            or type(raw["schema_version"]) is not int
            or raw["schema_version"] != 1
            or raw["theme"] not in ("system", "light", "dark")
            or type(raw["close_to_tray"]) is not bool
        ):
            raise ValueError
        return DesktopPreferences(raw["theme"], raw["close_to_tray"])

    def load(self) -> DesktopPreferences:
        try:
            return self.validate(json.loads(read_text_shared(self.path, 4096)))
        except FileNotFoundError:
            return DesktopPreferences()
        except (OSError, ValueError, TypeError, RecursionError) as exc:
            raise CampusError(
                ErrorCode.CONFIG_ERROR, "桌面偏好无效，请重新保存主题与关闭方式。"
            ) from exc

    def save(self, preferences: DesktopPreferences) -> None:
        raw = {"schema_version": 1, **asdict(preferences)}
        self.validate(raw)
        try:
            with FileMutex(self.path.with_suffix(".json.lock")):
                ConfigStore._atomic_write(self.path, json.dumps(raw) + "\n")
        except OSError as exc:
            raise CampusError(ErrorCode.CONFIG_ERROR, "无法保存桌面偏好，请检查用户目录。") from exc
