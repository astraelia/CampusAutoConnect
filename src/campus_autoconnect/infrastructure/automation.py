"""M2 opt-in settings are separate from the unchanged M1 profile schema."""

import json
from dataclasses import dataclass
from pathlib import Path

from campus_autoconnect.core.errors import CampusError
from campus_autoconnect.core.models import ErrorCode
from campus_autoconnect.infrastructure.config import ConfigStore, user_data_dir
from campus_autoconnect.infrastructure.files import read_text_shared
from campus_autoconnect.infrastructure.locking import FileMutex


@dataclass(frozen=True)
class AutomationSettings:
    enabled: bool = False


class AutomationStore:
    def __init__(self, path: Path | None = None) -> None:
        self.path = path if path is not None else user_data_dir() / "automation.json"

    def load(self) -> AutomationSettings:
        try:
            raw = json.loads(read_text_shared(self.path, 1024))
            if (
                not isinstance(raw, dict)
                or set(raw) != {"schema_version", "enabled"}
                or type(raw["schema_version"]) is not int
                or raw["schema_version"] != 1
                or type(raw["enabled"]) is not bool
            ):
                raise ValueError
            return AutomationSettings(raw["enabled"])
        except FileNotFoundError:
            return AutomationSettings()
        except (OSError, ValueError, TypeError, RecursionError) as exc:
            # Never recover an enabled value from a backup after corruption.
            raise CampusError(
                ErrorCode.CONFIG_ERROR, "自动认证设置无效或不可读，已关闭本次自动操作。"
            ) from exc

    def set_enabled(self, enabled: bool) -> None:
        if type(enabled) is not bool:
            raise ValueError("自动认证开关必须为布尔值。")
        try:
            with FileMutex(self.path.with_suffix(".lock")):
                # Explicit user action may repair this minimal, non-secret settings file.
                self.path.parent.mkdir(parents=True, exist_ok=True)
                ConfigStore._atomic_write(
                    self.path,
                    json.dumps({"schema_version": 1, "enabled": enabled}) + "\n",
                )
        except OSError as exc:
            raise CampusError(ErrorCode.CONFIG_ERROR, "自动认证开关保存失败。") from exc
