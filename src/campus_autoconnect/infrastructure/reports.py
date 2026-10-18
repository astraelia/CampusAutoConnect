"""Reports belong beside the installed EXE. No implicit user-directory fallback."""

import json
import stat
import sys
import tempfile
import uuid
from datetime import UTC, datetime
from pathlib import Path

from campus_autoconnect.core.errors import CampusError
from campus_autoconnect.core.models import ErrorCode
from campus_autoconnect.infrastructure.config import ConfigStore
from campus_autoconnect.infrastructure.locking import FileMutex

REPORT_FILES = frozenset(
    {
        "diagnostic.json",
        "diagnostic.txt",
        "PortalCapture_session.json",
        "PortalCapture_session.txt",
        "lifecycle.json",
    }
)
SESSION_META = "session.json"
SESSION_LOCK = "active.lock"


def plain_path(path: Path) -> bool:
    """Never traverse a symbolic link or Windows reparse point for report IO."""
    try:
        info = path.lstat()
    except FileNotFoundError:
        return True
    return not (
        stat.S_ISLNK(info.st_mode)
        or getattr(info, "st_file_attributes", 0)
        & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    )


def check_report_root(root: Path) -> None:
    if any(not plain_path(path) for path in (root, *root.parents)):
        raise CampusError(ErrorCode.CONFIG_ERROR, "报告路径包含链接或联接，已停止写入或清理。")
    root.mkdir(parents=True, exist_ok=True)
    if not plain_path(root / ".reports.lock"):
        raise CampusError(ErrorCode.CONFIG_ERROR, "报告互斥文件异常，已停止操作。")


def installation_directory() -> Path:
    if getattr(sys, "frozen", False):
        return Path(sys.executable).absolute().parent
    return Path(__file__).absolute().parents[3]


class ReportSession:
    def __init__(self, root: Path | None = None) -> None:
        self.root = (root if root is not None else installation_directory() / "reports").absolute()
        self.created_at = datetime.now(UTC)
        self.protected = False
        self._active: FileMutex | None = None
        self.directory = self.root / (
            datetime.now(UTC).astimezone().strftime("%Y%m%d_%H%M%S_") + uuid.uuid4().hex[:12]
        )

    def preflight(self) -> None:
        try:
            check_report_root(self.root)
            with FileMutex(self.root / ".reports.lock", timeout=1):
                self._preflight()
        except OSError as exc:
            raise CampusError(
                ErrorCode.CONFIG_ERROR,
                "程序目录下 reports 不可写；请将完整程序放到本人可写的固定目录。未改存其他位置。",
            ) from exc

    def _preflight(self) -> None:
        if not plain_path(self.directory):
            raise CampusError(ErrorCode.CONFIG_ERROR, "报告会话路径异常，已停止保存。")
        self.directory.mkdir(exist_ok=True)
        if any(not plain_path(path) for path in self.directory.iterdir()):
            raise CampusError(ErrorCode.CONFIG_ERROR, "报告会话包含链接或联接，已停止保存。")
        if self._active is None:
            active = FileMutex(self.directory / SESSION_LOCK)
            if not active.acquire():
                raise CampusError(ErrorCode.BUSY, "报告会话正在被其他进程使用。")
            self._active = active
        with tempfile.TemporaryFile(dir=self.directory) as stream:
            stream.write(b"report-write-check")
            stream.flush()
        self._write_metadata()

    def _write_metadata(self) -> None:
        ConfigStore._atomic_write(
            self.directory / SESSION_META,
            json.dumps(
                {
                    "schema_version": 1,
                    "source": "CampusAutoConnect",
                    "created_at": self.created_at.isoformat(),
                    "protected": self.protected,
                }
            )
            + "\n",
        )

    def set_protected(self, value: bool) -> None:
        if type(value) is not bool:
            raise ValueError("报告保留标记无效。")
        self.preflight()
        with FileMutex(self.root / ".reports.lock", timeout=1):
            self.protected = value
            self._write_metadata()

    def close(self) -> None:
        if getattr(self, "_active", None) is not None:
            self._active.release()
            self._active = None

    def __del__(self) -> None:
        self.close()

    def write(self, name: str, value: dict | str) -> Path:
        if name not in REPORT_FILES:
            raise ValueError("报告文件名不受支持。")
        content = (
            json.dumps(value, ensure_ascii=False, indent=2, allow_nan=False)
            if isinstance(value, dict)
            else value
        )
        if len(content.encode("utf-8")) > 2 * 1024 * 1024:
            raise CampusError(ErrorCode.CONFIG_ERROR, "报告超过保存上限，未覆盖现有报告。")
        try:
            check_report_root(self.root)
            with FileMutex(self.root / ".reports.lock", timeout=1):
                self._preflight()
                path = self.directory / name
                ConfigStore._atomic_write(path, content + "\n")
                return path
        except OSError as exc:
            raise CampusError(
                ErrorCode.CONFIG_ERROR, "报告保存失败；窗口中的结果仍可复制。"
            ) from exc
