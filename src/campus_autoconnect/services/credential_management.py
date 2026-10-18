"""User-initiated credential management and non-secret, explicitly stale receipts."""

import json
import threading
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from campus_autoconnect.core.errors import CampusError
from campus_autoconnect.core.models import Credentials, ErrorCode
from campus_autoconnect.infrastructure.config import ConfigStore, validate_ref
from campus_autoconnect.infrastructure.files import read_text_shared
from campus_autoconnect.infrastructure.locking import FileMutex
from campus_autoconnect.security.credentials import CredentialStore, WindowsCredentialStore


@dataclass(frozen=True)
class CredentialStatus:
    state: str = "unknown"
    checked_at: str | None = None
    historical: bool = False
    receipt_saved: bool = True

    def label(self) -> str:
        labels = {
            "unknown": "尚未检查；输入框为空不表示没有保存。",
            "confirmed": "已保存并复核：本次输入与 Windows 安全存储一致。",
            "present": "已找到可读取的凭据；没有进行校园网账号密码验证。",
            "absent": "本次查询未找到该引用的凭据。",
            "error": "查询失败，当前无法确认保存状态；请稍后重新检查。",
            "unconfirmed": "写入调用已完成，但回读复核失败；保存结果待确认。",
        }
        if self.historical:
            message = "上次保存/检查记录：" + labels[self.state] + " 本次启动尚未重新检查。"
        else:
            message = labels[self.state]
        if self.checked_at:
            message += "\n确认时间：" + self.checked_at
        if not self.receipt_saved:
            message += "\n状态记录未能持久保存；不会改变本次安全存储查询结果。"
        return message


class CredentialManagement:
    def __init__(self, store: CredentialStore, directory: Path | None = None) -> None:
        self.store = store
        self.path = directory / "credential-status.json" if directory else None
        self._lock = threading.RLock()
        self._current: dict[str, CredentialStatus] = {}

    def _receipts(self) -> dict:
        if self.path is None:
            return {}
        try:
            raw = json.loads(read_text_shared(self.path, 32768))
            if not isinstance(raw, dict) or set(raw) != {"schema_version", "receipts"}:
                raise ValueError
            entries = raw["receipts"]
            if (
                type(raw["schema_version"]) is not int
                or raw["schema_version"] != 1
                or not isinstance(entries, dict)
                or len(entries) > 128
            ):
                raise ValueError
            for reference, item in entries.items():
                validate_ref(reference)
                if not isinstance(item, dict) or set(item) != {"state", "checked_at"}:
                    raise ValueError
                if item["state"] not in {"confirmed", "present", "absent", "error", "unconfirmed"}:
                    raise ValueError
                at = item["checked_at"]
                if not isinstance(at, str) or len(at) > 40:
                    raise ValueError
                datetime.fromisoformat(at)
            return entries
        except FileNotFoundError:
            return {}
        except (OSError, CampusError, ValueError, TypeError, RecursionError):
            return {}  # A receipt never proves the current presence of credentials.

    def snapshot(self, reference: str) -> CredentialStatus:
        validate_ref(reference)
        with self._lock:
            if reference in self._current:
                return self._current[reference]
            item = self._receipts().get(reference)
            return CredentialStatus(**item, historical=True) if item else CredentialStatus()

    def _remember(self, reference: str, state: str) -> CredentialStatus:
        status = CredentialStatus(
            state, datetime.now(UTC).astimezone().isoformat(timespec="seconds")
        )
        with self._lock:
            if self.path is not None:
                try:
                    with FileMutex(self.path.with_suffix(".lock"), timeout=1):
                        entries = self._receipts()
                        entries[reference] = {"state": state, "checked_at": status.checked_at}
                        entries = dict(list(entries.items())[-128:])
                        ConfigStore._atomic_write(
                            self.path,
                            json.dumps({"schema_version": 1, "receipts": entries}) + "\n",
                        )
                except (OSError, CampusError):
                    status = CredentialStatus(state, status.checked_at, receipt_saved=False)
            self._current.pop(reference, None)
            self._current[reference] = status
        return status

    def save(self, reference: str, credentials: Credentials) -> CredentialStatus:
        validate_ref(reference)
        try:
            self.store.set(reference, credentials)
            # The production store verifies inside its cross-process mutation lock.
            if (
                not isinstance(self.store, WindowsCredentialStore)
                and self.store.get(reference) != credentials
            ):
                raise CampusError(ErrorCode.CREDENTIAL_VERIFY, "写入后回读复核失败。")
        except CampusError as exc:
            self._remember(
                reference, "unconfirmed" if exc.code == ErrorCode.CREDENTIAL_VERIFY else "error"
            )
            raise
        return self._remember(reference, "confirmed")

    def check(self, reference: str) -> CredentialStatus:
        validate_ref(reference)
        try:
            present = self.store.exists(reference)
        except CampusError:
            return self._remember(reference, "error")
        return self._remember(reference, "present" if present else "absent")

    def delete(self, reference: str) -> CredentialStatus:
        self.store.delete(reference)
        return self.check(reference)

    def diagnostic(self) -> dict:
        with self._lock:
            statuses = list(self._current.values())
        latest = statuses[-1] if statuses else CredentialStatus()
        return {
            "state": latest.state,
            "checked_at": latest.checked_at,
            "source": "user_credential_management",
            "historical": latest.historical,
        }
