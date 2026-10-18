"""Only the explicit Windows Credential Manager backend is accepted."""

import json
import os
from contextlib import nullcontext
from typing import Protocol

from campus_autoconnect.core.errors import CampusError
from campus_autoconnect.core.models import Credentials, ErrorCode
from campus_autoconnect.infrastructure.config import validate_ref
from campus_autoconnect.infrastructure.locking import FileMutex


class CredentialStore(Protocol):
    def exists(self, reference: str) -> bool: ...
    def get(self, reference: str) -> Credentials | None: ...
    def set(self, reference: str, credentials: Credentials) -> None: ...
    def delete(self, reference: str) -> None: ...


class WindowsCredentialStore:
    SERVICE = "CampusAutoConnect/v1"

    def __init__(self, mutation_lock: FileMutex | None = None) -> None:
        self._mutation_lock = mutation_lock

    @staticmethod
    def _backend():
        if os.name != "nt":
            raise CampusError(
                ErrorCode.CREDENTIAL_STORE, "凭据存储仅支持 Windows Credential Manager。"
            )
        try:
            from keyring.backends.Windows import WinVaultKeyring

            backend = WinVaultKeyring()
            if type(backend) is not WinVaultKeyring or backend.priority <= 0:
                raise RuntimeError
            return backend
        except Exception as exc:
            raise CampusError(
                ErrorCode.CREDENTIAL_STORE, "Windows 安全凭据后端不可用；不会回退到文件存储。"
            ) from exc

    def get(self, reference: str) -> Credentials | None:
        validate_ref(reference)
        try:
            value = self._backend().get_password(self.SERVICE, reference)
            if value is None:
                return None
            raw = json.loads(value)
            if set(raw) != {"username", "password"}:
                raise ValueError
            if not all(isinstance(raw[k], str) and raw[k] for k in raw):
                raise ValueError
            return Credentials(raw["username"], raw["password"])
        except CampusError:
            raise
        except Exception as exc:
            raise CampusError(
                ErrorCode.CREDENTIAL_STORE, "无法读取安全凭据，请重新保存或检查系统权限。"
            ) from exc

    def exists(self, reference: str) -> bool:
        return self.get(reference) is not None

    def set(self, reference: str, credentials: Credentials) -> None:
        with self._mutation_lock if self._mutation_lock is not None else nullcontext():
            self._set(reference, credentials)

    def _set(self, reference: str, credentials: Credentials) -> None:
        validate_ref(reference)
        if (
            not credentials.username.strip()
            or not credentials.password
            or len(credentials.username) > 256
            or len(credentials.password) > 1024
        ):
            raise ValueError("账号和密码不能为空，或超过长度限制。")
        try:
            # Both account and password stay inside one protected WinVault value.
            payload = json.dumps(
                {"username": credentials.username, "password": credentials.password},
                ensure_ascii=False,
            )
            if len(payload.encode("utf-16-le")) > 2400:
                raise ValueError
            self._backend().set_password(self.SERVICE, reference, payload)
        except CampusError:
            raise
        except Exception as exc:
            raise CampusError(
                ErrorCode.CREDENTIAL_STORE, "安全凭据保存失败，未写入任何明文文件。"
            ) from exc
        try:
            if self.get(reference) != credentials:
                raise ValueError
        except Exception as exc:
            raise CampusError(
                ErrorCode.CREDENTIAL_VERIFY,
                "Windows 写入调用已完成，但回读核对失败；保存结果待确认，请主动检查保存状态。",
            ) from exc

    def delete(self, reference: str) -> None:
        with self._mutation_lock if self._mutation_lock is not None else nullcontext():
            self._delete(reference)

    def _delete(self, reference: str) -> None:
        validate_ref(reference)
        try:
            backend = self._backend()
            if backend.get_password(self.SERVICE, reference) is not None:
                backend.delete_password(self.SERVICE, reference)
        except CampusError:
            raise
        except Exception as exc:
            raise CampusError(
                ErrorCode.CREDENTIAL_STORE, "安全凭据删除失败，请检查 Windows 凭据管理器。"
            ) from exc
