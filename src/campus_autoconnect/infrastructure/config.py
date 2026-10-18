"""Non-secret JSON, atomic replacement, strict schema and safe recovery."""

import json
import os
import re
import tempfile
import threading
from collections.abc import Callable
from dataclasses import asdict
from pathlib import Path

from campus_autoconnect.core.errors import CampusError
from campus_autoconnect.core.models import ErrorCode, NetworkProfile
from campus_autoconnect.core.portal import normalize_authority, normalize_bjut_endpoints
from campus_autoconnect.infrastructure.files import read_text_shared
from campus_autoconnect.infrastructure.locking import FileMutex

_REF = re.compile(r"[A-Za-z0-9_-]{1,64}\Z")
_PROFILE_FIELDS = set(NetworkProfile.__dataclass_fields__)


def user_data_dir() -> Path:
    local = os.environ.get("LOCALAPPDATA")
    if os.name != "nt" or not local or not Path(local).is_absolute():
        raise CampusError(ErrorCode.CONFIG_ERROR, "需要 Windows LOCALAPPDATA 用户数据目录。")
    return Path(local) / "CampusAutoConnect"


def validate_ref(value: str) -> str:
    if not isinstance(value, str) or not _REF.fullmatch(value):
        raise ValueError("凭据引用只允许 1–64 位字母、数字、下划线或连字符。")
    return value


def validate_profile(profile: NetworkProfile) -> NetworkProfile:
    if not _REF.fullmatch(profile.profile_id):
        raise ValueError("档案 ID 无效。")
    for value, limit in ((profile.display_name, 80), (profile.ssid, 32)):
        if (
            not isinstance(value, str)
            or not value.strip()
            or len(value.encode("utf-8")) > limit
            or any(ord(c) < 32 or ord(c) == 127 for c in value)
        ):
            raise ValueError("档案名称不能为空且最多 80 字节；SSID 必须为 1–32 字节可显示文本。")
    if type(profile.enabled) is not bool or type(profile.auto_auth) is not bool:
        raise ValueError("启用和自动认证标记必须为布尔值。")
    if type(profile.allow_http_auth) is not bool:
        raise ValueError("HTTP 兼容许可必须为布尔值。")
    if type(profile.allow_zero_mac) is not bool:
        raise ValueError("全零 MAC 兼容许可必须为布尔值。")
    endpoints = normalize_bjut_endpoints(profile.portal_page_url, profile.bjut_api_origin)
    if endpoints != (profile.portal_page_url, profile.bjut_api_origin):
        raise ValueError("认证地址请使用规范化的协议、精确主机与端口。")
    if profile.allow_http_auth and not endpoints[0].startswith("http://"):
        raise ValueError("允许 HTTP 兼容前，必须明确填写 HTTP 认证页和认证服务地址。")
    if profile.allow_zero_mac and not all(endpoints):
        raise ValueError("允许全零 MAC 兼容前，必须明确填写认证页和认证服务地址。")
    if profile.adapter_id != "bjut":
        raise ValueError("M1 用户档案仅支持 bjut 适配器。")
    validate_ref(profile.credential_ref)
    if not isinstance(profile.trusted_portal_hosts, tuple) or any(
        not isinstance(host, str) for host in profile.trusted_portal_hosts
    ):
        raise ValueError("可信主机必须为字符串列表。")
    if len(set(profile.trusted_portal_hosts)) != len(profile.trusted_portal_hosts):
        raise ValueError("可信主机不得重复。")
    for host in profile.trusted_portal_hosts:
        if normalize_authority(host) != host:
            raise ValueError("可信主机请使用规范化的小写形式。")
    if profile.last_verified_at is not None:
        from datetime import datetime

        if not isinstance(profile.last_verified_at, str):
            raise ValueError("验证时间必须为 ISO 时间字符串。")
        datetime.fromisoformat(profile.last_verified_at)
    return profile


class ConfigStore:
    MAX_BYTES = 256 * 1024

    def __init__(self, path: Path | None = None) -> None:
        self.path = path if path is not None else user_data_dir() / "config.json"
        self.warning: str | None = None
        self._lock = threading.RLock()

    def load(self) -> list[NetworkProfile]:
        with self._lock:
            self.warning = None
            try:
                return self._read(self.path)
            except FileNotFoundError:
                return []
            except (ValueError, TypeError, KeyError, OSError, UnicodeError, RecursionError):
                # Keep both original and backup intact. Saving requires explicit repair.
                try:
                    profiles = self._read(self.path.with_suffix(".json.bak"))
                except (ValueError, TypeError, KeyError, OSError, UnicodeError, RecursionError):
                    profiles = []
                self.warning = "配置损坏或不可读，已使用有效备份或空档案；请人工检查后修复。"
                return profiles

    def _read(self, path: Path) -> list[NetworkProfile]:
        return self.decode(read_text_shared(path, self.MAX_BYTES))

    @classmethod
    def decode(cls, text: str) -> list[NetworkProfile]:
        if len(text.encode("utf-8")) > cls.MAX_BYTES:
            raise ValueError("档案文件过大。")
        raw = json.loads(text)
        if (
            not isinstance(raw, dict)
            or set(raw) != {"schema_version", "profiles"}
            or type(raw["schema_version"]) is not int
            or raw["schema_version"] != 1
            or not isinstance(raw["profiles"], list)
        ):
            raise ValueError("配置版本或结构不支持。")
        result = []
        for item in raw["profiles"]:
            if not isinstance(item, dict) or set(item) - _PROFILE_FIELDS:
                raise ValueError("配置包含不支持字段。")
            entry = dict(item)
            hosts = entry.get("trusted_portal_hosts", [])
            if not isinstance(hosts, list):
                raise ValueError("主机列表无效。")
            entry["trusted_portal_hosts"] = tuple(hosts)
            result.append(validate_profile(NetworkProfile(**entry)))
        cls._validate_unique(result)
        return result

    @staticmethod
    def _validate_unique(profiles: list[NetworkProfile]) -> None:
        ids = [p.profile_id for p in profiles]
        enabled_ssids = [p.ssid for p in profiles if p.enabled]
        if len(ids) != len(set(ids)) or len(enabled_ssids) != len(set(enabled_ssids)):
            raise ValueError("档案 ID 或启用的 SSID 存在重复；精确匹配必须唯一。")

    def save(self, profiles: list[NetworkProfile]) -> None:
        with self._lock, FileMutex(self.path.with_suffix(".json.lock")):
            self._save(profiles)

    def update(self, change: Callable[[list[NetworkProfile]], list[NetworkProfile]]) -> None:
        """Hold one cross-process lock across the complete read/modify/write transaction."""
        with self._lock, FileMutex(self.path.with_suffix(".json.lock")):
            profiles = self.load()
            if self.warning:
                raise CampusError(ErrorCode.CONFIG_ERROR, "配置无效，已阻止修改；请先人工修复。")
            self._save(change(profiles))

    def _save(self, profiles: list[NetworkProfile]) -> None:
        with self._lock:
            try:
                for p in profiles:
                    validate_profile(p)
                self._validate_unique(profiles)
                payload = json.dumps(
                    {"schema_version": 1, "profiles": [asdict(p) for p in profiles]},
                    ensure_ascii=False,
                    indent=2,
                )
                if len(payload.encode("utf-8")) > self.MAX_BYTES:
                    raise ValueError("档案总量超过配置大小上限。")
                self.path.parent.mkdir(parents=True, exist_ok=True)
                if self.path.exists():
                    try:
                        self._read(self.path)
                    except (
                        ValueError,
                        TypeError,
                        KeyError,
                        OSError,
                        UnicodeError,
                        RecursionError,
                    ) as exc:
                        raise CampusError(
                            ErrorCode.CONFIG_ERROR,
                            "原配置无效，已阻止覆盖。请先按文档备份并移走损坏文件。",
                        ) from exc
                    self._atomic_write(
                        self.path.with_suffix(".json.bak"),
                        read_text_shared(self.path, self.MAX_BYTES),
                    )
                self._atomic_write(self.path, payload + "\n")
            except CampusError:
                raise
            except (OSError, ValueError, TypeError) as exc:
                raise CampusError(
                    ErrorCode.CONFIG_ERROR, "配置保存失败，请检查档案或用户目录权限。"
                ) from exc

    @staticmethod
    def _atomic_write(path: Path, text: str) -> None:
        with FileMutex(path.with_suffix(path.suffix + ".io.lock"), timeout=1.0):
            ConfigStore._write_locked(path, text)

    @staticmethod
    def _write_locked(path: Path, text: str) -> None:
        temp_path: Path | None = None
        try:
            with tempfile.NamedTemporaryFile(
                mode="w", encoding="utf-8", dir=path.parent, prefix=".campus-", delete=False
            ) as stream:
                temp_path = Path(stream.name)
                stream.write(text)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temp_path, path)
        finally:
            if temp_path is not None:
                temp_path.unlink(missing_ok=True)
