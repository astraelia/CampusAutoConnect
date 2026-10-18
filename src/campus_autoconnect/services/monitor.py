"""Single per-user runtime, cooperative stop, sanitized status and fallback polling."""

import json
import logging
import re
import threading
import time
import uuid
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path

from campus_autoconnect.core.errors import CampusError
from campus_autoconnect.core.models import (
    AuthProgress,
    AuthStage,
    AuthState,
    ErrorCode,
    NetworkSnapshot,
    ProfileIssue,
)
from campus_autoconnect.core.network import NetworkProvider
from campus_autoconnect.core.network_native import NativeFailure
from campus_autoconnect.core.profiles import ProfileService
from campus_autoconnect.infrastructure.automation import AutomationStore
from campus_autoconnect.infrastructure.config import ConfigStore, user_data_dir
from campus_autoconnect.infrastructure.files import read_text_shared
from campus_autoconnect.infrastructure.locking import FileMutex
from campus_autoconnect.infrastructure.logging import log_startup_timing
from campus_autoconnect.infrastructure.windows_events import WindowsEventSource
from campus_autoconnect.services.automation import AutomationCoordinator, AutomationState


class MonitorControl:
    def __init__(self, directory: Path | None = None) -> None:
        self.directory = directory if directory is not None else user_data_dir()
        self.lock_path = self.directory / "monitor.lock"
        self.status_path = self.directory / "monitor-status.json"
        self.stop_path = self.directory / "monitor-stop.json"

    @staticmethod
    def _read(path: Path) -> dict:
        raw = json.loads(read_text_shared(path, 8192))
        if not isinstance(raw, dict):
            raise ValueError
        return raw

    def write(self, instance: str, status: dict) -> None:
        self.directory.mkdir(parents=True, exist_ok=True)
        ConfigStore._atomic_write(
            self.status_path,
            json.dumps({"schema_version": 1, "instance": instance, **status}, ensure_ascii=False)
            + "\n",
        )

    def _current(self) -> dict:
        raw = self._read(self.status_path)
        if (
            raw.get("schema_version") != 1
            or not isinstance(raw.get("instance"), str)
            or len(raw["instance"]) != 32
            or any(c not in "0123456789abcdef" for c in raw["instance"])
        ):
            raise ValueError
        # Whitelist the projection; never echo arbitrary fields from a modified status file.
        state = AutomationState(raw["state"])
        code = ErrorCode(raw["error_code"])
        failure_type = raw.get("failure_type")
        if failure_type is not None and (
            not isinstance(failure_type, str)
            or not re.fullmatch(r"[A-Za-z_][A-Za-z_0-9]{0,79}", failure_type)
        ):
            failure_type = "Exception"
        return {
            "instance": raw["instance"],
            "state": state.value,
            "error_code": code.value,
            "attempts": self._integer(raw.get("attempts"), 0, 3),
            "max_attempts": self._integer(raw.get("max_attempts"), 1, 3),
            "operation_running": raw.get("operation_running") is True,
            "event_fallback": raw.get("event_fallback") is True,
            "runtime_error": ErrorCode(raw.get("runtime_error", "none")).value,
            "failure_type": failure_type,
            "last_auth_state": AuthState(raw["last_auth_state"]).value
            if raw.get("last_auth_state")
            else None,
            "last_checked_at": self._timestamp(raw.get("last_checked_at")),
            "last_authentication": self._authentication(raw.get("last_authentication")),
            "network_query": self._network_query(raw.get("network_query")),
            "retry_in_seconds": self._seconds(raw.get("retry_in_seconds")),
        }

    @classmethod
    def _network_query(cls, raw: object) -> dict | None:
        if raw is None:
            return None  # Older monitors and injected providers have no query telemetry.
        if not isinstance(raw, dict) or raw.get("backend") not in {"native", "powershell"}:
            raise ValueError
        reason = raw.get("fallback_reason")
        if reason is not None:
            reason = NativeFailure(reason).value
        return {
            "backend": raw["backend"],
            "fallback_reason": reason,
            "snapshot_ms": cls._integer(raw.get("snapshot_ms"), 0, 86400000),
            "route_ms": cls._integer(raw.get("route_ms"), 0, 86400000),
        }

    @staticmethod
    def _authentication(raw: object) -> dict | None:
        if raw is None:
            return None  # Older monitors did not record these facts.
        if not isinstance(raw, dict):
            raise ValueError
        values = {}
        for key in (
            "profile_matched",
            "portal_page_configured",
            "api_origin_configured",
            "http_auth_allowed",
            "credential_read_attempted",
            "login_request_attempted",
        ):
            value = raw.get(key)
            optional = key in {"credential_read_attempted", "login_request_attempted"}
            if type(value) is not bool and not (optional and value is None):
                raise ValueError
            values[key] = value
        for key in ("zero_mac_allowed", "zero_mac_observed", "zero_vlan_observed"):
            value = raw.get(key, False if key == "zero_mac_allowed" else None)
            if type(value) is not bool and not (key != "zero_mac_allowed" and value is None):
                raise ValueError
            values[key] = value
        issues = raw.get("profile_issues")
        if not isinstance(issues, list) or len(issues) > len(ProfileIssue):
            raise ValueError
        return AuthProgress(
            stage=AuthStage(raw["stage"]),
            profile_issues=tuple(ProfileIssue(issue) for issue in issues),
            **values,
        ).diagnostic()

    @staticmethod
    def _timestamp(value: object) -> str | None:
        if value is None:
            return None
        if not isinstance(value, str) or len(value) > 40:
            raise ValueError
        return datetime.fromisoformat(value).isoformat()

    @staticmethod
    def _seconds(value: object) -> float | None:
        if value is None:
            return None
        if type(value) not in (int, float) or not 0 <= value <= 86400:
            raise ValueError
        return float(value)

    @staticmethod
    def _integer(value: object, lower: int, upper: int) -> int:
        if type(value) is not int or not lower <= value <= upper:
            raise ValueError
        return value

    def status(self) -> dict:
        mutex = FileMutex(self.lock_path)
        if mutex.acquire():
            mutex.release()
            code, failure_type = "none", None
            try:
                previous = self._current()
                code, failure_type = previous["runtime_error"], previous["failure_type"]
                if code == "none" and previous["state"] != "STOPPED":
                    code = "unknown"
            except FileNotFoundError:
                pass
            except (OSError, ValueError, TypeError, KeyError, RecursionError):
                code = "config_error"
            return {
                "running": False,
                "state": "STOPPED",
                "error_code": code,
                "failure_type": failure_type,
            }
        try:
            result = self._current()
            result.pop("instance")
            return {"running": True, **result}
        except (OSError, ValueError, TypeError, KeyError, RecursionError):
            return {"running": True, "state": "UNAVAILABLE", "error_code": "config_error"}

    def request_stop(self) -> bool:
        mutex = FileMutex(self.lock_path)
        if mutex.acquire():
            mutex.release()
            return False
        try:
            instance = self._current()["instance"]
            ConfigStore._atomic_write(
                self.stop_path, json.dumps({"schema_version": 1, "instance": instance}) + "\n"
            )
            return True
        except (OSError, ValueError, TypeError, KeyError, RecursionError) as exc:
            raise CampusError(
                ErrorCode.CONFIG_ERROR, "后台状态尚不可用，停止请求未发送；请稍后重试。"
            ) from exc

    def stop_requested(self, instance: str) -> bool:
        try:
            return self._read(self.stop_path) == {"schema_version": 1, "instance": instance}
        except FileNotFoundError:
            return False
        except (OSError, ValueError, TypeError, RecursionError) as exc:
            raise CampusError(ErrorCode.CONFIG_ERROR, "后台控制文件无效，已停止自动操作。") from exc


class MonitorRuntime:
    def __init__(
        self,
        coordinator: AutomationCoordinator,
        network: NetworkProvider,
        profiles: ProfileService,
        settings: AutomationStore,
        control: MonitorControl,
        *,
        events: WindowsEventSource | None = None,
        logger: logging.Logger | None = None,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self.coordinator = coordinator
        self.network = network
        self.profiles = profiles
        self.settings = settings
        self.control = control
        self.events = events if events is not None else WindowsEventSource()
        self.logger = logger
        self.clock = clock
        self._wake = threading.Event()
        self._changed = threading.Event()
        self._last_log: tuple | None = None
        self._failure_code = ErrorCode.NONE
        self._failure_type: str | None = None
        self._started_at: float | None = None
        self._timed_ready = self._timed_online = False

    def _notify(self, event: str) -> None:
        self.coordinator.invalidate(event)
        self._changed.set()
        self._wake.set()

    def _write_status(self, instance: str) -> None:
        status = self.coordinator.status()
        if not self._timed_online and status["state"] == "ONLINE" and self._started_at is not None:
            log_startup_timing(self.logger, "online", self.clock() - self._started_at)
            self._timed_online = True
        self.control.write(
            instance,
            {
                **status,
                "event_fallback": bool(self.events.warnings),
                "heartbeat_at": datetime.now(UTC).isoformat(),
                "runtime_error": self._failure_code.value,
                "failure_type": self._failure_type,
                "network_query": self.network.diagnostics()
                if callable(getattr(self.network, "diagnostics", None))
                else None,
            },
        )
        current = (
            status["state"],
            status["error_code"],
            status["attempts"],
            self._failure_code.value,
        )
        if self.logger is not None and current != self._last_log:
            self.logger.info("automation state=%s code=%s attempt=%d runtime_error=%s", *current)
            self._last_log = current

    def run(self, *, stop: threading.Event | None = None, duration: float | None = None) -> None:
        if duration is not None and not 0 < duration <= 86400:
            raise ValueError("后台运行时长须为 0–86400 秒之间的正数。")
        stop = stop if stop is not None else threading.Event()
        # Status probes briefly acquire the same lock. Wait through that bounded probe;
        # a real second runtime retains it and still produces BUSY before any work.
        with FileMutex(self.control.lock_path, timeout=1):
            instance = uuid.uuid4().hex
            snapshot: NetworkSnapshot | None = None
            started = self.clock()
            self._started_at = started
            self._timed_ready = self._timed_online = False
            log_startup_timing(self.logger, "background_started", 0)
            sample_due, write_due = started, started
            previous_tick = started
            try:
                self.coordinator.begin()
                self.events.start(self._notify)
                self._write_status(instance)
                while not stop.is_set():
                    now = self.clock()
                    if now - previous_tick > max(
                        60.0, self.coordinator.policy.snapshot_interval * 2
                    ):
                        # Covers missed resume notifications / long process suspension.
                        self._notify("resume")
                    previous_tick = now
                    if duration is not None and now - started >= duration:
                        break
                    if self.control.stop_requested(instance):
                        break
                    try:
                        enabled = self.settings.load().enabled
                        if enabled and (now >= sample_due or self._changed.is_set()):
                            self._changed.clear()
                            snapshot = self.network.snapshot()
                            sample_due = self.clock() + self.coordinator.policy.snapshot_interval
                            # A callback during the query invalidates that potentially stale sample.
                            if self._changed.is_set():
                                snapshot = None
                        current = snapshot if snapshot is not None else NetworkSnapshot()
                        profile = self.profiles.match(current.ssid) if enabled else None
                        self.coordinator.observe(current, profile, enabled=enabled)
                        if (
                            not self._timed_ready
                            and self.coordinator.state.value == "WAITING_READY"
                            and self.coordinator.code == ErrorCode.NONE
                        ):
                            log_startup_timing(self.logger, "network_ready", self.clock() - started)
                            self._timed_ready = True
                    except CampusError as exc:
                        self.coordinator.fail(exc.code)
                        snapshot = None
                        sample_due = self.clock() + self.coordinator.policy.snapshot_interval
                    self.coordinator.tick()
                    if now >= write_due:
                        self._write_status(instance)
                        write_due = self.clock() + 1.0
                    self._wake.wait(0.25)
                    self._wake.clear()
            except CampusError as exc:
                self._failure_code, self._failure_type = exc.code, "CampusError"
                raise
            except Exception as exc:
                self._failure_code, self._failure_type = ErrorCode.UNKNOWN, type(exc).__name__
                raise
            finally:
                self.coordinator.stop()
                self.events.close()
                # Hold the singleton lock until old work has drained; never overlap submissions.
                while self.coordinator.working:
                    self.coordinator.tick()
                    self._wake.wait(0.1)
                    self._wake.clear()
                self._write_status(instance)
