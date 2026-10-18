"""Bounded automatic orchestration around the existing one-shot authentication service.

Only the runtime thread calls observe/tick. Native notification callbacks may call
invalidate immediately; they never query the network or touch credentials.
"""

import ipaddress
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from enum import StrEnum

from campus_autoconnect.core.models import (
    AuthResult,
    AuthState,
    ErrorCode,
    NetworkProfile,
    NetworkSnapshot,
)
from campus_autoconnect.core.profiles import ProfileService
from campus_autoconnect.infrastructure.automation import AutomationStore
from campus_autoconnect.services.authentication import AuthenticationService


class AutomationState(StrEnum):
    STARTING = "STARTING"
    STOPPED = "STOPPED"
    DISABLED = "DISABLED"
    WAITING_NETWORK = "WAITING_NETWORK"
    WAITING_READY = "WAITING_READY"
    UNTRUSTED = "UNTRUSTED"
    SUSPENDED = "SUSPENDED"
    CHECKING = "CHECKING"
    CANCELLING = "CANCELLING"
    BACKOFF = "BACKOFF"
    ONLINE = "ONLINE"
    BLOCKED = "BLOCKED"


@dataclass(frozen=True)
class AutomationPolicy:
    retry_delays: tuple[float, ...] = (5.0, 15.0)
    settle_seconds: float = 2.0
    online_interval: float = 60.0
    snapshot_interval: float = 10.0

    def __post_init__(self) -> None:
        values = (
            *self.retry_delays,
            self.settle_seconds,
            self.online_interval,
            self.snapshot_interval,
        )
        if (
            len(self.retry_delays) > 2
            or any(not isinstance(v, (int, float)) or not 0 <= v <= 3600 for v in values)
            or self.online_interval == 0
            or self.snapshot_interval == 0
        ):
            raise ValueError("自动认证调度参数无效。")


_TRANSIENT = frozenset(
    {ErrorCode.NETWORK_UNREACHABLE, ErrorCode.DNS_ERROR, ErrorCode.TIMEOUT, ErrorCode.SERVER_ERROR}
)


def readiness(snapshot: NetworkSnapshot) -> tuple[AutomationState | None, ErrorCode]:
    if not snapshot.connected:
        return AutomationState.WAITING_NETWORK, ErrorCode.NETWORK_UNREACHABLE
    wifi = snapshot.wifi
    if wifi is None or not wifi.hardware or snapshot.warnings:
        return AutomationState.UNTRUSTED, ErrorCode.UNTRUSTED_NETWORK
    if any(
        a.connected and not a.hardware and (a.ipv4 or a.ipv6 or a.gateways)
        for a in snapshot.adapters
    ):
        return AutomationState.BLOCKED, ErrorCode.ROUTE_UNCONFIRMED
    try:
        addresses = [
            ipaddress.ip_address(value.split("%")[0]) for value in (*wifi.ipv4, *wifi.ipv6)
        ]
        usable = any(not (a.is_link_local or a.is_loopback or a.is_unspecified) for a in addresses)
        if not usable or not wifi.gateways:
            return AutomationState.WAITING_READY, ErrorCode.NETWORK_UNREACHABLE
    except ValueError:
        return AutomationState.WAITING_READY, ErrorCode.NETWORK_UNREACHABLE
    return None, ErrorCode.NONE


class AutomationCoordinator:
    def __init__(
        self,
        authentication: AuthenticationService,
        profiles: ProfileService,
        settings: AutomationStore,
        *,
        policy: AutomationPolicy | None = None,
        clock: Callable[[], float] = time.monotonic,
        record_result: Callable[[AuthResult], None] | None = None,
    ) -> None:
        self.authentication = authentication
        self.profiles = profiles
        self.settings = settings
        self.policy = policy if policy is not None else AutomationPolicy()
        self.clock = clock
        self.record_result = record_result
        self._lock = threading.RLock()
        self._revision = 0
        self._key: tuple | None = None
        self._network = NetworkSnapshot()
        self._profile: NetworkProfile | None = None
        self._eligible = False
        self._suspended = False
        self._stopping = False
        self._worker: threading.Thread | None = None
        self._cancel = threading.Event()
        self._completed: tuple[int, AuthResult] | None = None
        self._blocked: dict[NetworkProfile, ErrorCode] = {}
        self._attempt_counts: dict[NetworkProfile, int] = {}
        self._retry_due: dict[NetworkProfile, float] = {}
        self._due = 0.0
        self._settle_until = 0.0
        self.attempts = 0
        self.state = AutomationState.STOPPED
        self.code = ErrorCode.NONE
        self.last_result: AuthResult | None = None

    @property
    def working(self) -> bool:
        with self._lock:
            return self._worker is not None

    def begin(self) -> None:
        with self._lock:
            if self._stopping:
                raise ValueError("已停止的协调器不能复用，请创建新的后台实例。")
            self.state = AutomationState.STARTING

    def invalidate(self, event: str = "network") -> None:
        """Cancel before a subsequent snapshot, including switch-away-and-back events."""
        with self._lock:
            self._revision += 1
            self._cancel.set()
            self._settle_until = self.clock() + self.policy.settle_seconds
            if event == "suspend":
                self._suspended = True
            elif event == "resume":
                self._suspended = False
                self._due = max(self._settle_until, self._retry_due.get(self._profile, 0.0))
            if self._worker is not None:
                self.state = AutomationState.CANCELLING

    def fail(self, code: ErrorCode) -> None:
        with self._lock:
            self.invalidate()
            self._eligible = False
            self._key = None
            self.state, self.code = AutomationState.BLOCKED, code

    def observe(
        self, snapshot: NetworkSnapshot, profile: NetworkProfile | None, *, enabled: bool
    ) -> None:
        with self._lock:
            key = (snapshot.fingerprint, profile, enabled)
            changed = key != self._key
            if changed:
                self.invalidate()
                self._key = key
                self.attempts = self._attempt_counts.get(profile, 0)
                self._due = max(self._settle_until, self._retry_due.get(profile, 0.0))
            self._network, self._profile = snapshot, profile
            self._eligible = False
            if not enabled:
                self.state, self.code = AutomationState.DISABLED, ErrorCode.AUTOMATION_DISABLED
                self._cancel.set()
                return
            if self._suspended:
                self.state, self.code = AutomationState.SUSPENDED, ErrorCode.CANCELLED
                return
            state, code = readiness(snapshot)
            if state is not None:
                self.state, self.code = state, code
                self._cancel.set()
                return
            if profile is None or not profile.enabled or not profile.auto_auth:
                self.state, self.code = AutomationState.UNTRUSTED, ErrorCode.UNTRUSTED_NETWORK
                self._cancel.set()
                return
            self._eligible = not self._stopping
            if changed:
                self.state, self.code = AutomationState.WAITING_READY, ErrorCode.NONE

    def tick(self) -> None:
        with self._lock:
            now = self.clock()
            if self._worker is not None:
                if self._worker.is_alive():
                    return
                self._worker.join()
                self._worker = None
                completed, self._completed = self._completed, None
                if completed and completed[0] == self._revision and not self._cancel.is_set():
                    self._accept(completed[1], now)
            if self._stopping or not self._eligible or self._suspended:
                return
            if self._profile in self._blocked:
                self.state = AutomationState.BLOCKED
                self.code = self._blocked[self._profile]
                return
            if now < max(self._due, self._settle_until):
                return
            if self.attempts >= len(self.policy.retry_delays) + 1:
                self.state, self.code = AutomationState.BLOCKED, ErrorCode.CANCELLED
                if self._profile is not None:
                    self._blocked[self._profile] = self.code
                return
            self._launch()

    def _accept(self, result: AuthResult, now: float) -> None:
        self.last_result = result
        self.code = result.code
        if self.record_result is not None:
            self.record_result(result)
        if result.state == AuthState.AUTHENTICATED:
            self.state = AutomationState.ONLINE
            self.attempts = 0
            if self._profile is not None:
                self._attempt_counts[self._profile] = 0
                self._retry_due.pop(self._profile, None)
            self._due = now + self.policy.online_interval
        elif result.code == ErrorCode.BUSY:
            # Another process owns the shared operation lock. No authentication was attempted.
            self.attempts = max(0, self.attempts - 1)
            if self._profile is not None:
                self._attempt_counts[self._profile] = self.attempts
            self.state = AutomationState.BACKOFF
            self._due = now + self.policy.snapshot_interval
            if self._profile is not None:
                self._retry_due[self._profile] = self._due
        elif result.code in _TRANSIENT and self.attempts <= len(self.policy.retry_delays):
            self.state = AutomationState.BACKOFF
            self._due = now + self.policy.retry_delays[self.attempts - 1]
            if self._profile is not None:
                self._retry_due[self._profile] = self._due
        else:
            # Latches survive DHCP changes, reconnects, resume and global switch toggles.
            # Explicit profile edits or restarting the monitor allow a new bounded cycle.
            self.state = AutomationState.BLOCKED
            if self._profile is not None:
                self._blocked[self._profile] = result.code

    def _launch(self) -> None:
        revision, profile, snapshot = self._revision, self._profile, self._network
        cancel = threading.Event()
        self._cancel = cancel
        self.attempts += 1
        if profile is not None:
            self._attempt_counts[profile] = self.attempts
        self.state, self.code = AutomationState.CHECKING, ErrorCode.NONE

        def authorize(current: NetworkSnapshot, selected: NetworkProfile) -> bool:
            with self._lock:
                allowed = (
                    revision == self._revision
                    and not cancel.is_set()
                    and not self._stopping
                    and self._eligible
                    and selected == profile
                    and selected.auto_auth
                    and current.fingerprint == snapshot.fingerprint
                )
            # Re-read both disk authorizations immediately before reads/submission.
            return (
                allowed
                and self.settings.load().enabled
                and self.profiles.match(current.ssid) == profile
            )

        def work() -> None:
            try:
                result = self.authentication.login(cancel, authorize=authorize)
            except Exception:
                result = AuthResult(
                    AuthState.UNKNOWN, ErrorCode.UNKNOWN, "自动任务失败，已停止尝试。"
                )
            with self._lock:
                self._completed = (revision, result)

        self._worker = threading.Thread(target=work, name="campus-authentication", daemon=False)
        self._worker.start()

    def stop(self) -> None:
        with self._lock:
            self._stopping = True
            self._eligible = False
            self.invalidate()
            self.state, self.code = AutomationState.STOPPED, ErrorCode.CANCELLED

    def status(self) -> dict:
        with self._lock:
            return {
                "state": self.state.value,
                "error_code": self.code.value,
                "attempts": self.attempts,
                "max_attempts": len(self.policy.retry_delays) + 1,
                "retry_in_seconds": (
                    round(max(0, self._due - self.clock()), 1)
                    if self.state == AutomationState.BACKOFF
                    else None
                ),
                "operation_running": self._worker is not None,
                "last_auth_state": self.last_result.state.value if self.last_result else None,
                "last_authentication": self.last_result.progress.diagnostic()
                if self.last_result
                else None,
                "last_checked_at": self.last_result.checked_at if self.last_result else None,
            }
