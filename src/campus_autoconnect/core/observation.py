"""Bounded, non-throwing observations. URLs, headers, values and bodies never enter here."""

import threading
import time
import uuid
from contextvars import ContextVar, Token
from datetime import UTC, datetime

from campus_autoconnect.core.models import AuthStage, AuthState, ErrorCode

_ACTIVE: ContextVar[tuple | None] = ContextVar("campus_observation", default=None)
_FACTS = {
    "http_status",
    "expected",
    "redirect_observed",
    "accepted",
    "online",
    "https",
    "zero_mac_observed",
    "zero_vlan_observed",
    "live_config_supported",
    "account_suffix_present",
    "account_normalized",
    "adapter_count",
    "active_virtual_gateway",
}
_EVENTS = {"stage", "result", "http_start", "http_response", "http_error", "protocol"}
_ROLES = {"probe", "page", "config", "login", "none"}


class OperationTrace:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._events: list[dict] = []
        self.dropped = 0
        self.unavailable = False

    def begin(self, kind: str) -> Token | None:
        try:
            if kind not in {"check", "login", "preparation"}:
                raise ValueError
            return _ACTIVE.set(
                (self, uuid.uuid4().hex, kind, time.monotonic(), AuthStage.NOT_STARTED)
            )
        except Exception:
            self.unavailable = True
            return None

    def end(self, token: Token | None) -> None:
        if token is not None:
            _ACTIVE.reset(token)

    def record(self, event: dict) -> None:
        with self._lock:
            self._events.append(event)
            if len(self._events) > 800:
                self._events.pop(0)
                self.dropped += 1

    def snapshot(self) -> list[dict]:
        with self._lock:
            return [{**event, "facts": dict(event["facts"])} for event in self._events]


def observe(
    event: str,
    *,
    stage: AuthStage | None = None,
    role: str = "none",
    code: ErrorCode = ErrorCode.NONE,
    state: AuthState = AuthState.UNKNOWN,
    **facts: bool | int | None,
) -> None:
    active = _ACTIVE.get()
    if active is None:
        return
    recorder, operation, kind, started, current_stage = active
    try:
        stage = current_stage if stage is None else stage
        if event not in _EVENTS or role not in _ROLES:
            raise ValueError
        if event == "stage":
            _ACTIVE.set((recorder, operation, kind, started, AuthStage(stage)))
        safe = {}
        for key, value in facts.items():
            if key not in _FACTS or not (
                type(value) is bool
                or value is None
                or (type(value) is int and 0 <= value <= 100000)
            ):
                raise ValueError
            safe[key] = value
        recorder.record(
            {
                "source": "actual_application",
                "operation_id": operation,
                "kind": kind,
                "at": datetime.now(UTC).isoformat(),
                "elapsed_ms": max(0, round((time.monotonic() - started) * 1000)),
                "event": event,
                "stage": AuthStage(stage).value,
                "role": role,
                "code": ErrorCode(code).value,
                "state": AuthState(state).value,
                "facts": safe,
            }
        )
    except Exception:
        recorder.unavailable = True  # Observer failure cannot change authentication.
