"""Protocol boundary; constructing an adapter must never perform network I/O."""

from collections.abc import Callable
from dataclasses import dataclass
from typing import Protocol

from campus_autoconnect.core.models import (
    AuthState,
    ConnectivityResult,
    Credentials,
    ErrorCode,
    NetworkProfile,
    NetworkSnapshot,
)


@dataclass(frozen=True)
class AdapterDetection:
    recognized: bool
    code: ErrorCode = ErrorCode.NONE
    message: str = ""
    target_url: str | None = None


@dataclass(frozen=True)
class AdapterReply:
    accepted: bool
    code: ErrorCode = ErrorCode.NONE
    message: str = ""


class PortalAdapter(Protocol):
    def detect(self, profile: NetworkProfile, result: ConnectivityResult) -> AdapterDetection: ...
    def prepare(
        self, profile: NetworkProfile, network: NetworkSnapshot, guard: Callable[[str], None]
    ) -> None: ...
    def authenticate(self, target_url: str, credentials: Credentials) -> AdapterReply: ...
    def verify(self, result: ConnectivityResult) -> bool: ...
    def get_status(self) -> AuthState: ...
