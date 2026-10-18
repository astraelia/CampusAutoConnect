"""Safe error messages are fixed strings, never remote response bodies."""

from campus_autoconnect.core.models import ErrorCode


class CampusError(Exception):
    def __init__(self, code: ErrorCode, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
