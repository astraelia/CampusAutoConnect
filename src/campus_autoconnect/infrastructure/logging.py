"""Allowlisted event logs and a defensive formatter; no raw request logging."""

import hashlib
import logging
import re
from logging.handlers import RotatingFileHandler
from pathlib import Path

from campus_autoconnect.core.models import AuthResult, AuthStage
from campus_autoconnect.infrastructure.config import user_data_dir
from campus_autoconnect.infrastructure.locking import FileMutex

_SENSITIVE = re.compile(
    r"(?i)(?:password|passwd|pwd|username|account|cookie|token|authorization|secret|密码|账号)"
)
_URL = re.compile(r"https?://[^\s<>\"']+", re.IGNORECASE)
_IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


def redact(text: str, secrets: tuple[str, ...] = ()) -> str:
    for secret in sorted((s for s in secrets if s), key=len, reverse=True):
        text = text.replace(secret, "[已隐藏]")
    # A whole line is withheld when it names a sensitive field, including multiline headers.
    text = "\n".join(
        "[敏感行已隐藏]" if _SENSITIVE.search(line) else line for line in text.splitlines()
    )
    text = _URL.sub("[URL 已隐藏]", text)
    return _IPV4.sub("[IP 已隐藏]", text)


class SafeFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        # No traceback rendering: exception chains can contain arbitrary request content.
        message = redact(record.getMessage())
        return f"{self.formatTime(record)} {record.levelname} {message}"


class SafeRotatingHandler(RotatingFileHandler):
    """Serialize rotations across GUI/CLI/monitor, and never render logging failures."""

    failed = False

    def emit(self, record: logging.LogRecord) -> None:
        mutex = FileMutex(Path(self.baseFilename).with_suffix(".log.lock"))
        try:
            if not mutex.acquire():
                self.failed = True
                return
            try:
                super().emit(record)
            finally:
                # No idle open stream in another process may prevent Windows renames.
                if self.stream is not None:
                    self.stream.close()
                    self.stream = None
        except Exception:
            self.failed = True
        finally:
            mutex.release()

    def handleError(self, record: logging.LogRecord) -> None:
        self.failed = True


def setup_logging(directory: Path | None = None) -> logging.Logger:
    target = directory if directory is not None else user_data_dir() / "logs"
    identity = hashlib.sha256(str(target.resolve()).encode("utf-8")).hexdigest()[:16]
    logger = logging.getLogger("campus_autoconnect.events." + identity)
    logger.setLevel(logging.INFO)
    logger.propagate = False
    if not logger.handlers:
        target.mkdir(parents=True, exist_ok=True)
        handler = SafeRotatingHandler(
            target / "campus.log", maxBytes=128 * 1024, backupCount=2, encoding="utf-8", delay=True
        )
        handler.setFormatter(SafeFormatter())
        logger.addHandler(handler)
    return logger


def log_result(logger: logging.Logger, result: AuthResult) -> None:
    # Log only enum values; no user/server supplied strings or network identifiers.
    logger.info("operation state=%s code=%s", result.state.value, result.code.value)


STARTUP_STAGES = frozenset({"desktop_ready", "background_started", "network_ready", "online"})


def log_startup_timing(logger: logging.Logger | None, stage: str, elapsed: float) -> None:
    if logger is not None and stage in STARTUP_STAGES:
        milliseconds = min(86400000, max(0, round(elapsed * 1000)))
        logger.info("startup stage=%s elapsed_ms=%d", stage, milliseconds)


def log_operation_timing(logger: logging.Logger, events: list[dict]) -> None:
    """One scalar-only summary; never print arbitrary trace dictionaries."""
    if not events or events[-1]["event"] != "result":
        return
    latest = events[-1]["operation_id"]
    events = [item for item in events if item["operation_id"] == latest]
    kind = events[-1]["kind"]
    if kind not in {"check", "login", "preparation"}:
        return
    stages = [item for item in events if item["event"] in {"stage", "result"}]
    totals = dict.fromkeys(AuthStage, 0)
    for before, after in zip(stages, stages[1:], strict=False):
        totals[AuthStage(before["stage"])] += max(0, after["elapsed_ms"] - before["elapsed_ms"])
    values = [
        events[-1]["elapsed_ms"],
        *(
            totals[stage]
            for stage in (
                AuthStage.NETWORK,
                AuthStage.CONNECTIVITY,
                AuthStage.PREPARE,
                AuthStage.SUBMIT,
                AuthStage.VERIFY,
            )
        ),
    ]
    values = [min(86400000, max(0, int(value))) for value in values]
    logger.info(
        "timing kind=%s total_ms=%d network_ms=%d connectivity_ms=%d "
        "prepare_ms=%d submit_ms=%d verify_ms=%d",
        kind,
        *values,
    )
