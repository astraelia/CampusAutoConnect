"""Bounded report retention, with explicit legacy adoption and no recursive deletion."""

import json
import re
from dataclasses import asdict, dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path

from campus_autoconnect.core.errors import CampusError
from campus_autoconnect.core.models import ErrorCode
from campus_autoconnect.infrastructure.config import ConfigStore
from campus_autoconnect.infrastructure.files import read_text_shared
from campus_autoconnect.infrastructure.locking import FileMutex
from campus_autoconnect.infrastructure.reports import (
    REPORT_FILES,
    SESSION_LOCK,
    SESSION_META,
    check_report_root,
    plain_path,
)

_SESSION = re.compile(r"\d{8}_\d{6}_[a-f0-9]{12}")
_FILES = (
    REPORT_FILES
    | {SESSION_META, SESSION_LOCK}
    | {name + ".io.lock" for name in REPORT_FILES | {SESSION_META}}
)


@dataclass(frozen=True)
class ReportPolicy:
    enabled: bool = True
    days: int = 7
    max_sessions: int = 20
    max_bytes: int = 50 * 1024 * 1024
    include_capture: bool = False


class ReportPolicyStore:
    def __init__(self, path: Path) -> None:
        self.path = path

    @staticmethod
    def validate(raw: object) -> ReportPolicy:
        if not isinstance(raw, dict) or set(raw) != {"schema_version", *asdict(ReportPolicy())}:
            raise ValueError
        if type(raw["schema_version"]) is not int or raw["schema_version"] != 1:
            raise ValueError
        for key in ("enabled", "include_capture"):
            if type(raw[key]) is not bool:
                raise ValueError
        for key, low, high in (
            ("days", 1, 365),
            ("max_sessions", 1, 1000),
            ("max_bytes", 1024 * 1024, 1024 * 1024 * 1024),
        ):
            if type(raw[key]) is not int or not low <= raw[key] <= high:
                raise ValueError
        return ReportPolicy(**{key: raw[key] for key in asdict(ReportPolicy())})

    def load(self) -> ReportPolicy:
        try:
            return self.validate(json.loads(read_text_shared(self.path, 4096)))
        except FileNotFoundError:
            return ReportPolicy()
        except (OSError, ValueError, TypeError, RecursionError) as exc:
            raise CampusError(ErrorCode.CONFIG_ERROR, "报告清理设置无效，未执行自动删除。") from exc

    def save(self, policy: ReportPolicy) -> None:
        raw = {"schema_version": 1, **asdict(policy)}
        self.validate(raw)
        with FileMutex(self.path.with_suffix(".json.lock"), timeout=1):
            ConfigStore._atomic_write(self.path, json.dumps(raw) + "\n")


@dataclass(frozen=True)
class _Session:
    path: Path
    modified: float
    size: int
    legacy: bool
    protected: bool
    capture: bool


class ReportMaintenance:
    INTERVAL = timedelta(hours=24)

    def __init__(self, root: Path, policy_path: Path) -> None:
        self.root = root.absolute()
        self.store = ReportPolicyStore(policy_path)
        self.next_check: datetime | None = None
        self.last_result: dict | None = None

    def _scan(self) -> tuple[list[_Session], int]:
        sessions, skipped = [], 0
        for path in self.root.iterdir():
            if not _SESSION.fullmatch(path.name):
                continue
            if not plain_path(path) or not path.is_dir():
                skipped += 1
                continue
            children = list(path.iterdir())
            if any(not plain_path(p) or not p.is_file() or p.name not in _FILES for p in children):
                skipped += 1
                continue
            meta = path / SESSION_META
            legacy, protected = not meta.exists(), False
            if not legacy:
                try:
                    raw = (
                        json.loads(meta.read_text(encoding="utf-8"))
                        if meta.stat().st_size <= 4096
                        else {}
                    )
                    if (
                        not isinstance(raw, dict)
                        or set(raw) != {"schema_version", "source", "created_at", "protected"}
                        or type(raw.get("schema_version")) is not int
                        or raw["schema_version"] != 1
                        or raw.get("source") != "CampusAutoConnect"
                        or type(raw.get("protected")) is not bool
                    ):
                        raise ValueError
                    protected = raw["protected"]
                except (OSError, ValueError, AttributeError, RecursionError):
                    skipped += 1
                    continue
            content = [p for p in children if p.name in REPORT_FILES]
            sessions.append(
                _Session(
                    path,
                    max((p.stat().st_mtime for p in content), default=path.stat().st_mtime),
                    sum(p.stat().st_size for p in children),
                    legacy,
                    protected,
                    any(p.name.startswith("PortalCapture_") for p in content),
                )
            )
        return sessions, skipped

    def _plan(self, policy: ReportPolicy, now: datetime, include_legacy: bool) -> dict:
        sessions, skipped = self._scan()
        eligible, active = [], 0
        for session in sessions:
            if session.protected or (session.capture and not policy.include_capture):
                continue
            if session.legacy and not include_legacy:
                continue
            mutex = FileMutex(session.path / SESSION_LOCK)
            if not mutex.acquire():
                active += 1
                continue
            mutex.release()
            eligible.append(session)
        eligible.sort(key=lambda s: (s.modified, s.path.name))
        remaining_count, remaining_size = len(eligible), sum(s.size for s in eligible)
        selected = []
        cutoff = (now - timedelta(days=policy.days)).timestamp()
        for session in eligible:
            if (
                session.modified < cutoff
                or remaining_count > policy.max_sessions
                or remaining_size > policy.max_bytes
            ):
                selected.append(session)
                remaining_count -= 1
                remaining_size -= session.size
        return {
            "sessions": sessions,
            "selected": selected,
            "skipped": skipped,
            "active": active,
        }

    def preview(self, *, include_legacy: bool = False, now: datetime | None = None) -> dict:
        now = now or datetime.now(UTC)
        policy = self.store.load()
        check_report_root(self.root)
        with FileMutex(self.root / ".reports.lock", timeout=1):
            plan = self._plan(policy, now, include_legacy)
            return self._summary(plan, policy)

    def _summary(self, plan: dict, policy: ReportPolicy) -> dict:
        return {
            "policy": asdict(policy),
            "session_count": len(plan["sessions"]),
            "total_bytes": sum(s.size for s in plan["sessions"]),
            "legacy_count": sum(s.legacy for s in plan["sessions"]),
            "protected_count": sum(s.protected for s in plan["sessions"]),
            "capture_count": sum(s.capture for s in plan["sessions"]),
            "candidate_count": len(plan["selected"]),
            "candidate_bytes": sum(s.size for s in plan["selected"]),
            "candidate_names": [s.path.name for s in plan["selected"]],
            "legacy_names": [s.path.name for s in plan["sessions"] if s.legacy],
            "skipped": plan["skipped"],
            "active": plan["active"],
            "next_check_at": self.next_check.isoformat() if self.next_check else None,
            "last_result": self.last_result,
        }

    def cleanup(
        self,
        *,
        approved_legacy: tuple[str, ...] = (),
        approved_candidates: tuple[str, ...] | None = None,
        now: datetime | None = None,
    ) -> dict:
        """Only legacy names returned by a displayed preview may be explicitly approved."""
        now = now or datetime.now(UTC)
        policy = self.store.load()
        if any(not _SESSION.fullmatch(name) for name in approved_legacy):
            raise ValueError("旧报告批准范围无效。")
        check_report_root(self.root)
        deleted, failed, adopted = 0, 0, 0
        with FileMutex(self.root / ".reports.lock", timeout=1):
            for session in self._scan()[0]:
                if not session.legacy or session.path.name not in approved_legacy:
                    continue
                mutex = FileMutex(session.path / SESSION_LOCK)
                if not mutex.acquire():
                    continue
                try:
                    ConfigStore._atomic_write(
                        session.path / SESSION_META,
                        json.dumps(
                            {
                                "schema_version": 1,
                                "source": "CampusAutoConnect",
                                "created_at": datetime.fromtimestamp(
                                    session.modified, UTC
                                ).isoformat(),
                                "protected": False,
                            }
                        )
                        + "\n",
                    )
                    adopted += 1
                except OSError:
                    failed += 1
                finally:
                    mutex.release()
            plan = self._plan(policy, now, False)
            for session in plan["selected"]:
                if approved_candidates is not None and session.path.name not in approved_candidates:
                    continue
                mutex = FileMutex(session.path / SESSION_LOCK)
                if not mutex.acquire():
                    continue
                try:
                    # Recheck all boundaries immediately before touching any file.
                    if (
                        not plain_path(session.path)
                        or session.path.resolve().parent != self.root.resolve()
                    ):
                        failed += 1
                        continue
                    children = list(session.path.iterdir())
                    if any(
                        not plain_path(p) or not p.is_file() or p.name not in _FILES
                        for p in children
                    ):
                        failed += 1
                        continue
                    for path in children:
                        if path.name not in {SESSION_LOCK, SESSION_META, SESSION_META + ".io.lock"}:
                            path.unlink()
                    for name in (SESSION_META, SESSION_META + ".io.lock"):
                        (session.path / name).unlink(missing_ok=True)
                except OSError:
                    failed += 1
                    continue
                finally:
                    mutex.release()
                try:
                    (session.path / SESSION_LOCK).unlink()
                    session.path.rmdir()
                    deleted += 1
                except OSError:
                    failed += 1
            self.last_result = {
                "at": now.isoformat(),
                "deleted": deleted,
                "failed": failed,
                "adopted": adopted,
            }
            self.next_check = now + self.INTERVAL
            return self._summary(self._plan(policy, now, False), policy)

    def due(self, *, now: datetime | None = None) -> dict | None:
        now = now or datetime.now(UTC)
        if self.next_check is not None and now < self.next_check:
            return None
        policy = self.store.load()
        if policy.enabled:
            return self.cleanup(now=now)
        self.next_check = now + self.INTERVAL
        return self.preview(now=now)
