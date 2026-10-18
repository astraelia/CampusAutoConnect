"""Structured reports: only fixed messages and explicitly projected facts enter logs."""

import json
import os
import re
import tempfile
import uuid
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime, timedelta, timezone
from enum import StrEnum
from pathlib import Path

from campus_autoconnect import __version__


def timestamp() -> str:
    return datetime.now(UTC).astimezone(timezone(timedelta(hours=8))).isoformat(timespec="seconds")


def exception_type(error: BaseException) -> str:
    name = type(error).__name__
    return name if re.fullmatch(r"[A-Za-z_][A-Za-z_0-9]{0,79}", name) else "Exception"


class Outcome(StrEnum):
    PASS = "通过"
    INFO = "说明"
    WARNING = "需注意"
    BLOCKED = "阻塞"
    ERROR = "失败"
    SKIPPED = "未执行"


class Evidence(StrEnum):
    TOOL = "监测工具"
    RECHECK = "独立复查"
    EXE = "EXE公开接口"
    SHARED_LOG = "主程序共享事件日志"


Fact = bool | int | float | str | None


@dataclass(frozen=True)
class Step:
    key: str
    title: str
    outcome: Outcome
    code: str
    detail: str
    evidence: Evidence = Evidence.RECHECK
    facts: dict[str, Fact] = field(default_factory=dict)
    elapsed_ms: int = 0
    run: int = 0
    at: str = field(default_factory=timestamp)


@dataclass
class Report:
    session_id: str = field(default_factory=lambda: uuid.uuid4().hex)
    started_at: str = field(default_factory=timestamp)
    finished_at: str | None = None
    steps: list[Step] = field(default_factory=list)
    dropped_steps: int = 0

    def add(self, step: Step) -> None:
        self.steps.append(step)
        if len(self.steps) > 800:
            del self.steps[0]
            self.dropped_steps += 1

    def summary(self) -> str:
        runs = [step.run for step in self.steps if step.evidence == Evidence.RECHECK]
        latest = max(runs, default=0)
        checks = [s for s in self.steps if s.run == latest and s.evidence == Evidence.RECHECK]
        failures = [s for s in checks if s.outcome in {Outcome.ERROR, Outcome.BLOCKED}]
        if failures:
            first = failures[0]
            return f"最近一次独立复查停在「{first.title}」：{first.detail}"
        if any(s.key == "internet" and s.code == "already_authenticated" for s in checks):
            return "最近一次复查确认互联网可用；本工具未发起校园网登录。"
        return "尚无完整联网结论；请查看各环节及其证据来源。"

    def payload(self) -> dict:
        return {
            "schema_version": 1,
            "tool_version": __version__,
            "session_id": self.session_id,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "summary": self.summary(),
            "tool_credential_reads": 0,
            "tool_login_submissions": 0,
            "privacy": "SSID/account/IP/host/profile/URL/body/process-path are withheld",
            "evidence_boundary": (
                "独立复查不等于EXE内部轨迹；共享日志不能归属于某个PID或某次点击；"
                "EXE诊断接口执行的是另一次检测。"
            ),
            "dropped_steps": self.dropped_steps,
            "steps": [asdict(step) for step in self.steps],
        }

    def text(self) -> str:
        lines = [
            f"校园网软件检测 {__version__}",
            f"开始：{self.started_at}",
            f"结束：{self.finished_at or '监测中/检查中'}",
            self.summary(),
            "",
            "本工具不读取认证凭据、不提交校园网登录。",
            "独立复查、EXE公开结果和共享日志分别标注，不能互相替代。",
            "共享日志无法确认具体进程或操作来源；EXE接口结果来自另一次检测。",
            "网络标识、响应体及本机程序路径均已隐藏。",
            "",
        ]
        for step in self.steps:
            lines.append(
                f"{step.at} [{step.evidence}] 第{step.run}轮 {step.title} "
                f"— {step.outcome} [{step.code}] ({step.elapsed_ms} ms)"
            )
            lines.append(step.detail)
            if step.facts:
                lines.append(json.dumps(step.facts, ensure_ascii=False, sort_keys=True))
            lines.append("")
        if self.dropped_steps:
            lines.append(f"较早记录已限量移除：{self.dropped_steps} 条。")
        return "\n".join(lines) + "\n"


class ReportWriter:
    def __init__(self, root: Path, report: Report) -> None:
        self.directory = root / (report.started_at[:10] + "_" + report.session_id[:12])

    @staticmethod
    def _write(path: Path, content: str) -> None:
        temporary: Path | None = None
        try:
            with tempfile.NamedTemporaryFile(
                mode="w", encoding="utf-8-sig", dir=path.parent, prefix=".report-", delete=False
            ) as stream:
                temporary = Path(stream.name)
                stream.write(content)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, path)
        finally:
            if temporary is not None:
                temporary.unlink(missing_ok=True)

    def save(self, report: Report) -> None:
        self.directory.mkdir(parents=True, exist_ok=True)
        self._write(
            self.directory / "report.json",
            json.dumps(report.payload(), ensure_ascii=False, indent=2) + "\n",
        )
        self._write(self.directory / "report.txt", report.text())
