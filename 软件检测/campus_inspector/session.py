"""Session orchestration and read-only, allowlisted observation of shared app logs."""

import queue
import re
import threading
from collections.abc import Callable
from contextlib import suppress
from datetime import datetime
from pathlib import Path

from campus_autoconnect.core.models import AuthState, ErrorCode
from campus_autoconnect.services.automation import AutomationState
from campus_inspector.checks import InspectionRunner
from campus_inspector.processes import LaunchObserver, command_step, inspect_target
from campus_inspector.records import (
    Evidence,
    Outcome,
    Report,
    ReportWriter,
    Step,
    exception_type,
    timestamp,
)

LINE = re.compile(
    r"(?P<time>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2},\d{3}) INFO "
    r"(?P<kind>operation|automation) state=(?P<state>[A-Z_]+) code=(?P<code>[a-z_]+)"
    r"(?: attempt=(?P<attempt>[0-3]) runtime_error=(?P<runtime>[a-z_]+))?"
)


def safe_log_events(path: Path) -> list[tuple[str, dict]]:
    try:
        with path.open("rb") as stream:
            stream.seek(0, 2)
            size = stream.tell()
            stream.seek(max(0, size - 32768))
            content = stream.read(32768).decode("utf-8", errors="replace")
    except FileNotFoundError:
        return []
    result = []
    for line in content.splitlines()[-200:]:
        match = LINE.fullmatch(line)
        if match is None:
            continue
        raw = match.groupdict()
        try:
            at = datetime.strptime(raw["time"], "%Y-%m-%d %H:%M:%S,%f").isoformat()
            ErrorCode(raw["code"])
            if raw["kind"] == "operation":
                AuthState(raw["state"])
                if raw["attempt"] is not None:
                    continue
            else:
                AutomationState(raw["state"])
                ErrorCode(raw["runtime"])
                if raw["attempt"] is None:
                    continue
        except (ValueError, TypeError):
            continue
        facts = {
            "app_log_time": at,
            "event_kind": raw["kind"],
            "state": raw["state"],
            "error_code": raw["code"],
        }
        if raw["attempt"] is not None:
            facts.update(attempt=int(raw["attempt"]), runtime_error=raw["runtime"])
        result.append((line, facts))
    return result


class Session:
    def __init__(
        self,
        directory: Path,
        emit: Callable[[Step], None],
        *,
        runner_factory: Callable = InspectionRunner,
    ) -> None:
        self.directory = directory
        self.emit = emit
        self.report = Report()
        self.writer = ReportWriter(directory / "diagnostics", self.report)
        self.runner_factory = runner_factory
        self.recheck_requested = threading.Event()
        self.exe_requested = threading.Event()
        self.markers: queue.Queue[str] = queue.Queue(maxsize=64)
        self.launcher = LaunchObserver()
        self.seen: set[str] = set()
        self.run_number = 0
        self.save_failed = False

    def mark(self) -> None:
        with suppress(queue.Full):
            self.markers.put_nowait(timestamp())

    def add(self, step: Step) -> None:
        self.report.add(step)
        self.emit(step)
        self.save()

    def save(self) -> None:
        try:
            self.writer.save(self.report)
        except OSError:
            if not self.save_failed:
                self.save_failed = True
                step = Step(
                    "report_save",
                    "保存报告",
                    Outcome.ERROR,
                    "report_write_failed",
                    "无法写入诊断目录；结果仍保留在窗口，结束后可复制。",
                    Evidence.TOOL,
                )
                self.report.add(step)
                self.emit(step)

    def observe_logs(self, *, baseline: bool = False) -> None:
        try:
            events = safe_log_events(self.directory / "logs" / "campus.log")
            for identity, facts in events:
                if identity not in self.seen and not baseline:
                    self.add(
                        Step(
                            "app_event",
                            "观察到主程序事件",
                            Outcome.INFO,
                            facts["error_code"],
                            "来自同一用户目录的共享日志，无法归属于指定 PID 或某次点击。",
                            Evidence.SHARED_LOG,
                            facts,
                        )
                    )
            self.seen.update(identity for identity, _ in events)
            if len(self.seen) > 1200:
                self.seen = {identity for identity, _ in events}
        except OSError:
            self.add(
                Step(
                    "app_log",
                    "读取主程序事件",
                    Outcome.WARNING,
                    "log_unavailable",
                    "当前无法读取事件文件；不会输出原始文件或异常内容。",
                    Evidence.TOOL,
                )
            )

    def recheck(self, cancel: threading.Event, *, context: bool = False) -> None:
        self.run_number += 1
        runner = self.runner_factory(self.directory, self.add, run=self.run_number)
        if context:
            runner.context()
        runner.inspect(cancel)

    def execute(self, path: Path | None, cancel: threading.Event, *, monitor: bool) -> Report:
        target = None
        self.add(
            Step(
                "session",
                "开始检测",
                Outcome.INFO,
                "session_started",
                "监测工具不改变源代码、网络档案、自动开关或登录任务。",
                Evidence.TOOL,
            )
        )
        try:
            self.observe_logs(baseline=True)
            if path is not None:
                try:
                    target = inspect_target(path)
                    self.add(
                        Step(
                            "target",
                            "选定软件包",
                            Outcome.WARNING if target.manifest_matches is False else Outcome.PASS,
                            "manifest_mismatch"
                            if target.manifest_matches is False
                            else "target_identified",
                            "已核对程序摘要；校验清单只证明文件一致，不等于数字签名。",
                            Evidence.TOOL,
                            {
                                "exe_sha256": target.digest,
                                "target_version": target.version,
                                "manifest_matches": target.manifest_matches,
                                "cli_present": target.cli is not None,
                            },
                        )
                    )
                    if not cancel.is_set():
                        self.add(command_step(target, "runtime", cancel))
                except (OSError, ValueError, TypeError):
                    self.add(
                        Step(
                            "target",
                            "选定软件包",
                            Outcome.ERROR,
                            "invalid_target_exe",
                            "请选择完整解压目录中的 CampusAutoConnect.exe。",
                            Evidence.TOOL,
                        )
                    )
            else:
                self.add(
                    Step(
                        "target",
                        "选定软件包",
                        Outcome.SKIPPED,
                        "target_not_selected",
                        "没有选定 EXE，仍可做独立网络复查。",
                        Evidence.TOOL,
                    )
                )
            if cancel.is_set():
                return self.report
            self.recheck(cancel, context=True)
            if monitor and not cancel.is_set():
                if target is None:
                    self.add(
                        Step(
                            "launch",
                            "启动原软件",
                            Outcome.SKIPPED,
                            "target_not_selected",
                            "未选定有效 EXE，监测未启动。",
                            Evidence.TOOL,
                        )
                    )
                    return self.report
                launch = self.launcher.launch(target)
                self.add(launch)
                if launch.outcome != Outcome.PASS:
                    return self.report
                self.add(
                    Step(
                        "monitor",
                        "监测已就绪",
                        Outcome.INFO,
                        "monitor_ready",
                        "现在可在原软件中操作；可标记时间、再次复查或采集 EXE 新一次检测。",
                        Evidence.TOOL,
                    )
                )
                while not cancel.wait(0.5):
                    if event := self.launcher.poll():
                        self.add(event)
                    self.observe_logs()
                    while not self.markers.empty():
                        marked_at = self.markers.get_nowait()
                        self.add(
                            Step(
                                "marker",
                                "用户操作时间标记",
                                Outcome.INFO,
                                "user_marker",
                                "用户标记了此时刻；标记不证明原软件执行了哪一项操作。",
                                Evidence.TOOL,
                                at=marked_at,
                            )
                        )
                    if self.recheck_requested.is_set():
                        self.recheck_requested.clear()
                        self.recheck(cancel)
                    if self.exe_requested.is_set() and not cancel.is_set():
                        self.exe_requested.clear()
                        self.add(command_step(target, "diagnose", cancel))
            self.observe_logs()
        except Exception as exc:
            self.add(
                Step(
                    "session_error",
                    "监测会话",
                    Outcome.ERROR,
                    "unexpected_error",
                    "会话发生未预期错误；原始异常内容未输出。",
                    Evidence.TOOL,
                    {"exception_type": exception_type(exc)},
                )
            )
        finally:
            if monitor and self.launcher.process is not None:
                self.add(
                    Step(
                        "monitor_end",
                        "停止监测",
                        Outcome.INFO,
                        "monitor_stopped",
                        "只停止本工具的观测，没有终止原软件或其后台进程。",
                        Evidence.TOOL,
                    )
                )
            self.report.finished_at = timestamp()
            self.save()
        return self.report
