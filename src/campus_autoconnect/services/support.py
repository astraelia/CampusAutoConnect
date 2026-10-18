"""Integrated monitoring: actual trace, explicit rechecks and install-local reports."""

import json
import sys
import threading
from dataclasses import asdict
from pathlib import Path

from campus_autoconnect import __version__
from campus_autoconnect.core.errors import CampusError
from campus_autoconnect.core.models import AuthResult, ErrorCode
from campus_autoconnect.infrastructure.report_maintenance import ReportMaintenance, ReportPolicy
from campus_autoconnect.infrastructure.reports import ReportSession
from campus_autoconnect.services.authentication import AuthenticationService
from campus_autoconnect.services.inspection import InspectionRunner
from campus_autoconnect.services.inspection_records import Report, Step, timestamp


class SupportService:
    def __init__(
        self,
        directory: Path,
        authentication: AuthenticationService,
        report_root: Path | None = None,
    ) -> None:
        self.directory = directory
        self.authentication = authentication
        self.session = ReportSession(report_root)
        self.maintenance = ReportMaintenance(self.session.root, directory / "report-policy.json")
        self.maintenance_status: dict | None = None
        self.maintenance_error = False
        self.report = Report()
        self._lock = threading.RLock()
        self._save_lock = threading.Lock()
        self.last_diagnostic: dict = {}
        self.capture_summary: dict | None = None
        self.save_error = False
        self.monitoring = False
        self.last_saved = False
        self._excluded_operations: set[str] = set()
        self._closed_operations: set[str] = set()

    def _renew_if_closed(self) -> None:
        with self._lock:
            if self.report.finished_at is not None:
                self.session.close()
                self.session = ReportSession(self.session.root)
                self.report = Report()
                self.capture_summary = None
                self.last_saved = False
                self._excluded_operations = set(self._closed_operations)

    def begin(self) -> None:
        self._renew_if_closed()
        with self._lock:
            session = self.session
        session.preflight()
        self.monitoring = True

    def add(self, step: Step) -> None:
        with self._lock:
            self.report.add(step)

    def inspect(self, cancel: threading.Event) -> dict:
        self.begin()
        from campus_autoconnect.services.inspection_records import Evidence, Outcome

        if getattr(sys, "frozen", False):
            from campus_autoconnect.infrastructure.reports import installation_directory
            from campus_autoconnect.services.package_inspection import command_step, inspect_target

            try:
                target = inspect_target(installation_directory() / "CampusAutoConnect.exe")
                self.add(
                    Step(
                        "package",
                        "当前软件包",
                        Outcome.WARNING if target.manifest_matches is False else Outcome.PASS,
                        "manifest_mismatch"
                        if target.manifest_matches is False
                        else "target_identified",
                        "校验只证明文件一致，不等于数字签名。",
                        Evidence.TOOL,
                        {
                            "target_version": target.version,
                            "exe_sha256": target.digest,
                            "manifest_matches": target.manifest_matches,
                        },
                    )
                )
                if not cancel.is_set():
                    self.add(command_step(target, "runtime", cancel))
            except (OSError, ValueError, TypeError):
                self.add(
                    Step(
                        "package",
                        "当前软件包",
                        Outcome.ERROR,
                        "package_unavailable",
                        "当前软件包无法完整核对；没有输出原始路径或异常。",
                        Evidence.TOOL,
                    )
                )
        run = max((step.run for step in self.report.steps), default=0) + 1
        runner = InspectionRunner(self.directory, self.add, run=run)
        runner.context()
        runner.inspect(cancel)
        self.save()
        return self.payload()

    def prepare(self, cancel: threading.Event) -> AuthResult:
        self.begin()
        result = self.authentication.prepare_check(cancel)
        self.last_diagnostic["deep_check"] = {
            "source": "explicit_credential_free_preparation",
            "state": result.state.value,
            "error_code": result.code.value,
            "authentication": result.progress.diagnostic(),
            "checked_at": result.checked_at,
        }
        self.save()
        return result

    def record(self, diagnostic: dict) -> None:
        self._renew_if_closed()
        with self._lock:
            deep = self.last_diagnostic.get("deep_check")
            self.last_diagnostic = dict(diagnostic)
            if deep is not None:
                self.last_diagnostic["deep_check"] = deep
        if self.monitoring:
            self.save()  # Only an explicitly started monitoring session persists each operation.

    def maintain_reports(self) -> dict | None:
        try:
            result = self.maintenance.due()
            if result is not None:
                self.maintenance_status = result
                self.maintenance_error = False
        except (OSError, CampusError, ValueError):
            from datetime import UTC, datetime

            self.maintenance_error = True
            self.maintenance.next_check = datetime.now(UTC) + self.maintenance.INTERVAL
        return self.maintenance_status

    def report_overview(self) -> dict:
        self.maintenance_status = self.maintenance.preview()
        self.maintenance_error = False
        return self.maintenance_status

    def save_report_policy(self, policy: ReportPolicy) -> dict:
        self.maintenance.store.save(policy)
        self.maintenance.next_check = None
        return self.report_overview()

    def preview_cleanup(self) -> dict:
        return self.maintenance.preview(include_legacy=True)

    def cleanup_reports(self, preview: dict) -> dict:
        self.maintenance_status = self.maintenance.cleanup(
            approved_legacy=tuple(preview["legacy_names"]),
            approved_candidates=tuple(preview["candidate_names"]),
        )
        self.maintenance_error = False
        return self.maintenance_status

    def protect_report(self, value: bool) -> dict:
        try:
            self.session.set_protected(value)
            if value and not self.save():
                raise CampusError(
                    ErrorCode.CONFIG_ERROR,
                    "保留标记已写入，但诊断报告保存失败；请重试保存，窗口结果仍可复制。",
                )
        finally:
            if self.report.finished_at is not None:
                self.session.close()
        return self.report_overview()

    def close(self) -> None:
        self.monitoring = False
        self.session.close()

    def payload(self) -> dict:
        with self._lock:
            return {
                "schema_version": 1,
                "version": __version__,
                "rules_version": __version__,
                "source": "integrated_support",
                "diagnostic": dict(self.last_diagnostic),
                "independent_summary": self.report.summary(),
                "independent_steps": [asdict(step) for step in self.report.steps],
                "actual_trace": [
                    e
                    for e in self.authentication.trace.snapshot()
                    if e["operation_id"] not in self._excluded_operations
                ],
                "trace_dropped": self.authentication.trace.dropped,
                "trace_unavailable": self.authentication.trace.unavailable,
                "capture_analysis": self.capture_summary,
                "report_save_failed": self.save_error,
                "evidence_boundary": (
                    "actual_trace 为本进程实际操作；independent_steps 为另一次无凭据复查；"
                    "浏览器抓包单独保存。服务器接受、已有联网和本次登录后验证分别判断。"
                ),
            }

    def text(self) -> str:
        payload = self.payload()
        lines = [
            "校园网连接助手 · 诊断与监测",
            "版本：" + __version__,
            payload["evidence_boundary"],
            self.report.text(),
            "主程序实际执行记录：",
        ]
        from campus_autoconnect.core.models import AUTH_STAGE_LABELS, AuthStage

        for item in payload["actual_trace"]:
            lines.append(
                f"{item['at']} [{item['kind']}] {AUTH_STAGE_LABELS[AuthStage(item['stage'])]} "
                f"{item['event']} {item['role']} {item['code']} ({item['elapsed_ms']} ms) "
                + json.dumps(item["facts"], ensure_ascii=False)
            )
        lines.extend(
            ("当前脱敏诊断：", json.dumps(payload["diagnostic"], ensure_ascii=False, indent=2))
        )
        if self.save_error:
            lines.append("报告保存失败；以上结果仍可复制。")
        return "\n".join(lines)

    def save(self) -> bool:
        with self._save_lock:
            try:
                # Reset before writing so a recovered report does not retain a stale failure.
                self.save_error = False
                self.session.write("diagnostic.json", self.payload())
                self.session.write("diagnostic.txt", self.text())
                self.last_saved = True
                return True
            except (OSError, CampusError, ValueError):
                self.save_error, self.last_saved = True, False
                return False

    def finish(self) -> bool:
        self.monitoring = False
        self.report.finished_at = timestamp()
        self._closed_operations = {e["operation_id"] for e in self.authentication.trace.snapshot()}
        try:
            return self.save()
        finally:
            self.session.close()
