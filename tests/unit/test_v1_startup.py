import json
from types import SimpleNamespace

import pytest

from campus_autoconnect import entry
from campus_autoconnect.core.errors import CampusError
from campus_autoconnect.core.models import ErrorCode
from campus_autoconnect.infrastructure import lifecycle
from campus_autoconnect.infrastructure.automation import AutomationStore
from campus_autoconnect.infrastructure.launch import (
    FROZEN_STARTUP_ARGUMENTS,
    SOURCE_STARTUP_ARGUMENTS,
    LaunchCommand,
    startup_command,
)
from campus_autoconnect.infrastructure.reports import ReportSession
from campus_autoconnect.infrastructure.startup import WindowsStartupService
from campus_autoconnect.services.automation_application import AutomationService

pytestmark = pytest.mark.mock


def test_login_dispatch_opens_desktop_in_startup_mode_only(monkeypatch):
    calls = []
    monkeypatch.setattr("campus_autoconnect.ui.app.main", lambda **kw: calls.append(kw) or 0)
    assert entry._dispatch(["--startup"]) == 0
    assert calls == [{"startup": True}]
    assert entry._dispatch(["--startup", "login"]) == 2
    assert len(calls) == 1


@pytest.mark.parametrize("frozen", [True, False])
def test_startup_command_is_distinct_from_background_and_has_fixed_arguments(
    tmp_path, monkeypatch, frozen
):
    import sys

    executable = tmp_path / ("CampusAutoConnect.exe" if frozen else "pythonw.exe")
    executable.touch()
    monkeypatch.setattr(sys, "frozen", frozen, raising=False)
    monkeypatch.setattr(sys, "executable", str(executable))
    command = startup_command()
    assert command.arguments == (FROZEN_STARTUP_ARGUMENTS if frozen else SOURCE_STARTUP_ARGUMENTS)
    assert command.argv() == [str(executable), *command.arguments]
    with pytest.raises(CampusError):
        LaunchCommand(executable, ("--startup", "--cli", "login")).validate()


@pytest.mark.parametrize("state", ["BLOCKED", "DISABLED", "CHECKING"])
def test_login_adopts_live_monitor_and_preserves_settings_and_safety_state(tmp_path, state):
    settings = AutomationStore(tmp_path / "automation.json")
    status = {"running": True, "state": state, "attempts": 3}
    service = AutomationService(settings, SimpleNamespace(status=lambda: status), None, None)
    service.start_background = lambda: pytest.fail("must not restart a live monitor")
    service.ensure_background()
    assert status == {"running": True, "state": state, "attempts": 3}
    assert not settings.path.exists()


def test_login_starts_missing_monitor_without_enabling_authentication(tmp_path):
    settings = AutomationStore(tmp_path / "automation.json")
    service = AutomationService(
        settings, SimpleNamespace(status=lambda: {"running": False}), None, None
    )
    calls = []
    service.start_background = lambda: calls.append(True)
    service.ensure_background()
    assert calls == [True] and not settings.path.exists()


def test_login_duplicate_race_only_accepts_a_confirmed_live_monitor(tmp_path):
    states = iter([{"running": False}, {"running": True}])
    service = AutomationService(None, SimpleNamespace(status=lambda: next(states)), None, None)

    def busy():
        raise CampusError(ErrorCode.BUSY, "后台已在运行。")

    service.start_background = busy
    service.ensure_background()


def test_startup_runtime_projection_validates_types_and_hides_untrusted_details(tmp_path):
    executable = tmp_path / "CampusAutoConnect.exe"
    executable.touch()
    raw = dict(
        installed=True,
        owned=True,
        configured=True,
        enabled=True,
        running=True,
        executable_exists=True,
        last_run_at="2026-10-18T04:10:42+00:00",
        last_result="0x00041301",
    )
    calls = []

    def runner(script, payload):
        calls.append(json.loads(payload))
        assert "Get-ScheduledTaskInfo" in script
        assert "$trigger.Delay = 'PT0S'" in script
        assert "$trigger.Delay = 'PT15S'" not in script
        assert "IsNullOrEmpty([string]$xml.Task.Triggers.LogonTrigger.Delay)" in script
        assert "--background', '--startup'" in script
        assert "Start-ScheduledTask" not in script
        return json.dumps(raw)

    service = WindowsStartupService(executable=executable, runner=runner)
    assert service.status()["last_result"] == "0x00041301"
    assert calls[0]["arguments"] == "--startup"
    for key, bad in (
        ("running", "true"),
        ("last_result", "PRIVATE"),
        ("last_run_at", "2026-10-18T12:00:00"),
    ):
        previous = raw[key]
        raw[key] = bad
        with pytest.raises(CampusError) as error:
            service.status()
        assert "PRIVATE" not in str(error.value)
        raw[key] = previous


def test_lifecycle_reuses_one_record_without_creating_report_sessions(tmp_path, monkeypatch):
    root = tmp_path / "reports"
    calls = []
    monkeypatch.setattr(lifecycle.subprocess, "Popen", lambda argv, **kw: calls.append(argv))
    report = ReportSession(root)
    for _ in range(3):
        assert lifecycle.start_watcher(report)
    assert len(calls) == 3
    assert not any(path.is_dir() for path in root.iterdir())
    assert (root / "lifecycle-latest.json").exists()
    payload = json.loads((root / "lifecycle-latest.json").read_text())
    assert calls[-1][-1] == payload["instance"]
    assert calls[-1][-2] == str(root)
