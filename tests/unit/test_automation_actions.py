"""Explicit repair actions use isolated preferences and never touch real tasks."""

import json
from types import SimpleNamespace

import pytest

from campus_autoconnect.core.errors import CampusError
from campus_autoconnect.core.models import ErrorCode
from campus_autoconnect.infrastructure.automation import AutomationStore
from campus_autoconnect.infrastructure.startup import WindowsStartupService
from campus_autoconnect.services.automation_application import AutomationService

pytestmark = pytest.mark.mock


@pytest.mark.parametrize("running", [False, True])
def test_save_and_start_is_explicit_and_reuses_running_monitor(tmp_path, monkeypatch, running):
    settings = AutomationStore(tmp_path / "automation.json")
    service = AutomationService(
        settings, SimpleNamespace(status=lambda: {"running": running}), None, None
    )
    starts = []
    monkeypatch.setattr(service, "start_background", lambda: starts.append(True))
    service.set_enabled(True)
    assert starts == []
    service.save_and_start(True)
    assert settings.load().enabled and starts == ([] if running else [True])


def test_combined_start_does_not_enable_without_explicit_checked_permission(tmp_path):
    settings = AutomationStore(tmp_path / "automation.json")
    service = AutomationService(settings, None, None, None)
    with pytest.raises(CampusError) as error:
        service.save_and_start(False)
    assert error.value.code == ErrorCode.AUTOMATION_DISABLED
    assert not settings.path.exists()


def test_start_failure_reports_saved_preference_without_claiming_running(tmp_path, monkeypatch):
    settings = AutomationStore(tmp_path / "automation.json")
    control = SimpleNamespace(status=lambda: {"running": False})
    service = AutomationService(settings, control, None, None)

    def fail():
        raise CampusError(ErrorCode.TIMEOUT, "尚未确认后台启动，请刷新状态后再操作。")

    monkeypatch.setattr(service, "start_background", fail)
    with pytest.raises(CampusError) as error:
        service.save_and_start(True)
    assert error.value.code == ErrorCode.TIMEOUT
    assert "开关已保存" in error.value.message
    assert settings.load().enabled and not control.status()["running"]


@pytest.mark.parametrize("enabled", [False, True])
def test_startup_repair_has_separate_command_and_accepts_preserved_disabled_state(
    tmp_path, enabled
):
    executable = tmp_path / "CampusAutoConnect.exe"
    executable.touch()
    calls = []

    def runner(script, payload):
        calls.append(json.loads(payload))
        assert "-not $before.owned" in script
        assert "Managed task not found" in script
        assert "-Disable:$keepDisabled" in script
        assert "Start-ScheduledTask" not in script
        return json.dumps(dict(installed=True, owned=True, configured=True, enabled=enabled))

    startup = WindowsStartupService(executable=executable, runner=runner)
    assert startup.repair()["enabled"] is enabled
    assert [call["command"] for call in calls] == ["repair"]


@pytest.mark.parametrize("field", ["installed", "owned", "configured"])
def test_startup_repair_never_accepts_missing_conflicting_or_unmigrated_task(tmp_path, field):
    executable = tmp_path / "CampusAutoConnect.exe"
    executable.touch()
    raw = dict.fromkeys(("installed", "owned", "configured", "enabled"), True)
    raw[field] = False
    startup = WindowsStartupService(executable=executable, runner=lambda *_: json.dumps(raw))
    with pytest.raises(CampusError) as error:
        startup.repair()
    assert error.value.code == ErrorCode.STARTUP_ERROR
