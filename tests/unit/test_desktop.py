import json

import pytest

from campus_autoconnect.core.errors import CampusError
from campus_autoconnect.infrastructure.desktop import DesktopPreferences, DesktopStore
from campus_autoconnect.infrastructure.launch import (
    FROZEN_ARGUMENTS,
    SOURCE_ARGUMENTS,
    LaunchCommand,
    monitor_command,
)
from campus_autoconnect.infrastructure.startup import WindowsStartupService
from campus_autoconnect.services.desktop import DesktopService

pytestmark = pytest.mark.mock


def test_desktop_defaults_and_roundtrip_cannot_enable_authentication(tmp_path):
    store = DesktopStore(tmp_path / "desktop.json")
    assert store.load() == DesktopPreferences()
    store.save(DesktopPreferences("dark", False))
    assert store.load() == DesktopPreferences("dark", False)
    assert set(json.loads(store.path.read_text())) == {"schema_version", "theme", "close_to_tray"}
    assert not (tmp_path / "automation.json").exists()


@pytest.mark.parametrize(
    "raw",
    [
        {},
        [],
        {"schema_version": True, "theme": "light", "close_to_tray": True},
        {"schema_version": 1, "theme": "password=secret", "close_to_tray": True},
        {"schema_version": 1, "theme": "dark", "close_to_tray": 1},
        {"schema_version": 1, "theme": "dark", "close_to_tray": True, "enabled": True},
    ],
)
def test_invalid_desktop_data_is_not_trusted_or_echoed(tmp_path, raw):
    store = DesktopStore(tmp_path / "desktop.json")
    store.path.write_text(json.dumps(raw), encoding="utf-8")
    with pytest.raises(CampusError) as error:
        store.load()
    assert "secret" not in str(error.value)


def test_log_viewer_discards_injected_lines_even_if_log_redaction_was_bypassed(tmp_path):
    service = DesktopService(tmp_path)
    assert "暂无" in service.read_logs()
    folder = tmp_path / "logs"
    folder.mkdir(exist_ok=True)
    (folder / "campus.log").write_text(
        "2026-10-16 10:00:00,000 INFO operation state=UNKNOWN code=unknown\n"
        "2026-10-16 10:00:01,000 INFO automation state=DISABLED "
        "code=none attempt=0 runtime_error=none\n"
        "password=DO_NOT_SHOW\n"
        "2026-10-16 10:00:00,000 INFO operation state=UNKNOWN code=unknown token=DO_NOT_SHOW\n"
        "2026-10-16 10:00:00,000 INFO operation state=FAKE code=unknown\n"
        "2026-10-16 10:00:00,000 INFO automation state=ONLINE code=none\n",
        encoding="utf-8",
    )
    result = service.read_logs()
    assert len(result.splitlines()) == 2
    assert "DO_NOT_SHOW" not in result and "FAKE" not in result


def test_frozen_cli_uses_sibling_gui_with_literal_arguments(tmp_path, monkeypatch):
    import sys

    monkeypatch.setattr(sys, "frozen", True, raising=False)
    monkeypatch.setattr(sys, "executable", str(tmp_path / "CampusAutoConnect-CLI.exe"))
    target = tmp_path / "CampusAutoConnect.exe"
    target.touch()
    command = monitor_command()
    assert command.argv() == [str(target), "--background"]
    target.unlink()
    with pytest.raises(CampusError):
        command.argv()


@pytest.mark.parametrize(
    "name,args",
    [
        ("python.exe", SOURCE_ARGUMENTS),
        ("CampusAutoConnect.exe", ("--cli", "login")),
        ("pythonw.exe", FROZEN_ARGUMENTS),
        ("CampusAutoConnect-CLI.exe", FROZEN_ARGUMENTS),
    ],
)
def test_launch_rejects_unknown_executable_or_arguments(tmp_path, name, args):
    target = tmp_path / name
    target.touch()
    with pytest.raises(CampusError):
        LaunchCommand(target, args).validate()


def test_frozen_startup_keeps_existing_ownership_and_least_privilege_checks(tmp_path):
    executable = tmp_path / "CampusAutoConnect.exe"
    executable.touch()

    def runner(script, payload):
        request = json.loads(payload)
        assert request["arguments"] == "--startup"
        assert request["executable"] == str(executable)
        assert "-RunLevel Limited" in script
        assert "Task ownership conflict" in script
        assert "campus_autoconnect.cli.main monitor run" in script
        return json.dumps(dict.fromkeys(("installed", "owned", "configured", "enabled"), True))

    assert WindowsStartupService(executable=executable, runner=runner).enable()["configured"]


def test_export_import_preserves_source_and_never_reuses_credentials(profiles, tmp_path, profile):
    path = tmp_path / "export.json"
    profiles.export_to(path)
    before = profiles.list()
    assert profiles.import_from(path) == 1
    after = profiles.list()
    assert after[0] == before[0]
    imported = after[1]
    assert imported.ssid == profile.ssid
    assert imported.profile_id != profile.profile_id
    assert imported.credential_ref != profile.credential_ref
    assert not imported.enabled and not imported.auto_auth and imported.last_verified_at is None
    raw = json.loads(path.read_text(encoding="utf-8"))
    raw["profiles"][0]["password"] = "DO_NOT_IMPORT"
    path.write_text(json.dumps(raw), encoding="utf-8")
    with pytest.raises(ValueError):
        profiles.import_from(path)
    assert profiles.list() == after
