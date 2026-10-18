import json
import subprocess
import sys

import pytest

from campus_autoconnect.core.errors import CampusError
from campus_autoconnect.core.models import Credentials, ErrorCode
from campus_autoconnect.infrastructure.automation import AutomationStore
from campus_autoconnect.infrastructure.locking import FileMutex
from campus_autoconnect.infrastructure.startup import WindowsStartupService
from campus_autoconnect.security.credentials import WindowsCredentialStore
from campus_autoconnect.services.monitor import MonitorControl

pytestmark = pytest.mark.mock


def test_missing_settings_default_off_and_round_trip(tmp_path):
    store = AutomationStore(tmp_path / "automation.json")
    assert not store.load().enabled
    store.set_enabled(True)
    assert AutomationStore(store.path).load().enabled
    store.set_enabled(False)
    assert not store.load().enabled
    assert set(json.loads(store.path.read_text())) == {"schema_version", "enabled"}


@pytest.mark.parametrize(
    "content",
    [
        "{",
        "[]",
        '{"schema_version":true,"enabled":true}',
        '{"schema_version":1,"enabled":"true"}',
        '{"schema_version":1,"enabled":true,"password":"fictional"}',
        "[" * 2000,
    ],
)
def test_invalid_settings_fail_closed_and_do_not_restore_enabled_backup(tmp_path, content):
    store = AutomationStore(tmp_path / "automation.json")
    store.path.write_text(content, encoding="utf-8")
    store.path.with_suffix(".json.bak").write_text('{"schema_version":1,"enabled":true}')
    with pytest.raises(CampusError) as error:
        store.load()
    assert error.value.code == ErrorCode.CONFIG_ERROR
    assert store.path.read_text(encoding="utf-8") == content
    store.set_enabled(False)
    assert not store.load().enabled


def test_profile_transaction_rejects_other_writer_without_losing_data(profiles, profile):
    with (
        FileMutex(profiles.store.path.with_suffix(".json.lock")),
        pytest.raises(CampusError) as error,
    ):
        profiles.remove(profile.profile_id)
    assert error.value.code == ErrorCode.BUSY
    assert profiles.list() == [profile]
    profiles.remove(profile.profile_id)
    assert profiles.list() == []


def test_mutex_is_cross_process_and_os_releases_after_exit(tmp_path):
    path = tmp_path / "process.lock"
    child = subprocess.Popen(
        [
            sys.executable,
            "-c",
            """
import sys
from pathlib import Path
from campus_autoconnect.infrastructure.locking import FileMutex
mutex = FileMutex(Path(sys.argv[1]))
assert mutex.acquire()
print('ready', flush=True)
sys.stdin.readline()
""",
            str(path),
        ],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        assert child.stdout.readline().strip() == "ready"
        assert not FileMutex(path).acquire()
    finally:
        child.communicate("stop\n", timeout=5)
    with FileMutex(path):
        assert path.exists()


def test_credential_mutations_cannot_race_with_running_authentication(tmp_path, monkeypatch):
    path = tmp_path / "authentication.lock"
    store = WindowsCredentialStore(mutation_lock=FileMutex(path))
    backend_calls = []
    monkeypatch.setattr(store, "_backend", lambda: backend_calls.append("must not be reached"))
    with FileMutex(path):
        for action in (
            lambda: store.set("shared", Credentials("synthetic", "synthetic-only")),
            lambda: store.delete("shared"),
        ):
            with pytest.raises(CampusError) as error:
                action()
            assert error.value.code == ErrorCode.BUSY
    assert backend_calls == []


def test_stale_runtime_file_cannot_claim_running_or_target_new_process(tmp_path):
    control = MonitorControl(tmp_path)
    old = "1" * 32
    control.write(old, {"state": "ONLINE", "error_code": "none"})
    assert control.status()["running"] is False
    assert not control.request_stop()
    control.stop_path.write_text(json.dumps({"schema_version": 1, "instance": old}))
    assert not control.stop_requested("2" * 32)


def test_running_status_and_stop_are_whitelisted_and_bound_to_instance(tmp_path):
    control = MonitorControl(tmp_path)
    instance = "2" * 32
    with FileMutex(control.lock_path):
        control.write(
            instance,
            {
                "state": "BLOCKED",
                "error_code": "protocol_unverified",
                "attempts": 1,
                "max_attempts": 3,
                "operation_running": False,
                "secret": "DO_NOT_ECHO",
            },
        )
        status = control.status()
        assert status["running"]
        assert status["error_code"] == "protocol_unverified"
        assert "DO_NOT_ECHO" not in str(status)
        assert "instance" not in status
        assert control.request_stop()
        assert control.stop_requested(instance)
    assert control.status()["running"] is False


def test_startup_is_explicit_and_preserves_argument_boundaries(tmp_path):
    executable = tmp_path / "path with spaces & literal" / "pythonw.exe"
    executable.parent.mkdir()
    executable.touch()
    requests = []

    def runner(script, input_text):
        request = json.loads(input_text)
        requests.append(request)
        # Security contract: no elevation/password logon and no shell-concatenated user input.
        assert "-UserId $currentUser" in script
        assert "-LogonType Interactive -RunLevel Limited" in script
        assert "Task principal identity mismatch" in script
        assert "-MultipleInstances IgnoreNew" in script
        assert "-Hidden" in script
        assert "-User $sid" in script
        assert "Task ownership conflict" in script
        assert str(executable) not in script
        installed = request["command"] != "disable"
        return json.dumps(dict.fromkeys(("installed", "owned", "configured", "enabled"), installed))

    startup = WindowsStartupService(executable=executable, runner=runner)
    assert requests == []
    assert startup.enable()["enabled"]
    assert startup.status()["installed"]
    assert not startup.disable()["installed"]
    assert [r["command"] for r in requests] == ["enable", "status", "disable"]
    assert all(r["executable"] == str(executable) for r in requests)


def test_startup_raw_failure_is_not_exposed():
    def fail(*_):
        raise CampusError(ErrorCode.UNKNOWN, "account=DO_NOT_ECHO")

    with pytest.raises(CampusError) as error:
        WindowsStartupService(runner=fail).status()
    assert error.value.code == ErrorCode.STARTUP_ERROR
    assert "DO_NOT_ECHO" not in error.value.message
