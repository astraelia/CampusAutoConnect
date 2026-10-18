import json
import sys
import threading
from dataclasses import asdict

import pytest
from campus_inspector.processes import (
    CommandResult,
    LaunchObserver,
    Target,
    bounded_json,
    command_step,
    file_hash,
    inspect_target,
)
from campus_inspector.records import Outcome
from campus_inspector.session import safe_log_events


def test_bounded_subprocess_json_and_output_limit():
    cancel = threading.Event()
    good = bounded_json([sys.executable, "-c", "print('{\"ok\":true}')"], cancel)
    assert good.payload == {"ok": True}
    huge = bounded_json([sys.executable, "-c", "print('x'*100000)"], cancel, limit=1024)
    assert huge.code == "helper_output_limit"
    assert huge.payload is None


def test_subprocess_timeout_and_raw_exception_not_returned():
    result = bounded_json(
        [sys.executable, "-c", "import time; time.sleep(10)"], threading.Event(), timeout=0.15
    )
    assert result.code == "helper_timeout"
    raw = bounded_json(
        [sys.executable, "-c", "print('password=PRIVATE_SECRET')"], threading.Event()
    )
    assert raw.code == "helper_invalid_output"
    assert "PRIVATE_SECRET" not in repr(raw)


def test_target_manifest_checks_both_executables(tmp_path):
    gui = tmp_path / "CampusAutoConnect.exe"
    cli = tmp_path / "CampusAutoConnect-CLI.exe"
    gui.write_bytes(b"MZ synthetic GUI")
    cli.write_bytes(b"MZ synthetic CLI")
    (tmp_path / "BUILD_INFO.json").write_text('{"version":"0.1.0.dev4"}', encoding="utf-8")
    (tmp_path / "SHA256SUMS.json").write_text(
        json.dumps(
            {
                gui.name: file_hash(gui),
                cli.name: file_hash(cli),
            }
        ),
        encoding="utf-8",
    )
    assert inspect_target(gui).manifest_matches is True
    cli.write_bytes(b"MZ changed")
    assert inspect_target(gui).manifest_matches is False


def test_manifest_mismatch_never_executes(tmp_path, monkeypatch):
    target = Target(
        tmp_path / "CampusAutoConnect.exe", tmp_path / "CLI.exe", "0" * 64, "0.1.0.dev4", False
    )
    monkeypatch.setattr("subprocess.Popen", lambda *a, **k: pytest.fail("must not execute"))
    assert command_step(target, "runtime", threading.Event()).code == "manifest_mismatch"
    assert LaunchObserver().launch(target).outcome == Outcome.BLOCKED


def test_exe_projection_discards_arbitrary_fields(tmp_path, monkeypatch):
    target = Target(
        tmp_path / "CampusAutoConnect.exe", tmp_path / "CLI.exe", "0" * 64, "0.1.0.dev4", True
    )
    monkeypatch.setattr(
        "campus_inspector.processes.bounded_json",
        lambda *_: CommandResult(
            "helper_result",
            1,
            {
                "version": "0.1.0.dev4",
                "state": "UNKNOWN",
                "error_code": "untrusted_target",
                "ssid_known": True,
                "portal_discovered": True,
                "password": "PRIVATE_SECRET",
                "host": "private-host",
                "checked_at": "2026-10-17T04:36:33+00:00",
            },
        ),
    )
    step = command_step(target, "diagnose", threading.Event())
    content = json.dumps(asdict(step))
    assert step.code == "untrusted_target"
    assert "PRIVATE_SECRET" not in content
    assert "private-host" not in content
    assert "另一次检测" in step.detail


def test_runtime_does_not_trust_only_a_passed_flag(tmp_path, monkeypatch):
    target = Target(
        tmp_path / "CampusAutoConnect.exe", tmp_path / "CLI.exe", "0" * 64, "0.1.0.dev4", True
    )
    monkeypatch.setattr(
        "campus_inspector.processes.bounded_json",
        lambda *_: CommandResult("helper_result", 0, {"passed": True}),
    )
    assert command_step(target, "runtime", threading.Event()).outcome == Outcome.ERROR


def test_event_log_accepts_only_valid_enum_lines(tmp_path):
    path = tmp_path / "campus.log"
    path.write_text(
        "2026-10-17 12:36:33,100 INFO operation state=UNKNOWN code=untrusted_target\n"
        "2026-10-17 12:36:33,101 INFO operation state=UNKNOWN code=password_SECRET\n"
        "2026-10-17 12:36:33,102 INFO operation state=UNKNOWN code=none token=SECRET\n"
        "2026-10-17 12:36:33,103 INFO automation state=DISABLED code=automation_disabled"
        " attempt=0 runtime_error=none\n",
        encoding="utf-8",
    )
    result = safe_log_events(path)
    assert len(result) == 2
    assert "SECRET" not in repr(result)


def test_normal_singleton_exit_not_reported_as_crash():
    observer = LaunchObserver()

    class Exited:
        def poll(self):
            return 0

    observer.process = Exited()
    step = observer.poll()
    assert step.outcome == Outcome.INFO
    assert "单实例" in step.detail
    assert observer.poll() is None
