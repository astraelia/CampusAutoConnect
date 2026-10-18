"""Report retention exercises real temporary files and OS locks, never user reports."""

import json
import os
from dataclasses import asdict, replace
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from campus_autoconnect.core.errors import CampusError
from campus_autoconnect.core.models import AuthState
from campus_autoconnect.infrastructure import report_maintenance as retention
from campus_autoconnect.infrastructure.report_maintenance import (
    ReportMaintenance,
    ReportPolicy,
    ReportPolicyStore,
)
from campus_autoconnect.infrastructure.reports import ReportSession
from campus_autoconnect.services.application import ApplicationServices
from campus_autoconnect.services.support import SupportService

pytest_plugins = ["tests.unit.test_bjut_auth"]
pytestmark = pytest.mark.mock
NOW = datetime(2026, 10, 18, 8, tzinfo=UTC)


@pytest.fixture
def manager(tmp_path):
    return ReportMaintenance(tmp_path / "reports", tmp_path / "settings" / "report-policy.json")


def session(manager, *, age=10, capture=False, protected=False, active=False, size=30):
    report = ReportSession(manager.root)
    report.write("diagnostic.json", "x" * size)
    if capture:
        report.write("PortalCapture_session.json", {"synthetic": True})
    if protected:
        report.set_protected(True)
    for name in ("diagnostic.json", "PortalCapture_session.json"):
        path = report.directory / name
        if path.exists():
            stamp = (NOW - timedelta(days=age)).timestamp()
            os.utime(path, (stamp, stamp))
    if not active:
        report.close()
    return report


def test_normal_connection_has_memory_trace_but_no_report_directory(
    bjut_service, credentials, profiles, tmp_path
):
    auth, _, _, _ = bjut_service
    support = SupportService(tmp_path, auth, tmp_path / "reports")
    app = ApplicationServices(profiles, credentials, auth, support=support)
    app.record_result(auth.login())
    assert app.last_result.state == AuthState.AUTHENTICATED
    assert support.payload()["actual_trace"] and support.last_diagnostic["checked_at"]
    assert not support.session.root.exists()
    assert not support.last_saved and not support.save_error
    support.begin()
    app.record_result(auth.check())
    assert (support.session.directory / "diagnostic.json").exists()
    support.finish()


def test_pin_explicitly_saves_current_memory_diagnostic_and_keeps_finished_session_closed(
    bjut_service, credentials, profiles, tmp_path
):
    auth, _, _, _ = bjut_service
    support = SupportService(tmp_path, auth, tmp_path / "reports")
    app = ApplicationServices(profiles, credentials, auth, support=support)
    app.record_result(auth.login())
    try:
        support.protect_report(True)
        path = support.session.directory / "diagnostic.json"
        document = json.loads(path.read_text(encoding="utf-8"))
        assert document["diagnostic"]["state"] == "AUTHENTICATED"
        assert support.session.protected and path.exists()
        support.finish()
        support.protect_report(False)
        assert support.session._active is None
        assert not json.loads((path.parent / "session.json").read_text())["protected"]
    finally:
        support.close()


def test_expired_reports_removed_but_active_pinned_capture_and_unknown_stay(manager):
    expired = session(manager)
    active = session(manager, active=True)
    pinned = session(manager, protected=True)
    capture = session(manager, capture=True)
    unknown = session(manager)
    (unknown.directory / "my-notes.txt").write_text("keep", encoding="utf-8")
    try:
        result = manager.cleanup(now=NOW)
        assert result["last_result"]["deleted"] == 1
        assert result["last_result"]["failed"] == 0
        assert not expired.directory.exists()
        assert all(r.directory.exists() for r in (active, pinned, capture, unknown))
        assert result["skipped"] == result["active"] == 1
    finally:
        active.close()


def test_count_cap_removes_oldest_recent_sessions(manager):
    manager.store.save(replace(ReportPolicy(), max_sessions=2))
    reports = [session(manager, age=age) for age in (4, 3, 2, 1)]
    result = manager.cleanup(now=NOW)
    assert result["last_result"]["deleted"] == 2
    assert [r.directory.exists() for r in reports] == [False, False, True, True]


def test_size_cap_is_independent_from_age_and_count(manager):
    manager.store.save(replace(ReportPolicy(), max_bytes=1024 * 1024))
    old = session(manager, age=2, size=750000)
    new = session(manager, age=1, size=750000)
    result = manager.cleanup(now=NOW)
    assert result["last_result"]["deleted"] == 1
    assert not old.directory.exists() and new.directory.exists()
    assert result["total_bytes"] < 1024 * 1024


def test_capture_only_becomes_eligible_after_explicit_policy_permission(manager):
    report = session(manager, capture=True)
    assert manager.cleanup(now=NOW)["last_result"]["deleted"] == 0
    manager.store.save(replace(ReportPolicy(), include_capture=True))
    assert manager.cleanup(now=NOW)["last_result"]["deleted"] == 1
    assert not report.directory.exists()


def test_legacy_is_previewed_and_only_approved_names_can_be_adopted_or_deleted(manager):
    reports = [session(manager) for _ in range(2)]
    for report in reports:
        (report.directory / "session.json").unlink()
        (report.directory / "session.json.io.lock").unlink()
    assert manager.due(now=NOW)["last_result"]["deleted"] == 0
    preview = manager.preview(include_legacy=True, now=NOW)
    assert preview["legacy_count"] == preview["candidate_count"] == 2
    chosen = reports[0].directory.name
    result = manager.cleanup(approved_legacy=(chosen,), approved_candidates=(chosen,), now=NOW)
    assert result["last_result"]["deleted"] == result["last_result"]["adopted"] == 1
    assert not reports[0].directory.exists() and reports[1].directory.exists()


def test_confirmed_recent_legacy_is_retained_then_automatically_expires(manager):
    report = session(manager, age=1)
    (report.directory / "session.json").unlink()
    manager.cleanup(approved_legacy=(report.directory.name,), approved_candidates=(), now=NOW)
    assert report.directory.exists()
    result = manager.due(now=NOW + timedelta(days=8))
    assert result["last_result"]["deleted"] == 1 and not report.directory.exists()


def test_daily_schedule_and_disabled_policy_do_not_delete_on_every_poll(manager):
    report = session(manager)
    manager.store.save(replace(ReportPolicy(), enabled=False))
    assert manager.due(now=NOW)["policy"]["enabled"] is False
    assert manager.due(now=NOW + timedelta(hours=23)) is None
    assert report.directory.exists()
    manager.store.save(ReportPolicy())
    assert manager.due(now=NOW + timedelta(hours=24))["last_result"]["deleted"] == 1


def test_deletion_failure_is_visible_and_never_unlinks_unknown_paths(manager, monkeypatch):
    report = session(manager)
    original = Path.unlink

    def deny(path, *args, **kwargs):
        if path == report.directory / "diagnostic.json":
            raise PermissionError("PRIVATE-DO-NOT-ECHO")
        return original(path, *args, **kwargs)

    monkeypatch.setattr(Path, "unlink", deny)
    result = manager.cleanup(now=NOW)
    assert result["last_result"]["failed"] == 1
    assert report.directory.exists() and (report.directory / "session.json").exists()
    assert "PRIVATE" not in json.dumps(result)


def test_reparse_session_or_file_is_excluded_before_deletion(manager, monkeypatch):
    report = session(manager)
    original = retention.plain_path
    monkeypatch.setattr(
        retention,
        "plain_path",
        lambda path: path != report.directory / "diagnostic.json" and original(path),
    )
    result = manager.cleanup(now=NOW)
    assert result["skipped"] == 1 and report.directory.exists()
    assert (report.directory / "diagnostic.json").exists()


def test_corrupt_policy_fails_closed_and_never_echoes_input(manager):
    report = session(manager)
    manager.store.path.parent.mkdir(parents=True, exist_ok=True)
    manager.store.path.write_text('{"password":"PRIVATE"}', encoding="utf-8")
    with pytest.raises(CampusError) as raised:
        manager.due(now=NOW)
    assert report.directory.exists() and "PRIVATE" not in str(raised.value)


@pytest.mark.parametrize(
    "field,value",
    [
        ("days", True),
        ("days", 0),
        ("max_sessions", 0),
        ("max_bytes", 0),
        ("include_capture", 1),
        ("enabled", "true"),
        ("schema_version", True),
    ],
)
def test_policy_validation_is_strict(field, value):
    raw = {"schema_version": 1, **asdict(ReportPolicy())}
    raw[field] = value
    with pytest.raises(ValueError):
        ReportPolicyStore.validate(raw)


def test_new_session_can_be_cleaned_after_its_real_lock_is_released(manager):
    report = session(manager, active=True)
    assert manager.cleanup(now=NOW)["last_result"]["deleted"] == 0
    report.close()
    assert manager.cleanup(now=NOW)["last_result"]["deleted"] == 1
