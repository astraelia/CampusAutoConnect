import pytest

from campus_autoconnect.core.models import AuthState, ErrorCode
from campus_autoconnect.core.observation import OperationTrace, observe
from campus_autoconnect.infrastructure.logging import (
    log_operation_timing,
    log_startup_timing,
    setup_logging,
)
from campus_autoconnect.services.desktop import DesktopService

pytestmark = pytest.mark.mock


def test_scalar_timing_logs_are_viewable_and_injected_lines_remain_hidden(tmp_path):
    logger = setup_logging(tmp_path / "logs")
    trace = OperationTrace()
    token = trace.begin("login")
    try:
        observe("stage", stage="network")
        observe("stage", stage="connectivity")
        observe("result", state=AuthState.AUTHENTICATED, code=ErrorCode.NONE)
    finally:
        trace.end(token)
    log_operation_timing(logger, trace.snapshot())
    log_startup_timing(logger, "network_ready", 0.125)
    log_startup_timing(logger, "password=DO_NOT_SHOW", 1)
    path = tmp_path / "logs/campus.log"
    with path.open("a", encoding="utf-8") as stream:
        stream.write(
            "2026-10-18 10:00:00,000 INFO startup stage=online elapsed_ms=10 token=SECRET\n"
        )
        stream.write("2026-10-18 10:00:00,000 INFO startup stage=online elapsed_ms=99999999\n")
    visible = DesktopService(tmp_path).read_logs()
    assert "timing kind=login" in visible
    assert "startup stage=network_ready elapsed_ms=125" in visible
    assert "SECRET" not in visible and "DO_NOT_SHOW" not in visible
    assert len(visible.splitlines()) == 2
