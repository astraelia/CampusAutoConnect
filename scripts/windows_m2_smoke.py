"""Opt-in, credential-free M2 host checks. Never installs a task or changes the network."""

import json
import tempfile
import threading
import time
from pathlib import Path

from campus_autoconnect.core.errors import CampusError
from campus_autoconnect.core.models import ErrorCode
from campus_autoconnect.core.profiles import ProfileService
from campus_autoconnect.infrastructure.automation import AutomationStore
from campus_autoconnect.infrastructure.config import ConfigStore
from campus_autoconnect.infrastructure.startup import WindowsStartupService
from campus_autoconnect.infrastructure.windows_events import WindowsEventSource
from campus_autoconnect.services.automation import AutomationCoordinator
from campus_autoconnect.services.monitor import MonitorControl, MonitorRuntime


def main() -> int:
    class NeverUsed:
        calls = 0

        def snapshot(self):
            self.calls += 1
            raise AssertionError("Default-off monitor must not query networks")

        def login(self, *_args, **_kwargs):
            self.calls += 1
            raise AssertionError("No authentication is authorized by this smoke check")

    result = {}
    with tempfile.TemporaryDirectory(prefix="campus-m2-smoke-") as directory:
        root = Path(directory)
        profiles = ProfileService(ConfigStore(root / "config.json"))
        settings = AutomationStore(root / "automation.json")
        never = NeverUsed()
        coordinator = AutomationCoordinator(never, profiles, settings)
        events = WindowsEventSource()
        control = MonitorControl(root)
        runtime = MonitorRuntime(coordinator, never, profiles, settings, control, events=events)
        stop = threading.Event()
        failures = []

        def run():
            try:
                runtime.run(stop=stop, duration=8)
            except Exception as exc:
                failures.append(type(exc).__name__)

        thread = threading.Thread(target=run)
        thread.start()
        try:
            deadline = time.monotonic() + 5
            while time.monotonic() < deadline and control.status().get("state") != "DISABLED":
                time.sleep(0.05)
            result["disabled_monitor_running"] = control.status().get("state") == "DISABLED"
            result["native_registrations"] = len(events._cleanups)
            result["event_warnings"] = list(events.warnings)
            try:
                runtime.run(duration=0.1)
                result["duplicate_rejected"] = False
            except CampusError as exc:
                result["duplicate_rejected"] = exc.code == ErrorCode.BUSY
            result["stop_queued"] = control.request_stop()
        finally:
            stop.set()
            thread.join(10)
        result["stopped"] = not thread.is_alive() and not control.status()["running"]
        result["native_cleanup_warnings"] = list(events.warnings)
        result["network_and_auth_calls"] = never.calls
        result["runtime_failure_types"] = failures
    try:
        result["startup_read_only"] = WindowsStartupService().status()
    except CampusError as exc:
        result["startup_read_only"] = {"available": False, "error_code": exc.code.value}
    print(json.dumps(result, ensure_ascii=True, indent=2))
    passed = (
        result["disabled_monitor_running"]
        and result["native_registrations"] == 5
        and not result["native_cleanup_warnings"]
        and result["duplicate_rejected"]
        and result["stop_queued"]
        and result["stopped"]
        and result["network_and_auth_calls"] == 0
        and not result["runtime_failure_types"]
    )
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
