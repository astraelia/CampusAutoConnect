"""Exercise the real hidden Python launch with isolated, default-off user data."""

import json
import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path

from campus_autoconnect.services.application import build_services


def child_check() -> int:
    services = build_services()
    automation = services.automation
    result = {"default_off": not automation.settings.load().enabled}
    try:
        automation.start_background(duration=8)
        deadline = time.monotonic() + 5
        state = {}
        while time.monotonic() < deadline:
            state = automation.control.status()
            if state.get("state") == "DISABLED":
                break
            time.sleep(0.05)
        result["hidden_process_running_disabled"] = state.get("state") == "DISABLED"
        result["cooperative_stop_queued"] = automation.stop_background()
        deadline = time.monotonic() + 5
        while automation.control.status()["running"] and time.monotonic() < deadline:
            time.sleep(0.05)
        result["stopped"] = not automation.control.status()["running"]
    finally:
        # A duration also bounds the helper if status/control publication itself fails.
        deadline = time.monotonic() + 10
        while automation.control.status()["running"] and time.monotonic() < deadline:
            time.sleep(0.05)
    print(json.dumps(result, ensure_ascii=True))
    return 0 if all(result.values()) else 1


def main() -> int:
    if sys.argv[1:] == ["--isolated-child"]:
        return child_check()
    with tempfile.TemporaryDirectory(prefix="campus-m2-launch-") as directory:
        environment = dict(os.environ, LOCALAPPDATA=directory, PYTHONUTF8="1")
        completed = subprocess.run(
            [sys.executable, str(Path(__file__).resolve()), "--isolated-child"],
            env=environment,
            capture_output=True,
            text=True,
            encoding="utf-8",
            timeout=30,
            creationflags=subprocess.CREATE_NO_WINDOW,
        )
        # Never forward unexpected traceback text from a child.
        try:
            summary = json.loads(completed.stdout)
            keys = {
                "default_off",
                "hidden_process_running_disabled",
                "cooperative_stop_queued",
                "stopped",
            }
            if set(summary) != keys or any(type(value) is not bool for value in summary.values()):
                raise ValueError
        except (ValueError, TypeError):
            summary = {"check_failed": True, "child_exit_code": completed.returncode}
            print(json.dumps(summary, indent=2))
            return 1
        print(json.dumps(summary, indent=2))
        return completed.returncode


if __name__ == "__main__":
    raise SystemExit(main())
