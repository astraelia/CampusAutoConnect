"""Optional helper observes an already-started GUI; it never starts authentication."""

import ctypes
import json
import os
import re
import subprocess
import sys
import uuid
from datetime import UTC, datetime
from pathlib import Path

from campus_autoconnect.infrastructure.config import ConfigStore
from campus_autoconnect.infrastructure.locking import FileMutex
from campus_autoconnect.infrastructure.reports import (
    ReportSession,
    check_report_root,
    installation_directory,
    plain_path,
)


def start_watcher(session: ReportSession) -> bool:
    try:
        root = session.root
        check_report_root(root)
        token = uuid.uuid4().hex
        with FileMutex(root / ".reports.lock", timeout=1):
            if not plain_path(root / "lifecycle-latest.json"):
                return False
            ConfigStore._atomic_write(
                root / "lifecycle-latest.json",
                json.dumps(
                    {
                        "source": "lifecycle_helper",
                        "state": "requested",
                        "instance": token,
                        "coverage": "仅观察辅助进程启动后本次 GUI 的退出，不覆盖此前装载故障。",
                    }
                )
                + "\n",
            )
        arguments = [sys.executable]
        if not getattr(sys, "frozen", False):
            arguments += ["-X", "utf8", "-m", "campus_autoconnect.entry"]
        arguments += ["--support-watch", str(os.getpid()), str(root), token]
        subprocess.Popen(
            arguments,
            cwd=str(installation_directory()),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            creationflags=subprocess.CREATE_NO_WINDOW,
            env={**os.environ, "PYINSTALLER_RESET_ENVIRONMENT": "1"},
        )
        return True
    except Exception:
        return False


def watch(arguments: list[str]) -> int:
    if (
        len(arguments) != 3
        or not re.fullmatch(r"[1-9][0-9]{0,9}", arguments[0])
        or not re.fullmatch(r"[a-f0-9]{32}", arguments[2])
    ):
        return 2
    directory = Path(arguments[1])
    root = installation_directory() / "reports"
    if not directory.is_absolute() or directory.resolve() != root.resolve():
        return 2
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.OpenProcess.argtypes = [ctypes.c_ulong, ctypes.c_int, ctypes.c_ulong]
    kernel.OpenProcess.restype = ctypes.c_void_p
    kernel.WaitForSingleObject.argtypes = [ctypes.c_void_p, ctypes.c_ulong]
    kernel.GetExitCodeProcess.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_ulong)]
    kernel.CloseHandle.argtypes = [ctypes.c_void_p]
    handle = kernel.OpenProcess(0x100000 | 0x1000, False, int(arguments[0]))
    if not handle:
        payload = {"source": "lifecycle_helper", "state": "unavailable", "exit_code": None}
    else:
        try:
            outcome = kernel.WaitForSingleObject(handle, 172800000)
            code = ctypes.c_ulong()
            queried = outcome == 0 and kernel.GetExitCodeProcess(handle, ctypes.byref(code))
            payload = {
                "source": "lifecycle_helper",
                "state": "exited" if queried else "unavailable",
                "exit_code": code.value if queried else None,
            }
        finally:
            kernel.CloseHandle(handle)
    payload["at"] = datetime.now(UTC).isoformat()
    try:
        check_report_root(root)
        with FileMutex(root / ".reports.lock", timeout=1):
            path = root / "lifecycle-latest.json"
            if not plain_path(path) or path.stat().st_size > 4096:
                return 1
            current = json.loads(path.read_text(encoding="utf-8"))
            if current.get("instance") != arguments[2]:
                return 0
            payload["instance"] = arguments[2]
            ConfigStore._atomic_write(path, json.dumps(payload) + "\n")
    except Exception:
        return 1
    return 0
