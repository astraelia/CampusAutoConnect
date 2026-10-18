"""Isolated synthetic checks available in both source and frozen distributions."""

import json
import os
import tempfile
import threading
import time
from dataclasses import asdict
from pathlib import Path

import httpx

from campus_autoconnect.core.models import NetworkAdapter, NetworkProfile, NetworkSnapshot
from campus_autoconnect.services.connectivity import DEFAULT_PROBES
from campus_inspector.checks import InspectionRunner
from campus_inspector.records import Evidence, Outcome, Step


class SyntheticNetwork:
    def __init__(self, *, route: bool = True) -> None:
        self.current = NetworkSnapshot(
            (
                NetworkAdapter(
                    7,
                    "Synthetic adapter",
                    "synthetic-guid",
                    True,
                    ssid="Synthetic-Campus",
                    ipv4=("192.0.2.10",),
                    gateways=("192.0.2.1",),
                ),
            )
        )
        self.route = route
        self.route_calls = 0

    def snapshot(self) -> NetworkSnapshot:
        return self.current

    def route_allows(self, _url: str, _snapshot: NetworkSnapshot) -> bool:
        self.route_calls += 1
        return self.route


def synthetic_config(directory: Path, *, enabled: bool = True) -> None:
    profile = NetworkProfile(
        "synthetic",
        "Synthetic profile",
        "Synthetic-Campus",
        enabled=enabled,
        trusted_portal_hosts=("portal.example.edu",),
    )
    (directory / "config.json").write_text(
        json.dumps(
            {
                "schema_version": 1,
                "profiles": [asdict(profile)],
            }
        ),
        encoding="utf-8",
    )


def transport_for(target: str | None) -> httpx.MockTransport:
    def respond(request):
        if target:
            return httpx.Response(302, headers={"Location": target})
        endpoint = next(p for p in DEFAULT_PROBES if p.url == str(request.url))
        return httpx.Response(endpoint.expected_status, content=endpoint.expected_body)

    return httpx.MockTransport(respond)


def offline_check() -> dict:
    cases = (
        ("http", "http://portal.example.edu/a79.htm", "http_disallowed"),
        ("host", "https://other.example.edu/login", "host_not_allowed"),
        ("port", "https://portal.example.edu:8443/login", "port_not_allowed"),
        ("online", None, "already_authenticated"),
        ("https", "https://portal.example.edu/login", "protocol_unverified"),
    )
    checks = {}
    with tempfile.TemporaryDirectory(prefix="campus-inspector-offline-") as temporary:
        directory = Path(temporary)
        synthetic_config(directory)
        original = (directory / "config.json").read_bytes()
        for name, target, expected in cases:
            steps = []
            network = SyntheticNetwork()
            runner = InspectionRunner(
                directory,
                steps.append,
                network=network,
                transport=transport_for(target),
                tls=lambda _: (True, "tls_verified", {"certificate_validation": True}),
            )
            runner.inspect(threading.Event())
            checks[name] = any(s.code == expected and s.outcome != Outcome.SKIPPED for s in steps)
            if name == "http":
                checks["http_no_target_connection"] = network.route_calls == 0
            serialized = json.dumps([asdict(s) for s in steps])
            checks[name + "_privacy"] = all(
                value not in serialized
                for value in (
                    "portal.example.edu",
                    "192.0.2.10",
                    "Synthetic-Campus",
                    "http://",
                    "https://",
                )
            )
        checks["config_unchanged"] = (directory / "config.json").read_bytes() == original
    return {
        "passed": all(checks.values()),
        "checks": checks,
        "evidence": "synthetic_only_no_host_network_or_credentials",
    }


def gui_check() -> dict:
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    from PySide6.QtCore import QCoreApplication, QEvent
    from PySide6.QtWidgets import QApplication

    from campus_inspector.gui import MainWindow
    from campus_inspector.session import Session

    class SyntheticRunner:
        def __init__(self, _directory, emit, **_kwargs):
            self.emit = emit

        def context(self):
            pass

        def inspect(self, cancel):
            cancel.wait(0.05)
            self.emit(
                Step(
                    "internet",
                    "合成联网场景",
                    Outcome.PASS,
                    "already_authenticated",
                    "隔离窗口自检使用虚构结果。",
                    Evidence.RECHECK,
                    run=1,
                )
            )

    checks = {}
    app = QApplication.instance() or QApplication([])
    with tempfile.TemporaryDirectory(prefix="campus-inspector-gui-") as temporary:
        window = MainWindow(
            Path(temporary),
            session_factory=lambda directory, emit: Session(
                directory, emit, runner_factory=SyntheticRunner
            ),
        )
        window.path_edit.clear()
        window.show()
        window.begin(False)
        checks["worker_started"] = window.thread is not None
        deadline = time.monotonic() + 10
        while window.thread is not None and time.monotonic() < deadline:
            app.processEvents()
            time.sleep(0.01)
        checks["worker_drained"] = window.thread is None
        checks["report_visible"] = window.report is not None and window.tree.topLevelItemCount() > 1
        checks["report_saved"] = (window.session.writer.directory / "report.json").is_file()
        window.copy_report()
        checks["copy_available"] = "校园网软件检测" in QApplication.clipboard().text()
        QApplication.clipboard().clear()
        window.close()
        window.deleteLater()
        QCoreApplication.sendPostedEvents(None, QEvent.DeferredDelete)
        app.processEvents()
    return {
        "passed": all(checks.values()),
        "checks": checks,
        "evidence": "isolated_gui_no_real_software_launch_or_network",
    }
