import runpy
import sys

import pytest

from campus_autoconnect import entry

pytestmark = pytest.mark.mock


def test_source_module_uses_the_same_dispatcher(monkeypatch):
    monkeypatch.setattr(entry, "main", lambda: 7)
    with pytest.raises(SystemExit) as raised:
        runpy.run_module("campus_autoconnect", run_name="__main__")
    assert raised.value.code == 7


def test_unknown_gui_arguments_do_not_open_app_or_start_monitor(monkeypatch):
    called = []
    monkeypatch.setattr("campus_autoconnect.ui.app.main", lambda: called.append("gui"))
    assert entry._dispatch(["--unexpected"]) == 2
    assert called == []


def test_frozen_background_routes_to_fixed_cli_mode(monkeypatch):
    called = []
    monkeypatch.setattr("campus_autoconnect.cli.main.main", lambda argv: called.append(argv) or 0)
    assert entry._dispatch(["--background", "--duration", "3"]) == 0
    assert called == [["monitor", "run", "--duration", "3"]]


def test_console_build_and_explicit_cli_share_parser(monkeypatch):
    called = []
    monkeypatch.setattr("campus_autoconnect.cli.main.main", lambda argv: called.append(argv) or 0)
    monkeypatch.setattr(sys, "executable", "CampusAutoConnect-CLI.exe")
    assert entry._dispatch(["--help"]) == 0
    assert entry._dispatch(["--cli", "monitor", "status"]) == 0
    assert called == [["--help"], ["monitor", "status"]]


def test_unexpected_startup_error_hides_raw_details(monkeypatch, capsys):
    def fail(_):
        raise ImportError("password=DO_NOT_ECHO")

    monkeypatch.setattr(entry, "_dispatch", fail)
    monkeypatch.setattr(sys, "argv", ["CampusAutoConnect-CLI.exe", "--cli"])
    assert entry.main() == 1
    text = capsys.readouterr().err
    assert "ImportError" in text and "DO_NOT_ECHO" not in text
