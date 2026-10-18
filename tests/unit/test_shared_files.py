import logging
import threading
from pathlib import Path

import pytest

from campus_autoconnect.infrastructure.config import ConfigStore
from campus_autoconnect.infrastructure.files import _open_shared, read_text_shared
from campus_autoconnect.infrastructure.locking import FileMutex
from campus_autoconnect.infrastructure.logging import SafeFormatter, SafeRotatingHandler

pytestmark = pytest.mark.mock


def test_concurrent_atomic_writer_waits_for_reader_and_preserves_both_snapshots(tmp_path):
    path = tmp_path / "status.json"
    path.write_text("old", encoding="utf-8")
    started, finished = threading.Event(), threading.Event()
    failures = []

    def write():
        started.set()
        try:
            ConfigStore._atomic_write(path, "new")
        except Exception as error:
            failures.append(type(error).__name__)
        finally:
            finished.set()

    with _open_shared(path) as reader:
        thread = threading.Thread(target=write)
        thread.start()
        assert started.wait(1)
        assert not finished.wait(0.03)
        assert reader.read() == b"old"
    thread.join(2)
    assert finished.is_set()
    assert failures == []
    assert read_text_shared(path, 3) == "new"


def test_shared_read_bounded_and_missing_has_file_not_found_type(tmp_path):
    path = tmp_path / "input.json"
    with pytest.raises(FileNotFoundError):
        read_text_shared(path, 10)
    path.write_bytes(b"x" * 11)
    with pytest.raises(ValueError):
        read_text_shared(path, 10)


def test_log_rotation_does_not_keep_other_process_handles_open(tmp_path):
    path = tmp_path / "events.log"
    first = SafeRotatingHandler(path, maxBytes=80, backupCount=2, encoding="utf-8", delay=True)
    second = SafeRotatingHandler(path, maxBytes=80, backupCount=2, encoding="utf-8", delay=True)
    try:
        for handler in (first, second, first, second):
            handler.setFormatter(SafeFormatter())
            handler.emit(logging.LogRecord("mock", logging.INFO, "", 0, "state=ONLINE", (), None))
            assert handler.stream is None
            assert not handler.failed
        assert Path(str(path) + ".1").exists()
    finally:
        first.close()
        second.close()


def test_logging_failure_suppresses_traceback_and_flags_loss(tmp_path, capsys):
    path = tmp_path / "events.log"
    handler = SafeRotatingHandler(path, maxBytes=80, backupCount=2, delay=True)
    with FileMutex(path.with_suffix(".log.lock")):
        handler.emit(logging.LogRecord("mock", logging.INFO, "", 0, "Mock operation", (), None))
    assert handler.failed
    assert capsys.readouterr().err == ""
    handler.close()
