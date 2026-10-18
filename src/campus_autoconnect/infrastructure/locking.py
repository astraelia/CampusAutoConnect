"""Small, process-lifetime file locks. A stale file never implies a live owner."""

import os
import threading
import time
from pathlib import Path
from typing import BinaryIO

from campus_autoconnect.core.errors import CampusError
from campus_autoconnect.core.models import ErrorCode


class FileMutex:
    def __init__(self, path: Path, *, timeout: float = 0) -> None:
        self.path = path
        self.timeout = timeout
        self._stream: BinaryIO | None = None
        self._local = threading.Lock()

    def acquire(self) -> bool:
        deadline = time.monotonic() + self.timeout
        while True:
            if self._try_acquire():
                return True
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return False
            time.sleep(min(0.01, remaining))

    def _try_acquire(self) -> bool:
        if not self._local.acquire(blocking=False):
            return False
        stream = None
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            stream = self.path.open("a+b")
            if self.path.stat().st_size == 0:
                stream.write(b"\0")
                stream.flush()
            stream.seek(0)
            try:
                if os.name == "nt":
                    import msvcrt

                    msvcrt.locking(stream.fileno(), msvcrt.LK_NBLCK, 1)
                else:
                    import fcntl

                    fcntl.flock(stream.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            except OSError as exc:
                if exc.errno not in {11, 13, 36}:
                    raise
                stream.close()
                self._local.release()
                return False
            self._stream = stream
            return True
        except OSError as exc:
            if stream is not None:
                stream.close()
            self._local.release()
            raise CampusError(
                ErrorCode.CONFIG_ERROR, "无法建立用户目录互斥锁，已停止操作。"
            ) from exc

    def release(self) -> None:
        stream, self._stream = self._stream, None
        if stream is not None:
            # Closing a locked descriptor releases it on Windows and POSIX, including on exit.
            try:
                stream.close()
            finally:
                self._local.release()

    def __enter__(self) -> "FileMutex":
        if not self.acquire():
            raise CampusError(ErrorCode.BUSY, "另一个进程正在操作，请等待后重试。")
        return self

    def __exit__(self, *_args: object) -> None:
        self.release()
