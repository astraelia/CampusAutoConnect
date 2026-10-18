"""Bounded reads serialized with writers: Windows replacement needs closed readers."""

from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import BinaryIO

from campus_autoconnect.infrastructure.locking import FileMutex


@contextmanager
def _open_shared(path: Path) -> Iterator[BinaryIO]:
    with (
        FileMutex(path.with_suffix(path.suffix + ".io.lock"), timeout=1.0),
        path.open("rb") as stream,
    ):
        yield stream


def read_text_shared(path: Path, max_bytes: int) -> str:
    with _open_shared(path) as stream:
        raw = stream.read(max_bytes + 1)
    if len(raw) > max_bytes:
        raise ValueError("文件超过大小上限。")
    return raw.decode("utf-8")
