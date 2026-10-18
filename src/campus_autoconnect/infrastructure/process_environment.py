"""Restore system DLL lookup for Windows system tools launched by a frozen app."""

import ctypes
import os
import sys
import threading
from collections.abc import Iterator
from contextlib import contextmanager

_DLL_LOCK = threading.RLock()


@contextmanager
def system_process_environment() -> Iterator[dict[str, str]]:
    environment = dict(os.environ)
    bundle = getattr(sys, "_MEIPASS", None)
    if os.name != "nt" or not bundle:
        yield environment
        return
    environment["PATH"] = os.pathsep.join(
        entry
        for entry in environment.get("PATH", "").split(os.pathsep)
        if not os.path.normcase(os.path.abspath(entry)).startswith(
            os.path.normcase(os.path.abspath(bundle)) + os.sep
        )
        and os.path.normcase(os.path.abspath(entry)) != os.path.normcase(os.path.abspath(bundle))
    )
    with _DLL_LOCK:
        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        setter = kernel.SetDllDirectoryW
        setter.argtypes = [ctypes.c_wchar_p]
        setter.restype = ctypes.c_int
        getter = kernel.GetDllDirectoryW
        getter.argtypes = [ctypes.c_uint32, ctypes.c_wchar_p]
        getter.restype = ctypes.c_uint32
        size = getter(0, None)
        buffer = ctypes.create_unicode_buffer(size + 1)
        getter(len(buffer), buffer)
        previous = buffer.value
        if not setter(None):
            raise OSError("System DLL search reset failed")
        try:
            yield environment
        finally:
            if not setter(previous or None):
                raise OSError("DLL search restore failed")
