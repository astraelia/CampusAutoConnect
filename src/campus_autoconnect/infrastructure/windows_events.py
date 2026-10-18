"""Native notifications with no message pump, network mutation or payload logging.

Callbacks only invalidate pending work and wake the runtime. Periodic snapshots remain
necessary: notification registration can fail and notifications can be coalesced/lost.
"""

import ctypes
import os
from collections.abc import Callable

_DWORD = ctypes.c_uint32
_PTR = ctypes.c_void_p
_FAILED_REFERENCES: list[object] = []


class _Notification(ctypes.Structure):
    _fields_ = [
        ("source", _DWORD),
        ("code", _DWORD),
        ("guid", ctypes.c_ubyte * 16),
        ("size", _DWORD),
        ("data", _PTR),
    ]


class WindowsEventSource:
    def __init__(self) -> None:
        self.warnings: tuple[str, ...] = ()
        self._cleanups: list[Callable[[], int]] = []
        self._references: list[object] = []
        self._started = False

    def start(self, notify: Callable[[str], None]) -> None:
        if self._started:
            raise ValueError("事件监听已启动。")
        self._started = True
        warnings = []
        if os.name != "nt":
            self.warnings = ("windows_notifications_unavailable",)
            return
        for name, subscribe in (
            ("wlan", self._wlan),
            ("ip", self._ip),
            ("power", self._power),
        ):
            try:
                subscribe(notify)
            except (OSError, AttributeError):
                warnings.append(f"{name}_notifications_unavailable")
        self.warnings = tuple(warnings)

    def _wlan(self, notify: Callable[[str], None]) -> None:
        dll = ctypes.WinDLL("wlanapi.dll")
        callback_type = ctypes.WINFUNCTYPE(None, ctypes.POINTER(_Notification), _PTR)

        def received(data, _context) -> None:
            # ACM connection/profile/interface events only. Ignore periodic scan notifications.
            if (
                data
                and data.contents.source & 8
                and data.contents.code in {5, 9, 10, 11, 13, 14, 15, 16, 20, 21, 27}
            ):
                notify("network")

        callback = callback_type(received)
        dll.WlanOpenHandle.argtypes = [_DWORD, _PTR, ctypes.POINTER(_DWORD), ctypes.POINTER(_PTR)]
        dll.WlanOpenHandle.restype = _DWORD
        dll.WlanRegisterNotification.argtypes = [
            _PTR,
            _DWORD,
            ctypes.c_int32,
            callback_type,
            _PTR,
            _PTR,
            ctypes.POINTER(_DWORD),
        ]
        dll.WlanRegisterNotification.restype = _DWORD
        dll.WlanCloseHandle.argtypes = [_PTR, _PTR]
        dll.WlanCloseHandle.restype = _DWORD
        handle, version = _PTR(), _DWORD()
        if dll.WlanOpenHandle(2, None, ctypes.byref(version), ctypes.byref(handle)):
            raise OSError
        if dll.WlanRegisterNotification(handle, 8, True, callback, None, None, None):
            dll.WlanCloseHandle(handle, None)
            raise OSError
        self._references.extend((dll, callback))
        # Closing waits for active callbacks and unregisters; never call from a callback.
        self._cleanups.append(lambda: dll.WlanCloseHandle(handle, None))

    def _ip(self, notify: Callable[[str], None]) -> None:
        dll = ctypes.WinDLL("iphlpapi.dll")
        callback_type = ctypes.WINFUNCTYPE(None, _PTR, _PTR, _DWORD)
        callback = callback_type(lambda _context, _row, _kind: notify("network"))
        dll.CancelMibChangeNotify2.argtypes = [_PTR]
        dll.CancelMibChangeNotify2.restype = _DWORD
        self._references.extend((dll, callback))
        failed = False
        for name in (
            "NotifyIpInterfaceChange",
            "NotifyRouteChange2",
            "NotifyUnicastIpAddressChange",
        ):
            subscribe = getattr(dll, name)
            subscribe.argtypes = [
                ctypes.c_uint16,
                callback_type,
                _PTR,
                ctypes.c_ubyte,
                ctypes.POINTER(_PTR),
            ]
            subscribe.restype = _DWORD
            handle = _PTR()
            if subscribe(0, callback, None, False, ctypes.byref(handle)):
                failed = True
            else:
                self._cleanups.append(lambda handle=handle: dll.CancelMibChangeNotify2(handle))
        if failed:
            raise OSError

    def _power(self, notify: Callable[[str], None]) -> None:
        dll = ctypes.WinDLL("powrprof.dll")
        callback_type = ctypes.WINFUNCTYPE(_DWORD, _PTR, _DWORD, _PTR)

        def received(_context, kind, _setting) -> int:
            if kind == 4:  # PBT_APMSUSPEND
                notify("suspend")
            elif kind in {7, 18}:  # PBT_APMRESUMESUSPEND / PBT_APMRESUMEAUTOMATIC
                notify("resume")
            return 0

        class Parameters(ctypes.Structure):
            _fields_ = [("callback", callback_type), ("context", _PTR)]

        callback = callback_type(received)
        parameters = Parameters(callback, None)
        dll.PowerRegisterSuspendResumeNotification.argtypes = [_DWORD, _PTR, ctypes.POINTER(_PTR)]
        dll.PowerRegisterSuspendResumeNotification.restype = _DWORD
        dll.PowerUnregisterSuspendResumeNotification.argtypes = [_PTR]
        dll.PowerUnregisterSuspendResumeNotification.restype = _DWORD
        handle = _PTR()
        if dll.PowerRegisterSuspendResumeNotification(
            2, ctypes.byref(parameters), ctypes.byref(handle)
        ):
            raise OSError
        self._references.extend((dll, callback, parameters))
        self._cleanups.append(lambda: dll.PowerUnregisterSuspendResumeNotification(handle))

    def close(self) -> None:
        failed = False
        for cleanup in reversed(self._cleanups):
            try:
                failed |= bool(cleanup())
            except OSError:
                failed = True
        self._cleanups.clear()
        if failed:
            self.warnings += ("notification_cleanup_failed",)
            # A native callback must remain valid even if unregister failed and this object dies.
            _FAILED_REFERENCES.extend(self._references)
