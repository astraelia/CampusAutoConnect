"""Current-user GUI singleton with fixed show/boot messages and no arbitrary payload."""

import hashlib
from pathlib import Path

from PySide6.QtCore import QObject, QTimer, Signal, Slot
from PySide6.QtNetwork import QLocalServer, QLocalSocket

from campus_autoconnect.core.errors import CampusError
from campus_autoconnect.core.models import ErrorCode
from campus_autoconnect.infrastructure.locking import FileMutex


class GuiInstance(QObject):
    activated = Signal()
    startup_requested = Signal()

    def __init__(self, directory: Path) -> None:
        super().__init__()
        identity = hashlib.sha256(str(directory.resolve()).encode("utf-8")).hexdigest()[:24]
        self.name = "CampusAutoConnect-GUI-" + identity
        self.mutex = FileMutex(directory / "gui.lock")
        self.server = QLocalServer(self)
        self.server.setSocketOptions(QLocalServer.UserAccessOption)
        self.server.setMaxPendingConnections(4)
        self.server.newConnection.connect(self._activate)
        self._connections: set[QLocalSocket] = set()

    def acquire(self, *, activate: bool = True) -> bool:
        if not self.mutex.acquire():
            socket = QLocalSocket(self)
            socket.connectToServer(self.name)
            if socket.waitForConnected(1500):
                socket.write(b"show" if activate else b"boot")
                socket.waitForBytesWritten(1000)
                socket.disconnectFromServer()
                socket.deleteLater()
                return False
            socket.deleteLater()
            raise CampusError(ErrorCode.BUSY, "主窗口正在启动或退出，请稍候再次打开。")
        QLocalServer.removeServer(self.name)
        if not self.server.listen(self.name):
            self.mutex.release()
            raise CampusError(ErrorCode.BUSY, "无法创建当前用户窗口通信服务。")
        return True

    def _activate(self) -> None:
        while self.server.hasPendingConnections():
            socket = self.server.nextPendingConnection()
            if len(self._connections) >= 4:
                socket.abort()
                socket.deleteLater()
                continue
            socket.setParent(self)
            self._connections.add(socket)
            socket.setReadBufferSize(16)
            socket.readyRead.connect(self._receive)
            socket.disconnected.connect(self._disconnected)
            timeout = QTimer(socket)
            timeout.setSingleShot(True)
            timeout.timeout.connect(socket.disconnectFromServer)
            timeout.start(2000)
            if socket.bytesAvailable():
                self._read_socket(socket)

    @Slot()
    def _receive(self) -> None:
        socket = self.sender()
        if isinstance(socket, QLocalSocket):
            self._read_socket(socket)

    def _read_socket(self, socket: QLocalSocket) -> None:
        if socket.bytesAvailable() < 4:
            return
        message = bytes(socket.read(16))
        if message == b"show":
            self.activated.emit()
        elif message == b"boot":
            self.startup_requested.emit()
        socket.disconnectFromServer()

    @Slot()
    def _disconnected(self) -> None:
        socket = self.sender()
        if isinstance(socket, QLocalSocket):
            self._connections.discard(socket)
            socket.deleteLater()

    def close(self) -> None:
        self.server.close()
        for socket in tuple(self._connections):
            socket.readyRead.disconnect(self._receive)
            socket.disconnected.disconnect(self._disconnected)
            socket.abort()
            socket.deleteLater()
        self._connections.clear()
        self.mutex.release()
