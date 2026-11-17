"""Credential input and a separately masked, on-demand view of the saved record."""

from PySide6.QtCore import Qt, QTimer, Signal
from PySide6.QtWidgets import (
    QFormLayout,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QVBoxLayout,
)

from campus_autoconnect.core.models import Credentials
from campus_autoconnect.services.credential_management import CredentialStatus


class CredentialsPanel(QGroupBox):
    reveal_requested = Signal()

    def __init__(self, parent=None) -> None:
        super().__init__("认证账户 · Windows 安全存储", parent)
        layout = QVBoxLayout(self)
        form = QFormLayout()
        self.reference = QLineEdit("shared")
        self.reference.setObjectName("credential_ref")
        self.username = QLineEdit()
        self.username.setObjectName("username")
        self.username.setPlaceholderText("请输入要新增或更新的账号")
        self.password = QLineEdit()
        self.password.setObjectName("password")
        self.password.setEchoMode(QLineEdit.Password)
        self.password.setPlaceholderText("输入新密码后点击保存 / 更新")
        form.addRow("凭据引用", self.reference)
        self.saved_username = QLabel("********")
        self.saved_password = QLabel("********")
        for label in (self.saved_username, self.saved_password):
            label.setTextFormat(Qt.PlainText)
            label.setWordWrap(True)
        self.saved_username.setObjectName("saved_username")
        self.saved_password.setObjectName("saved_password")
        self.reveal_button = QPushButton("显示")
        self.reveal_button.setObjectName("reveal_saved_credentials")
        self.reveal_button.setToolTip("按住显示已保存的账号密码，点击隐藏收起")
        self.reveal_revision = 0
        self._revealed, self._hide_on_release, self._absent = False, False, False
        self._hold = QTimer(self)
        self._hold.setSingleShot(True)
        self._hold.setInterval(400)
        self._hold.timeout.connect(self._request_reveal)
        self.reveal_button.pressed.connect(self._reveal_pressed)
        self.reveal_button.released.connect(self._reveal_released)
        form.addRow("已保存账号", self.saved_username)
        form.addRow("已保存密码", self.saved_password)
        saved_actions = QHBoxLayout()
        saved_actions.addWidget(self.reveal_button)
        saved_actions.addWidget(QLabel("按住显示，点击隐藏"))
        saved_actions.addStretch()
        form.addRow(saved_actions)
        form.addRow("新账号", self.username)
        form.addRow("新密码", self.password)
        layout.addLayout(form)
        buttons = QHBoxLayout()
        self.save_button = QPushButton("保存 / 更新凭据")
        self.save_button.setObjectName("save_credentials")
        self.delete_button = QPushButton("删除凭据")
        self.check_button = QPushButton("检查是否已保存")
        buttons.addWidget(self.save_button)
        buttons.addWidget(self.delete_button)
        buttons.addWidget(self.check_button)
        buttons.addStretch()
        layout.addLayout(buttons)
        self.status = QLabel(
            "尚未检查当前 Windows 记录；输入框为空不表示没有保存。多个档案可使用 shared 共享账户。"
        )
        self.status.setWordWrap(True)
        layout.addWidget(self.status)
        self.status.setTextFormat(Qt.PlainText)
        self.draft = QLabel("输入框用于新增或更新；留空不会删除已有凭据。")
        self.draft.setWordWrap(True)
        layout.addWidget(self.draft)
        for entry in (self.username, self.password):
            entry.textEdited.connect(
                lambda _: self.draft.setText("有尚未保存的修改；存储状态与本次输入分别显示。")
            )

    def _reveal_pressed(self) -> None:
        self._hide_on_release = self._revealed
        if not self._revealed:
            self._hold.start()

    def _reveal_released(self) -> None:
        self._hold.stop()
        if self._hide_on_release:
            self.hide_saved()

    def _request_reveal(self) -> None:
        if self.reveal_button.isDown() and self.isVisible():
            self.reveal_requested.emit()

    def set_saved_status(self, status: CredentialStatus | None) -> None:
        self._absent = bool(status and status.state == "absent" and not status.historical)
        self.hide_saved()

    def show_saved(self, value: Credentials) -> None:
        self._revealed = True
        self.saved_username.setText(value.username)
        self.saved_password.setText(value.password)
        self.reveal_button.setText("隐藏")

    def hide_saved(self) -> None:
        self._hold.stop()
        self.reveal_revision += 1
        self._revealed = self._hide_on_release = False
        placeholder = "—" if self._absent else "********"
        self.saved_username.setText(placeholder)
        self.saved_password.setText(placeholder)
        self.reveal_button.setText("显示")

    def hideEvent(self, event) -> None:
        self.hide_saved()
        super().hideEvent(event)
