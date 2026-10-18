"""Credential input widget: no saved-password display and no protocol logic."""

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QFormLayout,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QVBoxLayout,
)


class CredentialsPanel(QGroupBox):
    def __init__(self, parent=None) -> None:
        super().__init__("认证账户 · Windows 安全存储", parent)
        layout = QVBoxLayout(self)
        form = QFormLayout()
        self.reference = QLineEdit("shared")
        self.reference.setObjectName("credential_ref")
        self.username = QLineEdit()
        self.username.setObjectName("username")
        self.username.setPlaceholderText("纯账号或带一次正确后缀的完整账号；已保存内容不回显")
        self.password = QLineEdit()
        self.password.setObjectName("password")
        self.password.setEchoMode(QLineEdit.Password)
        self.password.setPlaceholderText("输入新密码后点击保存 / 更新")
        form.addRow("凭据引用", self.reference)
        form.addRow("校园网账号", self.username)
        form.addRow("校园网密码", self.password)
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
