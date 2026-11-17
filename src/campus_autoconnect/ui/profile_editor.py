"""Local form validation only; persistence belongs to ProfileService."""

import uuid
from dataclasses import replace
from urllib.parse import urlsplit

from PySide6.QtCore import QUrl
from PySide6.QtGui import QDesktopServices
from PySide6.QtWidgets import (
    QCheckBox,
    QDialog,
    QDialogButtonBox,
    QFileDialog,
    QFormLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QVBoxLayout,
)

from campus_autoconnect.core.errors import CampusError
from campus_autoconnect.core.models import NetworkProfile
from campus_autoconnect.core.portal import (
    bjut_wired_portal_supported,
    normalize_authority,
    normalize_bjut_endpoints,
    normalize_wired_portal,
    profile_setup_summary,
)
from campus_autoconnect.infrastructure.config import validate_profile
from campus_autoconnect.services.capture_analysis import capture_endpoints
from campus_autoconnect.ui.support_pages import CapturePanel


class ProfileEditor(QDialog):
    def __init__(
        self, parent=None, *, profile: NetworkProfile | None = None, current_ssid: str = ""
    ) -> None:
        super().__init__(parent)
        self.wired = bool(profile and profile.is_wired)
        if self.wired:
            self.setWindowTitle("配置有线登录")
        else:
            self.setWindowTitle("编辑 Wi-Fi 档案" if profile else "添加 Wi-Fi 档案")
        self.setMinimumWidth(530)
        self.profile = profile
        self.result_profile: NetworkProfile | None = None
        self.capture_panel: CapturePanel | None = None
        self._capturing = False
        layout = QVBoxLayout(self)
        form = QFormLayout()
        self.name_edit = QLineEdit(profile.display_name if profile else current_ssid)
        self.name_edit.setObjectName("profile_name")
        self.ssid_edit = QLineEdit(profile.ssid if profile else current_ssid)
        self.ssid_edit.setObjectName("profile_ssid")
        self.ref_edit = QLineEdit(profile.credential_ref if profile else "shared")
        self.ref_edit.setObjectName("profile_ref")
        self.hosts_edit = QLineEdit(", ".join(profile.trusted_portal_hosts) if profile else "")
        self.hosts_edit.setPlaceholderText("学校实测主机名，可含端口；逗号分隔")
        self.page_edit = QLineEdit(profile.portal_page_url if profile else "")
        self.page_edit.setPlaceholderText("实测认证页完整地址，以 /a79.htm 结尾")
        self.api_edit = QLineEdit(profile.bjut_api_origin if profile else "")
        self.api_edit.setPlaceholderText("实测认证服务地址，包含协议和端口，不含路径")
        self.capture_button = QPushButton("从脱敏抓包填写认证地址…")
        self.capture_button.clicked.connect(self._from_capture)
        self.allow_http = QCheckBox("允许本档案使用 HTTP 认证（账号密码将未加密传输）")
        self.allow_http.setChecked(profile.allow_http_auth if profile else False)
        self.allow_zero_mac = QCheckBox("允许本档案兼容认证页返回的全零 MAC（先手动测试）")
        self.allow_zero_mac.setObjectName("profile_allow_zero_mac")
        self.allow_zero_mac.setChecked(profile.allow_zero_mac if profile else False)
        self.enabled = QCheckBox("启用该档案")
        self.enabled.setChecked(profile.enabled if profile else True)
        self.auto_auth = QCheckBox("允许此档案自动认证（还需全局开关及后台）")
        self.auto_auth.setChecked(profile.auto_auth if profile else False)
        form.addRow("显示名称", self.name_edit)
        if not self.wired:
            form.addRow("SSID（精确匹配）", self.ssid_edit)
        form.addRow("凭据引用", self.ref_edit)
        if self.wired:
            self.page_edit.setPlaceholderText("https://学校网关/登录页")
            form.addRow("HTTPS 登录网址", self.page_edit)
            portal = QPushButton("打开填写的登录网址")
            portal.clicked.connect(self._open_wired_portal)
            form.addRow(portal)
        else:
            form.addRow("可信 HTTPS 主机", self.hosts_edit)
            form.addRow("认证页地址", self.page_edit)
            form.addRow("认证服务地址", self.api_edit)
            form.addRow(self.capture_button)
            form.addRow(self.allow_http)
            form.addRow(self.allow_zero_mac)
        form.addRow(self.enabled)
        form.addRow(self.auto_auth)
        layout.addLayout(form)
        self.setup_status = QLabel()
        self.setup_status.setWordWrap(True)
        layout.addWidget(self.setup_status)
        note = QLabel(
            "核对学校认证地址后保存。HTTP 兼容和全零 MAC 需分别确认。"
            "修改 SSID 或认证目标后，请重新核对许可和自动认证。"
        )
        note.setWordWrap(True)
        if self.wired:
            note.setText(
                "填入你确认的学校登录网址。档案通过当前物理网卡和 IPv4 网关匹配。"
                "保存后检查认证准备情况。"
            )
        layout.addWidget(note)
        self.buttons = QDialogButtonBox(QDialogButtonBox.Save | QDialogButtonBox.Cancel)
        self.buttons.button(QDialogButtonBox.Save).setText("保存并检查")
        self.buttons.button(QDialogButtonBox.Cancel).setText("取消")
        self.buttons.accepted.connect(self._save)
        self.buttons.rejected.connect(self.reject)
        layout.addWidget(self.buttons)
        self.page_edit.textChanged.connect(self._endpoint_changed)
        self.api_edit.textChanged.connect(self._endpoint_changed)
        self.ssid_edit.textChanged.connect(self._identity_changed)
        self.hosts_edit.textChanged.connect(self._identity_changed)
        self.allow_http.toggled.connect(self._permission_changed)
        self.allow_zero_mac.toggled.connect(self._permission_changed)
        self.enabled.toggled.connect(self._update_setup)
        self._update_setup()

    def add_live_capture(self) -> CapturePanel:
        panel = CapturePanel()
        self.layout().insertWidget(0, panel)
        self.capture_panel = panel
        return panel

    def set_capture_active(self, active: bool) -> None:
        self._capturing = active
        self.ssid_edit.setEnabled(not active)
        self.capture_button.setEnabled(not active)
        self.buttons.button(QDialogButtonBox.Save).setEnabled(not active)

    def reject(self) -> None:
        if self._capturing and self.capture_panel:
            self.capture_panel.stop.click()
            return
        super().reject()

    def _open_wired_portal(self) -> None:
        try:
            url, _ = normalize_wired_portal(self.page_edit.text().strip())
        except ValueError as exc:
            QMessageBox.warning(self, "登录网址无效", str(exc))
            return
        QDesktopServices.openUrl(QUrl(url))

    def _endpoint_changed(self, _text: str) -> None:
        self.allow_http.setChecked(False)
        self.allow_zero_mac.setChecked(False)
        self.auto_auth.setChecked(False)
        self._update_setup()

    def _identity_changed(self, _text: str) -> None:
        self.allow_zero_mac.setChecked(False)
        self.auto_auth.setChecked(False)
        self._update_setup()

    def _permission_changed(self, _checked: bool) -> None:
        self.auto_auth.setChecked(False)
        self._update_setup()

    def _update_setup(self, *_args) -> None:
        if self.wired:
            try:
                url, _ = normalize_wired_portal(self.page_edit.text().strip())
            except ValueError:
                self.auto_auth.setEnabled(False)
                self.setup_status.setText("请输入学校的 HTTPS 登录网址。")
                return
            supported = bjut_wired_portal_supported(url)
            self.auto_auth.setEnabled(supported)
            self.setup_status.setText(
                "保存后核对当前连接和北工大有线协议。"
                if supported
                else "此网址可保存并手动打开，自动认证协议待核对。"
            )
            return
        try:
            page, api = normalize_bjut_endpoints(
                self.page_edit.text().strip(), self.api_edit.text().strip()
            )
            hosts = tuple(
                normalize_authority(part.strip())
                for part in self.hosts_edit.text().replace("，", ",").split(",")
                if part.strip()
            )
            profile = NetworkProfile(
                "preview",
                "配置预览",
                "Preview",
                enabled=self.enabled.isChecked(),
                trusted_portal_hosts=hosts,
                portal_page_url=page,
                bjut_api_origin=api,
                allow_http_auth=self.allow_http.isChecked(),
                allow_zero_mac=self.allow_zero_mac.isChecked(),
            )
            summary = profile_setup_summary(profile)
        except (ValueError, TypeError):
            summary = "待补全：请填写同协议、同主机的实测认证页和服务地址，并核对端口。"
        self.setup_status.setText(summary + "\n保存后将对当前匹配的网络检查认证准备情况。")

    def _save(self) -> None:
        try:
            if self.wired and self.profile is not None:
                url, host = normalize_wired_portal(self.page_edit.text().strip())
                self.result_profile = validate_profile(
                    replace(
                        self.profile,
                        display_name=self.name_edit.text().strip(),
                        credential_ref=self.ref_edit.text().strip(),
                        enabled=self.enabled.isChecked(),
                        auto_auth=self.auto_auth.isChecked() and bjut_wired_portal_supported(url),
                        portal_page_url=url,
                        trusted_portal_hosts=(host,),
                        last_verified_at=None,
                    )
                )
                self.accept()
                return
            page, api = normalize_bjut_endpoints(
                self.page_edit.text().strip(), self.api_edit.text().strip()
            )
            hosts = tuple(
                normalize_authority(part.strip())
                for part in self.hosts_edit.text().replace("，", ",").split(",")
                if part.strip()
            )
            profile = NetworkProfile(
                profile_id=self.profile.profile_id if self.profile else uuid.uuid4().hex,
                display_name=self.name_edit.text().strip(),
                ssid=self.ssid_edit.text(),
                enabled=self.enabled.isChecked(),
                auto_auth=self.auto_auth.isChecked(),
                credential_ref=self.ref_edit.text().strip(),
                trusted_portal_hosts=hosts,
                portal_page_url=page,
                bjut_api_origin=api,
                allow_http_auth=self.allow_http.isChecked(),
                allow_zero_mac=self.allow_zero_mac.isChecked(),
                # Any edit invalidates the previous manual verification timestamp.
                last_verified_at=None,
            )
            self.result_profile = validate_profile(profile)
        except (ValueError, TypeError) as exc:
            QMessageBox.warning(self, "档案无效", str(exc))
            return
        self.accept()

    def _from_capture(self) -> None:
        from pathlib import Path

        path, _ = QFileDialog.getOpenFileName(self, "选择本人脱敏登录抓包", "", "JSON (*.json)")
        if not path:
            return
        try:
            page, api = capture_endpoints(Path(path))
        except CampusError as exc:
            QMessageBox.warning(self, "无法填写认证地址", exc.message)
            return
        self.apply_capture(page, api)

    def apply_capture(self, page: str, api: str, ssid: str = "") -> None:
        if ssid and not self.ssid_edit.text():
            self.ssid_edit.setText(ssid)
        if ssid and not self.name_edit.text():
            self.name_edit.setText(ssid)
        self.page_edit.setText(page)
        self.api_edit.setText(api)
        hosts = dict.fromkeys(
            parts.netloc for parts in map(urlsplit, (page, api)) if parts.scheme == "https"
        )
        self.hosts_edit.setText(", ".join(hosts))
        self.allow_http.setChecked(False)
        self.allow_zero_mac.setChecked(False)
        self.auto_auth.setChecked(False)
