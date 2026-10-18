"""Small M2 settings panel; background work remains outside Qt widgets."""

from datetime import datetime

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QCheckBox, QGroupBox, QHBoxLayout, QLabel, QPushButton, QVBoxLayout

from campus_autoconnect.core.models import AUTH_STAGE_LABELS

_LABELS = {
    "STARTING": "正在启动",
    "STOPPED": "已停止",
    "DISABLED": "自动认证已关闭",
    "WAITING_NETWORK": "等待网络",
    "WAITING_READY": "等待网络稳定",
    "UNTRUSTED": "无可信档案",
    "SUSPENDED": "已挂起",
    "CHECKING": "正在检测或认证",
    "CANCELLING": "正在取消",
    "BACKOFF": "等待有限重试",
    "ONLINE": "互联网可用",
    "BLOCKED": "已停止自动尝试",
    "UNAVAILABLE": "状态暂不可用",
}


class AutomationPanel(QGroupBox):
    def __init__(self) -> None:
        super().__init__("自动认证与登录启动")
        self._dirty = False
        layout = QVBoxLayout(self)
        self.startup_enabled = QCheckBox("登录 Windows 后自动启动到托盘")
        self.startup_enabled.setEnabled(False)
        layout.addWidget(self.startup_enabled)
        options = QHBoxLayout()
        self.enabled = QCheckBox("全局允许自动认证")
        self.enabled.setObjectName("automation_enabled")
        self.save_button = QPushButton("仅保存开关")
        self.save_start_button = QPushButton("保存并启动后台")
        self.refresh_button = QPushButton("刷新后台和启动状态")
        self.save_button.setEnabled(False)
        self.save_start_button.setEnabled(False)
        self.enabled.setEnabled(False)
        self.enabled.toggled.connect(self._mark_dirty)
        for widget in (self.enabled, self.save_button, self.save_start_button, self.refresh_button):
            options.addWidget(widget)
        layout.addLayout(options)
        self.advanced_toggle = QCheckBox("显示后台与旧版启动高级操作")
        layout.addWidget(self.advanced_toggle)
        self.advanced = QGroupBox("后台控制与启动迁移")
        actions = QHBoxLayout(self.advanced)
        self.advanced.setVisible(False)
        self.advanced_toggle.toggled.connect(self.advanced.setVisible)
        self.start_button = QPushButton("启动后台")
        self.stop_button = QPushButton("停止后台")
        self.startup_enable_button = QPushButton("启用登录启动")
        self.startup_repair_button = QPushButton("修复旧版登录启动到当前版本")
        self.startup_repair_button.setEnabled(False)
        self.startup_disable_button = QPushButton("关闭登录启动")
        for widget in (
            self.start_button,
            self.stop_button,
            self.startup_enable_button,
            self.startup_repair_button,
            self.startup_disable_button,
        ):
            actions.addWidget(widget)
        layout.addWidget(self.advanced)
        self.status = QLabel("尚未刷新；全局开关默认关闭。")
        self.status.setTextFormat(Qt.PlainText)
        self.status.setWordWrap(True)
        layout.addWidget(self.status)
        hint = QLabel(
            "全局开关和当前档案均允许才会自动尝试。临时故障最多 3 次，安全或协议错误即停止。\n"
            "“仅保存开关”不启动后台；勾选后可点击“保存并启动后台”。\n"
            "登录启动创建托盘并复用现有后台；自动认证许可单独控制。\n"
            "旧版登录任务需在高级操作主动修复到当前程序；保留原启用状态，不立即运行任务。\n"
            "收起到托盘后后台继续运行；“退出程序”会停止后台。"
        )
        hint.setWordWrap(True)
        layout.addWidget(hint)

    def show_status(self, overview: dict) -> None:
        if not self._dirty:
            self.enabled.blockSignals(True)
            self.enabled.setChecked(overview["enabled"])
            self.enabled.blockSignals(False)
        self.enabled.setEnabled(True)
        self.save_button.setEnabled(True)
        self.save_start_button.setEnabled(True)
        monitor, startup = overview["monitor"], overview["startup"]
        self.startup_enabled.blockSignals(True)
        self.startup_enabled.setChecked(bool(startup.get("enabled")))
        self.startup_enabled.blockSignals(False)
        self.startup_enabled.setEnabled(
            startup.get("available", True)
            and not (startup.get("installed") and not startup.get("owned"))
        )
        startup_label = (
            ("已启用" if startup.get("enabled") else "已关闭")
            if startup.get("available", True)
            else "暂不可查询"
        )
        repairable = bool(
            startup.get("installed") and startup.get("owned") and not startup.get("configured")
        )
        self.startup_repair_button.setEnabled(repairable)
        if startup.get("installed") and not startup.get("owned"):
            startup_label = "同名任务归属无法确认，已禁止修复或覆盖"
        elif repairable:
            startup_label = (
                "本应用旧版任务与当前程序不一致；展开高级操作，修复旧版登录启动到当前版本"
            )
        elif not startup.get("installed") and startup.get("available", True):
            startup_label = "未安装；勾选“登录 Windows 后自动启动到托盘”"
        elif startup.get("executable_exists") is False and startup.get("owned"):
            startup_label = "任务目标已不存在；请修复登录启动到当前版本"
        last_run = "尚无运行记录"
        if stamp := startup.get("last_run_at"):
            try:
                last_run = datetime.fromisoformat(stamp).astimezone().strftime("%Y-%m-%d %H:%M:%S")
            except (ValueError, TypeError):
                last_run = "记录无效"
        result = startup.get("last_result")
        run_label = "正在运行" if startup.get("running") else "未在运行"
        if result == "0x00000000":
            result_label = "上次进程正常退出"
        elif result == "0x00041301":
            result_label = "任务正在运行"
        else:
            result_label = result or "未记录"
        self.status.setText(
            f"后台：{_LABELS.get(monitor['state'], '状态待确认')}（{monitor['state']}）"
            f" · {monitor['error_code']}    登录启动：{startup_label}\n"
            f"已保存的全局自动认证：{'开启' if overview['enabled'] else '关闭'}"
            f"    认证流程次数：{monitor.get('attempts', 0)}/{monitor.get('max_attempts', 3)}"
            f"    后台上次流程（UTC）：{monitor.get('last_checked_at') or '—'}"
            f"\n登录任务：{run_label}；最近启动（本地）：{last_run}；结果：{result_label}。"
            "任务运行状态不代表已完成校园网认证。"
        )
        progress = monitor.get("last_authentication")
        if progress:
            self.status.setText(
                self.status.text()
                + "\n上次流程步骤："
                + AUTH_STAGE_LABELS.get(progress.get("stage"), "未记录")
                + "；登录请求："
                + {True: "已尝试发起", False: "未发起", None: "未记录"}.get(
                    progress.get("login_request_attempted"), "未记录"
                )
            )
        if monitor["state"] == "BLOCKED":
            self.status.setText(
                self.status.text()
                + "\n已锁止，本计数不代表服务器登录次数。先修复具体原因；档案修改后会重新评估，"
                "必要时停止后台并确认停止后重新启动。"
            )
        elif overview["enabled"] and monitor["state"] == "STOPPED":
            self.status.setText(
                self.status.text()
                + "\n全局许可已保存，但后台未运行，当前不会自动认证。点击“启动后台”，"
                "并确认当前档案也允许自动认证；建议先完成一次手动测试。"
            )

    def _mark_dirty(self, _: bool) -> None:
        self._dirty = True

    def mark_saved(self) -> None:
        self._dirty = False
