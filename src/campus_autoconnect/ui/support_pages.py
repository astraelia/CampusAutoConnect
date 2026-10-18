"""Native diagnostic/capture controls and searchable offline help."""

from pathlib import Path

from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QPalette
from PySide6.QtWidgets import (
    QApplication,
    QCheckBox,
    QFormLayout,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QListWidget,
    QPlainTextEdit,
    QPushButton,
    QSpinBox,
    QSplitter,
    QTextBrowser,
    QVBoxLayout,
    QWidget,
)

from campus_autoconnect.infrastructure.report_maintenance import ReportPolicy


class ReportSettingsPanel(QGroupBox):
    def __init__(self) -> None:
        super().__init__("报告保存与自动清理")
        self._dirty = False
        layout = QVBoxLayout(self)
        self.enabled = QCheckBox("自动清理已结束的诊断报告")
        self.enabled.setChecked(True)
        self.include_capture = QCheckBox("同时清理网页抓包原件（默认保留）")
        self.protected = QCheckBox("保留当前报告，不参与自动清理")
        self.days, self.count, self.size = QSpinBox(), QSpinBox(), QSpinBox()
        for widget, low, high, value, suffix in (
            (self.days, 1, 365, 7, " 天"),
            (self.count, 1, 1000, 20, " 组"),
            (self.size, 1, 1024, 50, " MiB"),
        ):
            widget.setRange(low, high)
            widget.setValue(value)
            widget.setSuffix(suffix)
            widget.valueChanged.connect(self._mark_dirty)
        self.enabled.toggled.connect(self._mark_dirty)
        self.include_capture.toggled.connect(self._mark_dirty)
        form = QFormLayout()
        form.addRow("保留期限", self.days)
        form.addRow("最多保留", self.count)
        form.addRow("容量上限", self.size)
        layout.addWidget(self.enabled)
        layout.addLayout(form)
        layout.addWidget(self.include_capture)
        layout.addWidget(self.protected)
        row = QHBoxLayout()
        self.save = QPushButton("保存清理设置")
        self.refresh = QPushButton("刷新报告统计")
        self.cleanup = QPushButton("预览并清理过期报告…")
        for button in (self.save, self.refresh, self.cleanup):
            row.addWidget(button)
        layout.addLayout(row)
        self.status = QLabel("尚未检查报告目录。日常连接默认不保存完整报告。")
        self.status.setWordWrap(True)
        self.status.setTextFormat(Qt.PlainText)
        layout.addWidget(self.status)
        hint = QLabel(
            "程序启动时及持续运行每 24 小时检查；旧报告首次先预览确认。"
            "数量和容量上限适用于可清理报告，活动、保留标记和未纳入的抓包会话除外。"
        )
        hint.setWordWrap(True)
        layout.addWidget(hint)

    def _mark_dirty(self, *_) -> None:
        self._dirty = True

    def policy(self) -> ReportPolicy:
        return ReportPolicy(
            self.enabled.isChecked(),
            self.days.value(),
            self.count.value(),
            self.size.value() * 1024 * 1024,
            self.include_capture.isChecked(),
        )

    def show_status(self, status: dict) -> None:
        if not self._dirty:
            policy = status["policy"]
            for widget, value in (
                (self.enabled, policy["enabled"]),
                (self.include_capture, policy["include_capture"]),
            ):
                widget.blockSignals(True)
                widget.setChecked(value)
                widget.blockSignals(False)
            for widget, value in (
                (self.days, policy["days"]),
                (self.count, policy["max_sessions"]),
                (self.size, policy["max_bytes"] // (1024 * 1024)),
            ):
                widget.blockSignals(True)
                widget.setValue(value)
                widget.blockSignals(False)
        result = status.get("last_result")
        last = (
            f"上次清理 {result['deleted']} 组，失败 {result['failed']} 组。"
            if result
            else "尚未执行清理。"
        )
        self.status.setText(
            f"共 {status['session_count']} 组，"
            f"占用 {status['total_bytes'] / (1024 * 1024):.2f} MiB；"
            f"旧报告 {status['legacy_count']} 组，保留 {status['protected_count']} 组，"
            f"含抓包 {status['capture_count']} 组；"
            f"活动/异常跳过 {status['active'] + status['skipped']} 组。\n"
            + last
            + f" 下次检查（UTC）：{status.get('next_check_at') or '启动或下次轮询时'}"
        )


class DiagnosticPanel(QWidget):
    def __init__(self) -> None:
        super().__init__()
        layout = QVBoxLayout(self)
        text = QLabel(
            "主程序实际记录、独立复查和浏览器抓包分别注明来源。深入诊断只核对页面与实时配置，不读取凭据、不登录。"
        )
        text.setWordWrap(True)
        layout.addWidget(text)
        self.begin = QPushButton("开始监测")
        self.inspect = QPushButton("独立分步复查")
        self.deep = QPushButton("深入诊断（不登录）")
        self.finish = QPushButton("结束监测并保存")
        self.copy = QPushButton("复制脱敏监测报告")
        self.open = QPushButton("打开报告目录")
        self.fix = QPushButton("前往当前问题的处理页面")
        for group in ((self.begin, self.inspect, self.deep), (self.finish, self.copy, self.open)):
            row = QHBoxLayout()
            for button in group:
                row.addWidget(button)
            layout.addLayout(row)
        self.path = QLabel("报告：尚未保存。")
        self.path.setTextFormat(Qt.PlainText)
        self.path.setWordWrap(True)
        layout.addWidget(self.path)
        layout.addWidget(self.fix)
        self.output = QPlainTextEdit()
        self.output.setReadOnly(True)
        layout.addWidget(self.output)


class CapturePanel(QWidget):
    def __init__(self) -> None:
        super().__init__()
        layout = QVBoxLayout(self)
        text = QLabel(
            "网页对照：开始后自动打开专用 Edge/Chrome 并访问已配置认证页；"
            "无有效档案时请求 HTTP 探测页发现 Portal。请自行确认学校页面。"
            "只记录该浏览器；主程序连接记录见诊断页。"
        )
        text.setWordWrap(True)
        layout.addWidget(text)
        row = QHBoxLayout()
        self.start = QPushButton("开始抓包并自动打开认证页")
        self.probe = QPushButton("重新打开认证页")
        self.stop = QPushButton("停止抓包并保存")
        self.retry = QPushButton("重试保存抓包")
        self.probe.setEnabled(False)
        self.stop.setEnabled(False)
        self.retry.setEnabled(False)
        for button in (self.start, self.probe, self.stop):
            row.addWidget(button)
        layout.addLayout(row)
        layout.addWidget(self.retry)
        self.state = QLabel("尚未抓包；无需断开或重连 Wi-Fi。")
        self.state.setWordWrap(True)
        layout.addWidget(self.state)
        self.output = QPlainTextEdit()
        self.output.setReadOnly(True)
        layout.addWidget(self.output)


class HelpPanel(QWidget):
    navigate = Signal(str)

    def __init__(self) -> None:
        super().__init__()
        layout = QVBoxLayout(self)
        self.search = QLineEdit()
        self.search.setPlaceholderText("搜索教程或故障，例如：凭据、HTTP、自启动、抓包")
        layout.addWidget(self.search)
        splitter = QSplitter()
        self.topics = QListWidget()
        self.reader = QTextBrowser()
        self.reader.setOpenLinks(False)
        self.reader.setOpenExternalLinks(False)
        splitter.addWidget(self.topics)
        splitter.addWidget(self.reader)
        splitter.setStretchFactor(1, 3)
        splitter.setSizes([190, 620])
        layout.addWidget(splitter, 1)
        row = QHBoxLayout()
        self.previous = QPushButton("上一步")
        self.next = QPushButton("下一步")
        for button in (self.previous, self.next):
            row.addWidget(button)
        layout.addLayout(row)
        source = Path(__file__).parents[1] / "assets" / "help.md"
        content = source.read_text(encoding="utf-8")
        self.chapters: list[tuple[str, str]] = []
        for section in content.split("\n## ")[1:]:
            title, _, body = section.partition("\n")
            self.chapters.append((title, "## " + title + "\n" + body))
        self.search.textChanged.connect(self.filter)
        self.topics.currentRowChanged.connect(self.display)
        self.reader.anchorClicked.connect(self.link)
        self.previous.clicked.connect(
            lambda: self.topics.setCurrentRow(max(0, self.topics.currentRow() - 1))
        )
        self.next.clicked.connect(
            lambda: self.topics.setCurrentRow(
                min(self.topics.count() - 1, self.topics.currentRow() + 1)
            )
        )
        self.filter("")
        QApplication.instance().paletteChanged.connect(self.refresh_colors)

    def filter(self, text: str) -> None:
        self.filtered = [
            (title, body) for title, body in self.chapters if text.casefold() in body.casefold()
        ]
        self.topics.clear()
        self.topics.addItems([title for title, _ in self.filtered])
        if self.filtered:
            self.topics.setCurrentRow(0)
        else:
            self.reader.setPlainText("未找到匹配章节，请更换关键词。")

    def display(self, row: int) -> None:
        if 0 <= row < len(self.filtered):
            color = QApplication.palette().color(QPalette.Link).name()
            self.reader.document().setDefaultStyleSheet(f"a {{ color: {color}; }}")
            self.reader.setMarkdown(self.filtered[row][1])
        self.previous.setEnabled(row > 0)
        self.next.setEnabled(0 <= row < len(self.filtered) - 1)

    def refresh_colors(self, _palette) -> None:
        position = self.reader.verticalScrollBar().value()
        self.display(self.topics.currentRow())
        self.reader.verticalScrollBar().setValue(position)

    def link(self, url) -> None:
        if url.scheme() == "page" and url.path() in {
            "overview",
            "profiles",
            "credentials",
            "automation",
            "logs",
            "capture",
            "settings",
            "help",
        }:
            self.navigate.emit(url.path())
        elif url.fragment():
            self.reader.scrollToAnchor(url.fragment())
