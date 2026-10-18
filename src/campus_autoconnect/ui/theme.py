"""Qt palettes and the unmodified supplied icon; no business dependencies."""

from pathlib import Path

from PySide6.QtGui import QColor, QIcon, QPalette
from PySide6.QtWidgets import QApplication


def app_icon() -> QIcon:
    return QIcon(str(Path(__file__).resolve().parents[1] / "assets" / "app.ico"))


def apply_theme(app: QApplication, theme: str) -> None:
    from PySide6.QtCore import Qt

    app.setProperty("campus_theme", theme)
    if theme == "system":
        app.styleHints().unsetColorScheme()
        dark = app.styleHints().colorScheme() == Qt.ColorScheme.Dark
    else:
        dark = theme == "dark"
        app.styleHints().setColorScheme(Qt.ColorScheme.Dark if dark else Qt.ColorScheme.Light)
    palette = QPalette()
    colors = {
        QPalette.Window: "#18212e" if dark else "#f2f5fa",
        QPalette.WindowText: "#eef3fa" if dark else "#17263a",
        QPalette.Base: "#111925" if dark else "#ffffff",
        QPalette.AlternateBase: "#202c3c" if dark else "#eaf0f7",
        QPalette.Text: "#eef3fa" if dark else "#17263a",
        QPalette.Button: "#26364a" if dark else "#ffffff",
        QPalette.ButtonText: "#eef3fa" if dark else "#17263a",
        QPalette.Highlight: "#3e8bdc" if dark else "#2167b1",
        QPalette.HighlightedText: "#ffffff",
        QPalette.ToolTipBase: "#26364a" if dark else "#ffffff",
        QPalette.ToolTipText: "#eef3fa" if dark else "#17263a",
        QPalette.PlaceholderText: "#a0aec0" if dark else "#596b82",
        QPalette.Link: "#83c4ff" if dark else "#075eb7",
        QPalette.LinkVisited: "#c7b3ff" if dark else "#6742a0",
    }
    for role, color in colors.items():
        palette.setColor(role, QColor(color))
    for role in (QPalette.Text, QPalette.WindowText, QPalette.ButtonText):
        palette.setColor(QPalette.Disabled, role, QColor("#8290a3" if dark else "#75839a"))
    app.setPalette(palette)
    foreground, background, base, button, border, muted = (
        ("#eef3fa", "#18212e", "#111925", "#26364a", "#52637b", "#a0aec0")
        if dark
        else ("#17263a", "#f2f5fa", "#ffffff", "#ffffff", "#9baec4", "#596b82")
    )
    # Explicit colors also refresh widgets already polished by the window's style sheet.
    app.setStyleSheet(
        f"QWidget {{ color: {foreground}; background-color: {background}; }}"
        f"QLineEdit, QPlainTextEdit, QTableWidget, QComboBox {{ background-color: {base}; "
        f"color: {foreground}; selection-background-color: #2167b1; selection-color: white; }}"
        f"QPushButton {{ background-color: {button}; border: 1px solid {border}; "
        "border-radius: 5px; }"
        "QPushButton:hover { border: 1px solid #3e8bdc; }"
        f"QPushButton:disabled, QCheckBox:disabled {{ color: {muted}; }}"
        f"QTabBar::tab:selected {{ background-color: {base}; }}"
        f"QHeaderView::section {{ background-color: {button}; color: {foreground}; }}"
        "QPushButton:focus, QLineEdit:focus, QComboBox:focus { border: 2px solid #3e8bdc; }"
    )
