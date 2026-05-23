# log_panel.py - Log Display Console Widget for NetSentinel v4

from PyQt6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QTextEdit, 
                             QComboBox, QPushButton, QLabel)
from PyQt6.QtGui import QTextCursor, QTextCharFormat, QColor, QFont
from PyQt6.QtCore import pyqtSlot

class LogPanel(QWidget):
    """Console logging widget displaying events with severity-based coloring and filters."""
    def __init__(self, parent=None):
        super().__init__(parent)
        self._all_logs = []
        self._filter_level = "ALL"
        self._init_ui()

    def _init_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)

        # Header controls layout
        header_layout = QHBoxLayout()
        
        # Severity filter selector
        filter_label = QLabel("Filter:")
        filter_label.setStyleSheet("color: #ffffff; font-weight: bold;")
        self.filter_dropdown = QComboBox()
        self.filter_dropdown.addItems(["ALL", "INFO", "WARNING", "CRITICAL"])
        self.filter_dropdown.currentTextChanged.connect(self._on_filter_changed)
        self.filter_dropdown.setStyleSheet("""
            QComboBox {
                background-color: #2b2b2b;
                color: #ffffff;
                border: 1px solid #3d3d3d;
                border-radius: 3px;
                padding: 3px 15px 3px 5px;
            }
            QComboBox QAbstractItemView {
                background-color: #2b2b2b;
                color: #ffffff;
                selection-background-color: #007acc;
            }
        """)

        # Clear button
        clear_btn = QPushButton("Clear Console")
        clear_btn.clicked.connect(self.clear_logs)
        clear_btn.setStyleSheet("""
            QPushButton {
                background-color: #cc3333;
                color: #ffffff;
                border: none;
                border-radius: 3px;
                padding: 5px 10px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #e64d4d;
            }
            QPushButton:pressed {
                background-color: #992626;
            }
        """)

        header_layout.addWidget(filter_label)
        header_layout.addWidget(self.filter_dropdown)
        header_layout.addStretch()
        header_layout.addWidget(clear_btn)
        layout.addLayout(header_layout)

        # Main scrollable rich text window
        self.console = QTextEdit()
        self.console.setReadOnly(True)
        self.console.setFont(QFont("Consolas", 10))
        self.console.setStyleSheet("""
            QTextEdit {
                background-color: #121212;
                border: 1px solid #2a2a2a;
                border-radius: 4px;
                padding: 5px;
            }
        """)
        layout.addWidget(self.console)

    @pyqtSlot(dict)
    def append_log(self, log_entry):
        """Appends a new log entry to history and displays it if it matches the current filter."""
        self._all_logs.append(log_entry)
        # Prevent memory leaks by capping UI logs at 1000 items
        if len(self._all_logs) > 1000:
            self._all_logs.pop(0)

        if self._should_display(log_entry):
            self._render_log_to_console(log_entry)

    def clear_logs(self):
        """Clears console display and stored UI log history."""
        self._all_logs.clear()
        self.console.clear()

    def _on_filter_changed(self, text):
        self._filter_level = text
        self._rebuild_console_display()

    def _should_display(self, log_entry):
        if self._filter_level == "ALL":
            return True
        return log_entry["severity"] == self._filter_level

    def _rebuild_console_display(self):
        self.console.clear()
        for log in self._all_logs:
            if self._should_display(log):
                self._render_log_to_console(log)

    def _render_log_to_console(self, log_entry):
        timestamp = log_entry.get("timestamp", "")
        severity = log_entry.get("severity", "INFO")
        message = log_entry.get("message", "")

        # Select matching color according to severity level
        if severity == "CRITICAL":
            color = QColor("#ff4d4d") # Bright red
        elif severity == "WARNING":
            color = QColor("#ffb84d") # Soft orange
        else:
            color = QColor("#33cc33") # Light green

        self.console.moveCursor(QTextCursor.MoveOperation.End)
        
        # Configure text formatting rules
        fmt = QTextCharFormat()
        
        # 1. Print timestamp in dim grey
        fmt.setForeground(QColor("#7a7a7a"))
        self.console.setCurrentCharFormat(fmt)
        self.console.insertPlainText(f"[{timestamp}] ")

        # 2. Print severity prefix
        fmt.setForeground(color)
        fmt.setFontWeight(QFont.Weight.Bold)
        self.console.setCurrentCharFormat(fmt)
        self.console.insertPlainText(f"[{severity}] ")

        # 3. Print main message payload in white
        fmt.setForeground(QColor("#e0e0e0"))
        fmt.setFontWeight(QFont.Weight.Normal)
        self.console.setCurrentCharFormat(fmt)
        self.console.insertPlainText(f"{message}\n")
        
        # Scroll to bottom automatically
        self.console.moveCursor(QTextCursor.MoveOperation.End)
