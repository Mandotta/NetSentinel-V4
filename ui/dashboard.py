# dashboard.py - Main GUI and background execution loops for NetSentinel v4

import sys
import os
import datetime
import subprocess
import shlex
from PyQt6.QtWidgets import (QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, 
                             QTableWidget, QTableWidgetItem, QTreeWidget, QTreeWidgetItem,
                             QSplitter, QTabWidget, QPushButton, QLabel, QLineEdit, 
                             QComboBox, QMessageBox, QFileDialog, QProgressBar, 
                             QGroupBox, QCheckBox)
from PyQt6.QtCore import QThread, pyqtSignal, QTimer, Qt, pyqtSlot
from PyQt6.QtGui import QColor, QFont, QPalette, QBrush

# Import core security modules
from core.process_monitor import ProcessMonitor
from core.network_monitor import NetworkMonitor
from core.threat_engine import ThreatEngine
from core.ai_engine import AISecurityExplainer

# Import utility modules
from utils.logger import app_logger
from utils.formatters import format_bytes, format_percentage, format_addr
from ui.log_panel import LogPanel


class SecurityScanThread(QThread):
    """Background worker executing process discovery and socket scanning."""
    scan_completed = pyqtSignal(dict)

    def __init__(self, threat_engine):
        super().__init__()
        self.proc_monitor = ProcessMonitor()
        self.net_monitor = NetworkMonitor()
        self.threat_engine = threat_engine
        self._running = True

    def run(self):
        # Initial scan
        self.perform_scan()

    def perform_scan(self):
        try:
            procs = self.proc_monitor.get_process_list()
            conns = self.net_monitor.get_connections()
            alerts = self.threat_engine.analyze(procs, conns)
            
            self.scan_completed.emit({
                "processes": procs,
                "connections": conns,
                "alerts": alerts
            })
        except Exception as e:
            app_logger.log("CRITICAL", f"Background scan execution failed: {e}")


class AIQueryThread(QThread):
    """Background worker querying AI explanation endpoints without blocking UI."""
    analysis_completed = pyqtSignal(dict)

    def __init__(self, ai_explainer, process_info, connections, alerts):
        super().__init__()
        self.ai_explainer = ai_explainer
        self.process_info = process_info
        self.connections = connections
        self.alerts = alerts

    def run(self):
        try:
            result = self.ai_explainer.analyze_threat(self.process_info, self.connections, self.alerts)
            self.analysis_completed.emit(result)
        except Exception as e:
            self.analysis_completed.emit({
                "risk_score": 50,
                "explanation": f"AI Query Thread Error: {e}",
                "recommendation": "Review process logs manually."
            })


class NetSentinelDashboard(QMainWindow):
    """Main Application Window hosting NetSentinel v4 GUI components."""
    
    def __init__(self):
        super().__init__()
        self.setWindowTitle("NetSentinel v4 - AI Network Security Analyzer")
        self.resize(1300, 850)

        # Initialize core logic variables
        self.proc_monitor = ProcessMonitor()
        self.net_monitor = NetworkMonitor()
        self.threat_engine = ThreatEngine()
        self.ai_explainer = AISecurityExplainer()
        
        self.processes_cache = {}
        self.connections_cache = []
        self.alerts_cache = []
        self.selected_pid = None
        self.monitoring_active = True

        # Classification visibility filters (all on by default)
        self._show_trusted   = True
        self._show_normal    = True
        self._show_unknown   = True
        self._show_suspicious = True

        # Initialize UI Components
        self._apply_dark_style()
        self._init_ui()

        # Connect logger feed directly to console log panel
        app_logger.add_listener(self.log_panel.append_log)

        # Background threading initialization
        self.scan_thread = None
        self.ai_thread = None

        # Auto-refresh timer initialization
        self.refresh_timer = QTimer(self)
        self.refresh_timer.timeout.connect(self.trigger_background_scan)
        self.refresh_timer.start(3000) # Default 3 seconds interval

        # Run initial scan
        app_logger.log("INFO", "NetSentinel v4 initialized. Starting security sweep...")
        self.trigger_background_scan()

    def _init_ui(self):
        # Main central widget
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)

        # ───────────────── HEADER PANEL (Score & Auto-refresh controls) ─────────────────
        header_layout = QHBoxLayout()
        
        # Security score badge
        score_label = QLabel("SYSTEM SECURITY PROFILE:")
        score_label.setFont(QFont("Segoe UI", 10, QFont.Weight.Bold))
        self.score_value = QLabel("SECURE (95/100)")
        self.score_value.setFont(QFont("Segoe UI", 12, QFont.Weight.Bold))
        self.score_value.setStyleSheet("color: #33cc33;") # Default green

        header_layout.addWidget(score_label)
        header_layout.addWidget(self.score_value)
        header_layout.addStretch()

        # Auto-refresh intervals config
        self.auto_refresh_box = QCheckBox("Auto-Refresh")
        self.auto_refresh_box.setChecked(True)
        self.auto_refresh_box.stateChanged.connect(self._on_auto_refresh_toggle)
        
        self.refresh_interval = QComboBox()
        self.refresh_interval.addItems(["1 sec", "2 sec", "3 sec", "5 sec"])
        self.refresh_interval.setCurrentIndex(2) # Default 3s
        self.refresh_interval.currentTextChanged.connect(self._on_interval_changed)

        header_layout.addWidget(self.auto_refresh_box)
        header_layout.addWidget(self.refresh_interval)

        # API Key manager button
        self.api_btn = QPushButton(" API Key")
        self.api_btn.setToolTip("Manage Gemini AI API key")
        self.api_btn.clicked.connect(self.open_api_key_dialog)
        self.api_btn.setStyleSheet(
            "QPushButton { background-color: #1a2e3d; color: #5599ff; font-weight: bold;"
            " border: 1px solid #5599ff; border-radius: 3px; padding: 5px 12px; }"
            "QPushButton:hover { background-color: #1f3d52; }"
        )
        header_layout.addWidget(self.api_btn)
        main_layout.addLayout(header_layout)

        # ───────────────── BODY SECTION (Splitter: Left Tables vs Right Inspector) ─────────────────
        body_splitter = QSplitter(Qt.Orientation.Horizontal)

        # Left Column - Tab Widget for Processes list, Process Tree, Network socket list
        left_tabs = QTabWidget()
        body_splitter.addWidget(left_tabs)

        # Tab 1: Dashboard Overview (Splitter: Process Table on top, Connections table on bottom)
        dashboard_tab = QWidget()
        dash_layout = QVBoxLayout(dashboard_tab)
        dash_splitter = QSplitter(Qt.Orientation.Vertical)
        
        # Process list box
        proc_group = QGroupBox("Active Processes")
        proc_layout = QVBoxLayout(proc_group)
        self.proc_table = QTableWidget(0, 6)
        self.proc_table.setHorizontalHeaderLabels(["PID", "Name", "CPU", "Memory", "User", "Path"])
        self.proc_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.proc_table.setSelectionMode(QTableWidget.SelectionMode.SingleSelection)
        self.proc_table.itemSelectionChanged.connect(self._on_process_table_selected)
        proc_layout.addWidget(self.proc_table)
        dash_splitter.addWidget(proc_group)

        # Connections list box + filter bar
        conn_group = QGroupBox("Active Socket Connections")
        conn_layout = QVBoxLayout(conn_group)

        # Classification filter row
        filter_row = QHBoxLayout()
        filter_row.addWidget(QLabel("Show:"))
        self.chk_trusted    = QCheckBox("Trusted");    self.chk_trusted.setChecked(True)
        self.chk_normal     = QCheckBox("Normal");     self.chk_normal.setChecked(True)
        self.chk_unknown    = QCheckBox("Unknown");    self.chk_unknown.setChecked(True)
        self.chk_suspicious = QCheckBox("Suspicious"); self.chk_suspicious.setChecked(True)
        for chk, attr in [(self.chk_trusted, '_show_trusted'), (self.chk_normal, '_show_normal'),
                          (self.chk_unknown, '_show_unknown'), (self.chk_suspicious, '_show_suspicious')]:
            chk.stateChanged.connect(lambda s, a=attr: (setattr(self, a, s == 2), self._update_connections_table()))
            filter_row.addWidget(chk)
        self.chk_trusted.setStyleSheet("color: #33cc33;")
        self.chk_normal.setStyleSheet("color: #5599ff;")
        self.chk_unknown.setStyleSheet("color: #ff9900; font-weight: bold;")
        self.chk_suspicious.setStyleSheet("color: #ff4d4d;")
        filter_row.addStretch()
        conn_layout.addLayout(filter_row)

        # 7-column table now includes Classification + Reason
        self.conn_table = QTableWidget(0, 7)
        self.conn_table.setHorizontalHeaderLabels(
            ["Classification", "Local Endpoint", "Remote Endpoint", "State", "PID", "Process", "Reason"])
        self.conn_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.conn_table.horizontalHeader().setStretchLastSection(True)
        conn_layout.addWidget(self.conn_table)
        dash_layout.addWidget(dash_splitter)
        conn_layout.addWidget(self.conn_table)
        dash_splitter.addWidget(conn_group)

        dash_layout.addWidget(dash_splitter)
        left_tabs.addTab(dashboard_tab, "Dashboard Grid")

        # Tab 3: UNKNOWN connections panel (always visible, default-selected)
        unknown_tab = QWidget()
        unknown_layout = QVBoxLayout(unknown_tab)
        unknown_header = QLabel("=== UNKNOWN NETWORK ACTIVITY ===")
        unknown_header.setFont(QFont("Segoe UI", 10, QFont.Weight.Bold))
        unknown_header.setStyleSheet("color: #ff9900; padding: 4px; border: 1px solid #ff9900; border-radius: 3px;")
        unknown_layout.addWidget(unknown_header)
        self.unknown_table = QTableWidget(0, 6)
        self.unknown_table.setHorizontalHeaderLabels(
            ["Process", "PID", "Remote IP", "Port", "State", "Reason"])
        self.unknown_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.unknown_table.horizontalHeader().setStretchLastSection(True)
        self.unknown_table.setStyleSheet(
            "QTableWidget { border: 2px solid #ff9900; } "
            "QTableWidget::item { color: #ffcc80; }")
        unknown_layout.addWidget(self.unknown_table)
        left_tabs.addTab(unknown_tab, "! UNKNOWN")

        # Tab 2: Process Tree View
        tree_tab = QWidget()
        tree_layout = QVBoxLayout(tree_tab)
        self.proc_tree = QTreeWidget()
        self.proc_tree.setHeaderLabels(["Process Tree (Parent -> Child Relationships)", "PID"])
        self.proc_tree.itemSelectionChanged.connect(self._on_tree_selected)
        tree_layout.addWidget(self.proc_tree)
        left_tabs.addTab(tree_tab, "Hierarchical Tree")

        # Right Column - Inspector Panel
        inspector_group = QGroupBox("Inspector / Security Profiler")
        inspector_layout = QVBoxLayout(inspector_group)
        body_splitter.addWidget(inspector_group)
        
        # Details Panel
        self.details_label = QLabel("Select a process to inspect its telemetry profiles.")
        self.details_label.setWordWrap(True)
        self.details_label.setFont(QFont("Segoe UI", 9))
        self.details_label.setStyleSheet("color: #cccccc;")
        inspector_layout.addWidget(self.details_label)

        # Risk score gauge progress bar
        inspector_layout.addWidget(QLabel("Threat Level Assessment Score:"))
        self.risk_bar = QProgressBar()
        self.risk_bar.setRange(0, 100)
        self.risk_bar.setValue(0)
        self.risk_bar.setTextVisible(True)
        self.risk_bar.setStyleSheet("""
            QProgressBar {
                border: 1px solid #3d3d3d;
                border-radius: 4px;
                text-align: center;
                color: #ffffff;
                font-weight: bold;
                background-color: #2b2b2b;
            }
            QProgressBar::chunk {
                background-color: #33cc33;
            }
        """)
        inspector_layout.addWidget(self.risk_bar)

        # AI Threat Intelligence text panel
        ai_box = QGroupBox("AI Explainer Engine")
        ai_layout = QVBoxLayout(ai_box)
        self.ai_output = QLabel("No analysis loaded. Select a process and click 'Run AI Analysis'.")
        self.ai_output.setWordWrap(True)
        self.ai_output.setFont(QFont("Consolas", 9))
        self.ai_output.setStyleSheet("color: #e0e0e0; background-color: #121212; padding: 5px; border-radius: 3px;")
        ai_layout.addWidget(self.ai_output)
        
        # Run AI Explainer btn
        self.ai_btn = QPushButton("Run AI Threat Explanation")
        self.ai_btn.setEnabled(False)
        self.ai_btn.clicked.connect(self.run_ai_threat_analysis)
        self.ai_btn.setStyleSheet("""
            QPushButton {
                background-color: #007acc;
                color: #ffffff;
                font-weight: bold;
                border: none;
                border-radius: 3px;
                padding: 6px;
            }
            QPushButton:hover { background-color: #0098ff; }
            QPushButton:pressed { background-color: #005999; }
            QPushButton:disabled { background-color: #3d3d3d; color: #777777; }
        """)
        ai_layout.addWidget(self.ai_btn)
        inspector_layout.addWidget(ai_box)

        # Administrative / Threat Containment Controls Panel
        ctrl_box = QGroupBox("Containment & Audit Controls")
        ctrl_grid = QVBoxLayout(ctrl_box)
        
        self.kill_btn = QPushButton("Terminate Process (Kill)")
        self.kill_btn.setEnabled(False)
        self.kill_btn.clicked.connect(self.contain_kill_process)
        self.kill_btn.setStyleSheet("""
            QPushButton {
                background-color: #990000;
                color: #ffffff;
                font-weight: bold;
                border: none;
                border-radius: 3px;
                padding: 6px;
            }
            QPushButton:hover { background-color: #cc0000; }
            QPushButton:disabled { background-color: #3d3d3d; color: #777777; }
        """)

        self.block_btn = QPushButton("Block Target IP (Firewall)")
        self.block_btn.setEnabled(False)
        self.block_btn.clicked.connect(self.contain_block_ip)
        self.block_btn.setStyleSheet("""
            QPushButton {
                background-color: #e68a00;
                color: #ffffff;
                font-weight: bold;
                border: none;
                border-radius: 3px;
                padding: 6px;
            }
            QPushButton:hover { background-color: #ff9900; }
            QPushButton:disabled { background-color: #3d3d3d; color: #777777; }
        """)

        self.safe_proc_btn = QPushButton("Mark Process as Safe")
        self.safe_proc_btn.setEnabled(False)
        self.safe_proc_btn.clicked.connect(self.action_mark_safe_process)
        self.safe_proc_btn.setStyleSheet(
            "QPushButton { background-color: #1a4d1a; color: #ffffff; font-weight: bold;"
            " border: none; border-radius: 3px; padding: 6px; }"
            "QPushButton:hover { background-color: #267326; }"
            "QPushButton:disabled { background-color: #3d3d3d; color: #777777; }")

        self.safe_ip_btn = QPushButton("Mark Remote IP as Safe")
        self.safe_ip_btn.setEnabled(False)
        self.safe_ip_btn.clicked.connect(self.action_mark_safe_ip)
        self.safe_ip_btn.setStyleSheet(
            "QPushButton { background-color: #1a3d4d; color: #ffffff; font-weight: bold;"
            " border: none; border-radius: 3px; padding: 6px; }"
            "QPushButton:hover { background-color: #1f5c73; }"
            "QPushButton:disabled { background-color: #3d3d3d; color: #777777; }")

        self.baseline_btn = QPushButton("Create Baseline (Learn Current State)")
        self.baseline_btn.clicked.connect(self.action_create_baseline)
        self.baseline_btn.setStyleSheet(
            "QPushButton { background-color: #2b2b2b; color: #cccccc; font-weight: bold;"
            " border: 1px solid #555; border-radius: 3px; padding: 6px; }"
            "QPushButton:hover { background-color: #3a3a3a; }")

        ctrl_grid.addWidget(self.kill_btn)
        ctrl_grid.addWidget(self.block_btn)
        ctrl_grid.addWidget(self.safe_proc_btn)
        ctrl_grid.addWidget(self.safe_ip_btn)
        ctrl_grid.addWidget(self.baseline_btn)
        inspector_layout.addWidget(ctrl_box)
        inspector_layout.addStretch()

        body_splitter.setSizes([850, 450])
        main_layout.addWidget(body_splitter, stretch=3)

        # ───────────────── BOTTOM SECTION (Controls Panel & Scrollable console logs) ─────────────────
        bottom_layout = QHBoxLayout()

        # Run state controllers
        self.monitoring_btn = QPushButton("Stop Monitoring")
        self.monitoring_btn.clicked.connect(self.toggle_monitoring_loop)
        self.monitoring_btn.setStyleSheet("background-color: #b37400; color: white; font-weight: bold; padding: 7px 15px;")
        
        self.refresh_btn = QPushButton("Scan Now")
        self.refresh_btn.clicked.connect(self.trigger_background_scan)
        self.refresh_btn.setStyleSheet("background-color: #2b2b2b; color: white; padding: 7px 15px;")

        self.export_btn = QPushButton("Export Logs (JSON)")
        self.export_btn.clicked.connect(self.export_logs_to_json)
        self.export_btn.setStyleSheet("background-color: #2b2b2b; color: white; padding: 7px 15px;")

        self.report_btn = QPushButton("Generate Report (HTML)")
        self.report_btn.clicked.connect(self.export_html_report)
        self.report_btn.setStyleSheet("background-color: #1f3d1f; color: white; font-weight: bold; padding: 7px 15px;")

        bottom_layout.addWidget(self.monitoring_btn)
        bottom_layout.addWidget(self.refresh_btn)
        bottom_layout.addWidget(self.export_btn)
        bottom_layout.addWidget(self.report_btn)
        bottom_layout.addStretch()
        
        main_layout.addLayout(bottom_layout)

        # Dedicated console logs panel
        self.log_panel = LogPanel(self)
        self.log_panel.setFixedHeight(180)
        main_layout.addWidget(self.log_panel)

    # ─────────────────────── SCAN SWEEP LOGIC ─────────────────────────
    def trigger_background_scan(self):
        """Dispatches scanning payload into background worker thread."""
        if not self.monitoring_active:
            return
            
        if self.scan_thread and self.scan_thread.isRunning():
            # Skip if previous thread execution is not done to avoid overlaps
            return

        self.scan_thread = SecurityScanThread(self.threat_engine)
        self.scan_thread.scan_completed.connect(self.handle_scan_results)
        self.scan_thread.start()

    @pyqtSlot(dict)
    def handle_scan_results(self, data):
        """Callback process running on GUI thread after scanning thread signals data load."""
        try:
            self.processes_cache = data["processes"]
            self.connections_cache = data["connections"]
            self.alerts_cache = data["alerts"]

            self._update_process_table()
            self._update_connections_table()
            self._update_process_tree()
            self._update_security_score()
            self._process_alerts(data["alerts"])
        except Exception as e:
            import traceback
            with open("err.txt", "w") as f:
                traceback.print_exc(file=f)
            sys.exit(1)

    def _update_process_table(self):
        self.proc_table.setSortingEnabled(False)
        selected_pids = [item.text() for item in self.proc_table.selectedItems() if item.column() == 0]
        prev_pid = selected_pids[0] if selected_pids else None

        self.proc_table.setRowCount(0)
        for pid, p in sorted(self.processes_cache.items(), key=lambda x: x[1]['name'].lower()):
            row = self.proc_table.rowCount()
            self.proc_table.insertRow(row)

            # Check if this process triggered alert
            p_alerts = [a for a in self.alerts_cache if a.get("pid") == pid]
            has_crit = any(a['severity'] == 'CRITICAL' for a in p_alerts)
            has_warn = any(a['severity'] == 'WARNING' for a in p_alerts)

            color = QColor("#2a1212") if has_crit else (QColor("#2a2012") if has_warn else QColor("#1e1e1e"))
            text_color = QColor("#ff4d4d") if has_crit else (QColor("#ffb84d") if has_warn else QColor("#ffffff"))

            # PID
            pid_item = QTableWidgetItem(str(pid))
            pid_item.setBackground(QBrush(color))
            pid_item.setForeground(QBrush(text_color))
            self.proc_table.setItem(row, 0, pid_item)

            # Name
            name_item = QTableWidgetItem(p['name'])
            name_item.setBackground(QBrush(color))
            name_item.setForeground(QBrush(text_color))
            self.proc_table.setItem(row, 1, name_item)

            # CPU
            cpu_item = QTableWidgetItem(format_percentage(p['cpu']))
            cpu_item.setBackground(QBrush(color))
            self.proc_table.setItem(row, 2, cpu_item)

            # Memory
            mem_item = QTableWidgetItem(format_bytes(p['memory']))
            mem_item.setBackground(QBrush(color))
            self.proc_table.setItem(row, 3, mem_item)

            # User
            user_item = QTableWidgetItem(p['user'])
            user_item.setBackground(QBrush(color))
            self.proc_table.setItem(row, 4, user_item)

            # Path
            path_item = QTableWidgetItem(p['path'])
            path_item.setBackground(QBrush(color))
            self.proc_table.setItem(row, 5, path_item)

            # Re-select row if it was active previously
            if prev_pid and str(pid) == prev_pid:
                self.proc_table.selectRow(row)

        self.proc_table.setSortingEnabled(True)

    # Classification colour palette
    _TIER_COLORS = {
        "TRUSTED":    ("#1a2e1a", "#33cc33"),
        "NORMAL":     ("#1a1e2e", "#5599ff"),
        "UNKNOWN":    ("#2e1e00", "#ff9900"),
        "SUSPICIOUS": ("#2e0000", "#ff4d4d"),
    }

    def _update_connections_table(self):
        self.conn_table.setRowCount(0)
        self.unknown_table.setRowCount(0)

        tier_visible = {
            "TRUSTED":    self._show_trusted,
            "NORMAL":     self._show_normal,
            "UNKNOWN":    self._show_unknown,
            "SUSPICIOUS": self._show_suspicious,
        }

        for conn in self.connections_cache:
            tier   = conn.get("classification", "UNKNOWN")
            reason = conn.get("reason", "")
            if not tier_visible.get(tier, True):
                continue

            bg_hex, fg_hex = self._TIER_COLORS.get(tier, ("#1e1e1e", "#ffffff"))
            bg = QBrush(QColor(bg_hex))
            fg = QBrush(QColor(fg_hex))

            pid       = conn.get("pid")
            proc_name = self.processes_cache.get(pid, {}).get("name", "N/A")
            local     = format_addr(conn['local_ip'], conn['local_port'])
            remote    = format_addr(conn['remote_ip'], conn['remote_port']) if conn.get('remote_ip') else "(Listening)"

            def make(text):
                it = QTableWidgetItem(str(text))
                it.setBackground(bg); it.setForeground(fg)
                return it

            row = self.conn_table.rowCount()
            self.conn_table.insertRow(row)
            for col, val in enumerate([tier, local, remote, conn['state'],
                                        str(pid) if pid else "N/A", proc_name, reason]):
                self.conn_table.setItem(row, col, make(val))

            # Mirror UNKNOWN entries into the dedicated UNKNOWN tab
            if tier == "UNKNOWN":
                urow = self.unknown_table.rowCount()
                self.unknown_table.insertRow(urow)
                for col, val in enumerate([proc_name, str(pid) if pid else "N/A",
                                           conn.get('remote_ip', ''), str(conn.get('remote_port', '')),
                                           conn['state'], reason]):
                    uit = QTableWidgetItem(str(val))
                    uit.setForeground(QBrush(QColor("#ffcc80")))
                    self.unknown_table.setItem(urow, col, uit)

    def _update_process_tree(self):
        self.proc_tree.clear()
        roots, children_map = self.proc_monitor.build_process_tree(self.processes_cache)

        # Recursive worker to construct child tree nodes
        def add_node(parent_widget, pid):
            proc = self.processes_cache.get(pid)
            if not proc:
                return
            item = QTreeWidgetItem(parent_widget)
            item.setText(0, f"{proc['name']} (PID: {pid})")
            item.setData(0, Qt.ItemDataRole.UserRole, pid)
            
            p_alerts = [a for a in self.alerts_cache if a.get("pid") == pid]
            if any(a['severity'] == 'CRITICAL' for a in p_alerts):
                item.setForeground(0, QBrush(QColor("#ff4d4d")))
            elif any(a['severity'] == 'WARNING' for a in p_alerts):
                item.setForeground(0, QBrush(QColor("#ffb84d")))

            children = children_map.get(pid, [])
            for c_pid in children:
                add_node(item, c_pid)

        for r_pid in roots:
            add_node(self.proc_tree, r_pid)

    def _update_security_score(self):
        """Recalculates a dynamic threat containment score (0-100)."""
        score = 100
        critical_count = sum(1 for a in self.alerts_cache if a['severity'] == 'CRITICAL')
        warning_count = sum(1 for a in self.alerts_cache if a['severity'] == 'WARNING')

        score -= (critical_count * 15)
        score -= (warning_count * 5)
        score = max(0, score)

        if score > 80:
            color = "#33cc33" # Green
            label = "SECURE"
        elif score > 50:
            color = "#ff9900" # Orange
            label = "RISK DETECTED"
        else:
            color = "#cc0000" # Red
            label = "COMPROMISED"

        self.score_value.setText(f"{label} ({score}/100)")
        self.score_value.setStyleSheet(f"color: {color};")

    def _process_alerts(self, new_alerts):
        """Pushes events into the global threat logs window with sound alerts on critical threats."""
        for alert in new_alerts:
            # Create a simple unique identifier for tracking alert logs
            log_msg = f"Alert: {alert['message']}"
            app_logger.log(alert['severity'], log_msg)

    # ─────────────────────── INSPECTOR DETAILS PANEL ─────────────────────────
    def update_inspector_panel(self, pid):
        self.selected_pid = pid
        proc = self.processes_cache.get(pid)
        if not proc:
            self.details_label.setText("Selected process has terminated.")
            self.risk_bar.setValue(0)
            self.risk_bar.setStyleSheet("QProgressBar::chunk { background-color: #33cc33; }")
            self.ai_btn.setEnabled(False)
            self.kill_btn.setEnabled(False)
            self.block_btn.setEnabled(False)
            return

        # Sockets counting details
        proc_conns = [c for c in self.connections_cache if c.get("pid") == pid]
        listeners = [c for c in proc_conns if c['state'] == 'LISTENING']
        estabs = [c for c in proc_conns if c['state'] == 'ESTABLISHED']

        # Format details printout
        text = (
            f"<b>Executable:</b> {proc['name']}<br>"
            f"<b>PID:</b> {pid}<br>"
            f"<b>User Scope:</b> {proc['user']}<br>"
            f"<b>CPU Status:</b> {format_percentage(proc['cpu'])}<br>"
            f"<b>Memory Load:</b> {format_bytes(proc['memory'])}<br>"
            f"<b>Path:</b> {proc['path']}<br><br>"
            f"<b>Sockets:</b> {len(proc_conns)} total ({len(listeners)} listening, {len(estabs)} established)"
        )
        self.details_label.setText(text)

        # Base threat scoring metrics
        p_alerts = [a for a in self.alerts_cache if a.get("pid") == pid]
        risk_score = 0
        if any(a['severity'] == 'CRITICAL' for a in p_alerts):
            risk_score = 80
            bar_color = "#cc0000"
        elif any(a['severity'] == 'WARNING' for a in p_alerts):
            risk_score = 45
            bar_color = "#ff9900"
        elif any(a['severity'] == 'INFO' for a in p_alerts):
            risk_score = 15
            bar_color = "#007acc"
        else:
            risk_score = 5
            bar_color = "#33cc33"

        self.risk_bar.setValue(risk_score)
        self.risk_bar.setStyleSheet(f"""
            QProgressBar {{
                border: 1px solid #3d3d3d;
                border-radius: 4px;
                text-align: center;
                color: #ffffff;
                font-weight: bold;
                background-color: #2b2b2b;
            }}
            QProgressBar::chunk {{
                background-color: {bar_color};
            }}
        """)

        # Enable interactive buttons
        self.ai_btn.setEnabled(True)
        self.kill_btn.setEnabled(True)
        self.safe_proc_btn.setEnabled(True)

        # Enable firewall block + safe-IP if there are established external connections
        has_ext_ips = any(c.get('remote_ip') is not None for c in estabs)
        self.block_btn.setEnabled(has_ext_ips)
        self.safe_ip_btn.setEnabled(has_ext_ips)

    # ─────────── Baseline / Safe marking actions ───────────
    def action_mark_safe_process(self):
        if not self.selected_pid:
            return
        proc = self.processes_cache.get(self.selected_pid)
        if not proc:
            return
        self.threat_engine.mark_safe_process(proc['name'])
        app_logger.log("INFO", f"User marked '{proc['name']}' as safe (added to session baseline).")
        QMessageBox.information(self, "Marked Safe", f"'{proc['name']}' is now classified as TRUSTED for this session.")
        self.trigger_background_scan()

    def action_mark_safe_ip(self):
        if not self.selected_pid:
            return
        conns = [c for c in self.connections_cache
                 if c.get('pid') == self.selected_pid and c.get('state') == 'ESTABLISHED'
                 and c.get('remote_ip')]
        if not conns:
            QMessageBox.warning(self, "No IPs", "No established external connections found for this process.")
            return
        # Mark all current external IPs for this process as safe
        for c in conns:
            self.threat_engine.mark_safe_ip(c['remote_ip'])
        ips = ', '.join(set(c['remote_ip'] for c in conns))
        app_logger.log("INFO", f"User marked IPs as safe: {ips}")
        QMessageBox.information(self, "Marked Safe", f"Remote IPs marked as safe:\n{ips}")
        self.trigger_background_scan()

    def action_create_baseline(self):
        self.threat_engine.create_baseline(self.processes_cache, self.connections_cache)
        app_logger.log("INFO", "Baseline created: all currently seen connections are now classified as NORMAL.")
        QMessageBox.information(self, "Baseline Created",
            "Current state snapshotted as baseline.\nAll existing connections will appear as NORMAL on next scan.")
        self.trigger_background_scan()

    def _on_process_table_selected(self):
        selected = self.proc_table.selectedItems()
        if not selected:
            return
        # Locate PID from column 0
        row = selected[0].row()
        pid_text = self.proc_table.item(row, 0).text()
        try:
            self.update_inspector_panel(int(pid_text))
        except ValueError:
            pass

    def _on_tree_selected(self):
        selected = self.proc_tree.selectedItems()
        if not selected:
            return
        pid = selected[0].data(0, Qt.ItemDataRole.UserRole)
        if pid:
            self.update_inspector_panel(pid)

    # ────────────────────────── AI ENGINE ─────────────────────────────
    def run_ai_threat_analysis(self):
        """Launches AI analysis as a background thread to prevent UI freezing."""
        if not self.selected_pid:
            return

        proc = self.processes_cache.get(self.selected_pid)
        if not proc:
            return

        conns = [c for c in self.connections_cache if c.get("pid") == self.selected_pid]
        alerts = [a for a in self.alerts_cache if a.get("pid") == self.selected_pid]

        self.ai_output.setText("Consulting AI threat engine... please wait.")
        self.ai_btn.setEnabled(False)

        self.ai_thread = AIQueryThread(self.ai_explainer, proc, conns, alerts)
        self.ai_thread.analysis_completed.connect(self.handle_ai_results)
        self.ai_thread.start()

    @pyqtSlot(dict)
    def handle_ai_results(self, result):
        """Displays risk assessment from AI or fallback rules engine."""
        self.ai_btn.setEnabled(True)
        
        risk = result.get("risk_score", 0)
        explanation = result.get("explanation", "")
        recommendation = result.get("recommendation", "")

        self.ai_output.setText(
            f"<b>Risk Score:</b> {risk}/100<br><br>"
            f"<b>Assessment:</b> {explanation}<br><br>"
            f"<b>Recommendation:</b> {recommendation}"
        )
        self.risk_bar.setValue(risk)


    # ─────────────────────── CONTAINMENT LOGIC ─────────────────────────
    def contain_kill_process(self):
        """Requests admin permission to terminate a process by PID."""
        if not self.selected_pid:
            return

        confirm = QMessageBox.question(
            self, "Confirm Process Termination",
            f"Are you sure you want to terminate process ID {self.selected_pid}?\nThis cannot be undone.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )
        if confirm != QMessageBox.StandardButton.Yes:
            return

        cmd = f"taskkill /PID {self.selected_pid} /F"
        try:
            # Runs safe cmd execution avoiding shell injection
            args = shlex.split(cmd)
            startupinfo = subprocess.STARTUPINFO()
            startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
            subprocess.run(args, startupinfo=startupinfo, check=True)
            
            app_logger.log("WARNING", f"Process with PID {self.selected_pid} terminated by user action.")
            QMessageBox.information(self, "Success", f"Process {self.selected_pid} terminated successfully.")
            self.trigger_background_scan()
        except Exception as e:
            app_logger.log("CRITICAL", f"Failed to terminate process ID {self.selected_pid}: {e}")
            QMessageBox.critical(self, "Error", f"Could not terminate process. Reason: {e}")

    def contain_block_ip(self):
        """Requests admin permission to configure block rules for external IPs."""
        if not self.selected_pid:
            return

        proc_conns = [c for c in self.connections_cache if c.get("pid") == self.selected_pid]
        est_conns = [c for c in proc_conns if c['state'] == 'ESTABLISHED' and c.get('remote_ip')]

        if not est_conns:
            QMessageBox.warning(self, "Warning", "No active external connections established for process.")
            return

        # Choose the first established connection
        target_ip = est_conns[0]['remote_ip']

        confirm = QMessageBox.question(
            self, "Confirm IP Block",
            f"Are you sure you want to block remote IP {target_ip} in Windows Firewall?\n(Requires Administrator Privileges)",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )
        if confirm != QMessageBox.StandardButton.Yes:
            return

        # Executing netsh block rule command securely
        rule_name = f"NetSentinel_Block_{target_ip.replace(':', '_')}"
        cmd = f'netsh advfirewall firewall add rule name="{rule_name}" dir=out action=block remoteip={target_ip} protocol=TCP'
        
        try:
            startupinfo = subprocess.STARTUPINFO()
            startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
            subprocess.run(shlex.split(cmd), startupinfo=startupinfo, check=True)
            
            app_logger.log("WARNING", f"Added local firewall block rule '{rule_name}' for remote destination IP {target_ip}.")
            QMessageBox.information(self, "Success", f"Blocked remote IP {target_ip} in Windows Firewall.")
        except Exception as e:
            app_logger.log("CRITICAL", f"Failed to block remote IP {target_ip}: {e}")
            QMessageBox.critical(self, "Error", f"Failed to modify firewall rules. Make sure the app is running as Administrator. Details: {e}")

    # ───────────────────────── SYSTEM SETTINGS ──────────────────────────
    def toggle_monitoring_loop(self):
        self.monitoring_active = not self.monitoring_active
        if self.monitoring_active:
            self.monitoring_btn.setText("Stop Monitoring")
            self.monitoring_btn.setStyleSheet("background-color: #b37400; color: white; font-weight: bold; padding: 7px 15px;")
            self.refresh_timer.start()
            app_logger.log("INFO", "Monitoring resumed.")
        else:
            self.monitoring_btn.setText("Start Monitoring")
            self.monitoring_btn.setStyleSheet("background-color: #1f3d1f; color: white; font-weight: bold; padding: 7px 15px;")
            self.refresh_timer.stop()
            app_logger.log("INFO", "Monitoring suspended.")

    # ─────────────────────── API KEY DIALOG ───────────────────────
    def open_api_key_dialog(self):
        """Opens a popup to view, delete, or update the Gemini API key."""
        from PyQt6.QtWidgets import QDialog, QDialogButtonBox, QFormLayout

        dialog = QDialog(self)
        dialog.setWindowTitle("Gemini API Key Manager")
        dialog.setMinimumWidth(420)
        dialog.setStyleSheet(
            "QDialog { background-color: #1e1e1e; color: #e0e0e0; }"
            "QLabel { color: #e0e0e0; }"
            "QLineEdit { background-color: #2b2b2b; color: #e0e0e0; border: 1px solid #3d3d3d;"
            "            border-radius: 3px; padding: 4px; }"
            "QPushButton { background-color: #2b2b2b; color: #cccccc; border: 1px solid #3d3d3d;"
            "              border-radius: 3px; padding: 5px 10px; }"
            "QPushButton:hover { background-color: #3a3a3a; }"
        )

        layout = QVBoxLayout(dialog)

        # Current key display (masked)
        current_key = self.ai_explainer.api_key or ""
        masked = (current_key[:8] + "..." + current_key[-4:]) if len(current_key) > 12 else ("(none)" if not current_key else current_key)
        status_color = "#33cc33" if current_key else "#ff4d4d"
        status_lbl = QLabel(f"Current key: <b style='color:{status_color}'>{masked}</b>")
        status_lbl.setTextFormat(Qt.TextFormat.RichText)
        layout.addWidget(status_lbl)

        # New key input
        form = QFormLayout()
        new_key_input = QLineEdit()
        new_key_input.setPlaceholderText("Paste new Gemini API key here...")
        new_key_input.setEchoMode(QLineEdit.EchoMode.Password)
        new_key_input.setMinimumWidth(300)
        form.addRow("New Key:", new_key_input)
        layout.addLayout(form)

        # Buttons
        btn_row = QHBoxLayout()

        save_btn = QPushButton("Save Key")
        save_btn.setStyleSheet("background-color: #1a4d1a; color: #fff; font-weight: bold; border: none; padding: 6px 14px;")
        def save_key():
            k = new_key_input.text().strip()
            if not k:
                QMessageBox.warning(dialog, "Empty Key", "Please enter a key before saving.")
                return
            self.ai_explainer.set_api_key(k)
            app_logger.log("INFO", "Gemini API key updated via dialog.")
            dialog.accept()
        save_btn.clicked.connect(save_key)

        delete_btn = QPushButton("Delete Key")
        delete_btn.setStyleSheet("background-color: #4d1a1a; color: #fff; font-weight: bold; border: none; padding: 6px 14px;")
        def delete_key():
            confirm = QMessageBox.question(dialog, "Delete Key",
                "Remove the current API key? AI analysis will fall back to local rules.",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
            if confirm == QMessageBox.StandardButton.Yes:
                self.ai_explainer.set_api_key("")
                app_logger.log("INFO", "Gemini API key deleted.")
                dialog.accept()
        delete_btn.clicked.connect(delete_key)

        close_btn = QPushButton("Close")
        close_btn.clicked.connect(dialog.reject)

        btn_row.addWidget(save_btn)
        btn_row.addWidget(delete_btn)
        btn_row.addStretch()
        btn_row.addWidget(close_btn)
        layout.addLayout(btn_row)

        dialog.exec()

    def _on_auto_refresh_toggle(self, state):
        if state == 2: # Checked
            self.refresh_timer.start()
            app_logger.log("INFO", "Auto-refresh activated.")
        else:
            self.refresh_timer.stop()
            app_logger.log("INFO", "Auto-refresh deactivated.")

    def _on_interval_changed(self, text):
        """Called when the user picks a new refresh interval from the combo box."""
        try:
            val = int(str(text).split()[0])  # e.g. "3 sec" -> 3
            self.refresh_timer.setInterval(val * 1000)
            app_logger.log("INFO", f"Refresh interval set to {text}.")
        except (ValueError, IndexError, AttributeError):
            pass  # Ignore spurious signal firings with unexpected values

    # ───────────────────────── LOGS & REPORTS ──────────────────────────
    def export_logs_to_json(self):
        file_path, _ = QFileDialog.getSaveFileName(self, "Export Log Database", "", "JSON Files (*.json)")
        if not file_path:
            return
        success, err = app_logger.export_json(file_path)
        if success:
            QMessageBox.information(self, "Success", "Logs exported successfully.")
        else:
            QMessageBox.critical(self, "Error", f"Failed to save log data: {err}")

    def export_html_report(self):
        """Generates a structured, self-contained HTML security report of the current sweep."""
        file_path, _ = QFileDialog.getSaveFileName(self, "Save Security Audit Report", "", "HTML Files (*.html)")
        if not file_path:
            return

        try:
            # Build process summary metrics
            crit_alerts = [a for a in self.alerts_cache if a['severity'] == 'CRITICAL']
            warn_alerts = [a for a in self.alerts_cache if a['severity'] == 'WARNING']

            html = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>NetSentinel v4 Security Audit Report</title>
    <style>
        body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background-color: #f7f9fa; color: #333333; margin: 20px; }}
        h1 {{ color: #003366; border-bottom: 2px solid #003366; padding-bottom: 10px; }}
        .header {{ background-color: #ffffff; padding: 20px; border-radius: 5px; box-shadow: 0 2px 4px rgba(0,0,0,0.05); margin-bottom: 20px; }}
        .metric-container {{ display: flex; gap: 20px; margin-bottom: 25px; }}
        .metric {{ flex: 1; padding: 15px; border-radius: 4px; color: white; text-align: center; font-weight: bold; }}
        .metric.crit {{ background-color: #d9534f; }}
        .metric.warn {{ background-color: #f0ad4e; }}
        .metric.safe {{ background-color: #5cb85c; }}
        table {{ width: 100%; border-collapse: collapse; background-color: #ffffff; margin-bottom: 20px; box-shadow: 0 2px 4px rgba(0,0,0,0.05); }}
        th, td {{ padding: 12px; text-align: left; border-bottom: 1px solid #eeeeee; }}
        th {{ background-color: #f2f2f2; color: #333333; }}
        tr.crit-row {{ background-color: #fdf7f7; }}
        tr.warn-row {{ background-color: #fcf8f2; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>NetSentinel Security Report</h1>
        <p><b>Generated at:</b> {datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</p>
        <div class="metric-container">
            <div class="metric crit">Critical Alerts: {len(crit_alerts)}</div>
            <div class="metric warn">Warning Alerts: {len(warn_alerts)}</div>
            <div class="metric safe">Active Processes Tracked: {len(self.processes_cache)}</div>
        </div>
    </div>

    <h2>Active Risk Violations</h2>
    <table>
        <thead>
            <tr>
                <th>Severity</th>
                <th>Process Name</th>
                <th>PID</th>
                <th>Audit Message</th>
            </tr>
        </thead>
        <tbody>
            {"".join([f"<tr class='{'crit-row' if a['severity'] == 'CRITICAL' else 'warn-row'}'><td><b>{a['severity']}</b></td><td>{a.get('process_name')}</td><td>{a.get('pid')}</td><td>{a['message']}</td></tr>" for a in self.alerts_cache]) or "<tr><td colspan='4'>No risk rules triggered on this sweep.</td></tr>"}
        </tbody>
    </table>

    <h2>Network Connections snapshot</h2>
    <table>
        <thead>
            <tr>
                <th>PID</th>
                <th>Local Socket</th>
                <th>Remote Socket</th>
                <th>Socket State</th>
            </tr>
        </thead>
        <tbody>
            {"".join([f"<tr><td>{c.get('pid')}</td><td>{format_addr(c['local_ip'], c['local_port'])}</td><td>{format_addr(c['remote_ip'], c['remote_port']) if c.get('remote_ip') else 'Listening'}</td><td>{c['state']}</td></tr>" for c in self.connections_cache])}
        </tbody>
    </table>
</body>
</html>
"""
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write(html)
            QMessageBox.information(self, "Success", "Audit Report generated successfully.")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to generate report: {e}")

    # ────────────────────────── PALETTE / STYLE ───────────────────────────
    def _apply_dark_style(self):
        """Sets up a premium, responsive dark mode theme palette for GUI widgets."""
        self.setStyleSheet("""
            QMainWindow { background-color: #1a1a1a; }
            QWidget { background-color: #1a1a1a; color: #ffffff; }
            QGroupBox {
                border: 1px solid #3d3d3d;
                border-radius: 4px;
                margin-top: 15px;
                padding-top: 15px;
                font-weight: bold;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                subcontrol-position: top left;
                padding: 0 5px;
                color: #007acc;
            }
            QTableWidget {
                background-color: #1e1e1e;
                gridline-color: #2b2b2b;
                border: 1px solid #2b2b2b;
                border-radius: 3px;
                alternate-background-color: #252526;
            }
            QTableWidget::item { padding: 4px; }
            QHeaderView::section {
                background-color: #2b2b2b;
                color: #ffffff;
                border: 1px solid #3d3d3d;
                padding: 5px;
            }
            QTreeWidget {
                background-color: #1e1e1e;
                border: 1px solid #2b2b2b;
            }
            QTreeWidget::item { padding: 4px; }
            QTabWidget::pane {
                border: 1px solid #3d3d3d;
            }
            QTabBar::tab {
                background-color: #2b2b2b;
                color: #cccccc;
                padding: 6px 14px;
                border: 1px solid #3d3d3d;
                border-bottom: none;
                border-top-left-radius: 3px;
                border-top-right-radius: 3px;
                min-width: 80px;
            }
            QTabBar::tab:selected {
                background-color: #1a1a1a;
                color: #ffffff;
                border-bottom: 2px solid #007acc;
                font-weight: bold;
            }
            QTabBar::tab:hover:!selected {
                background-color: #333333;
                color: #ffffff;
            }
            QLineEdit {
                background-color: #2b2b2b;
                border: 1px solid #3d3d3d;
                border-radius: 3px;
                color: #ffffff;
                padding: 3px;
            }
            QComboBox {
                background-color: #2b2b2b;
                color: #ffffff;
                border: 1px solid #3d3d3d;
                border-radius: 3px;
                padding: 3px 5px;
            }
        """)

    def closeEvent(self, event):
        # Stop background loops on closing window
        self.refresh_timer.stop()
        if self.scan_thread and self.scan_thread.isRunning():
            self.scan_thread.terminate()
            self.scan_thread.wait()
        app_logger.remove_listener(self.log_panel.append_log)
        event.accept()
