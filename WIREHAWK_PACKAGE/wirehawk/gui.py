#!/usr/bin/env python3
"""
gui.py
WireHawk desktop GUI — a dense, multi-tab professional application in
the spirit of Wireshark/Burp Suite: a muted dark palette with a single
sparing accent color, monospace data tables, dockable-style panels,
and semantic status coloring rather than a single theme color applied
to everything. No decorative animation — every visual element reflects
real state.

Tabs:
  Capture     — start/stop monitoring, live throughput graph, device
                table, stats panel
  Devices     — read-only discovery, device aliasing, jump to history
  Wi-Fi       — nearby network scan with security classification
  Guard       — self-security check + live ARP spoofing watch
  History     — browse a saved --log CSV file by device
  Interfaces  — pick which network interface the app uses

Run with:
    sudo wirehawk-gui

(Needs root for the same reason the CLI does: raw socket access for
ARP spoofing and packet capture.)
"""

import csv
import sys
import threading
import time
from pathlib import Path
from collections import deque, Counter

from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QFormLayout,
    QPushButton, QTableWidget, QTableWidgetItem, QLabel, QLineEdit,
    QHeaderView, QTextEdit, QMessageBox, QStatusBar, QSplitter,
    QToolBar, QDialog, QInputDialog, QFileDialog, QStyle, QTabWidget,
    QComboBox, QCheckBox, QListWidget, QListWidgetItem, QGroupBox,
    QAbstractItemView, QSizePolicy,
)
from PySide6.QtCore import Qt, QTimer, QThread, Signal
from PySide6.QtGui import QPainter, QColor, QPen, QPainterPath, QFont, QIcon, QAction

ICON_PATH = Path(__file__).parent / "assets" / "wirehawk_icon_256.png"

from wirehawk.network_utils import (
    get_own_ip, get_gateway_ip, get_mac, scan_network, get_local_subnet,
    get_default_iface, get_iface_type, get_own_mac,
    is_vpn_interface, list_vpn_interfaces, list_all_interfaces,
)
from wirehawk.arp_spoof import ARPSpoofer
from wirehawk.packet_capture import PacketStats, start_capture
from wirehawk.simulate import run_simulation, fake_device_names
from wirehawk.diagnostics import diagnose
from wirehawk.wifi_scan import scan_wifi_networks
from wirehawk.guard import check_own_security, ArpWatcher, run_arp_watcher
from wirehawk.history_reader import read_device_history, list_logged_devices
from wirehawk.device_aliases import load_aliases, save_aliases, set_alias, apply_aliases

# ---------------------------------------------------------------------------
# Theme: muted professional dark palette. The WireHawk red is an ACCENT
# used sparingly (selected tab, logo, critical alerts) — not applied to
# every element the way a themed "hacker" skin would. Status colors are
# semantic (green=ok, amber=warn, red=danger) rather than monochrome.
# ---------------------------------------------------------------------------
BG = "#1e1e1e"
BG_PANEL = "#252526"
BG_ALT = "#2d2d30"
BORDER = "#3c3c3c"
TEXT = "#d4d4d4"
TEXT_DIM = "#8a8a8a"
ACCENT = "#e74c3c"
ACCENT_DIM = "#8a3a33"
OK = "#4caf50"
WARN = "#f0ad4e"
DANGER = "#e74c3c"
MONO_FONT = "Consolas, 'DejaVu Sans Mono', Monaco, monospace"

STYLESHEET = f"""
QMainWindow, QWidget {{ background-color: {BG}; color: {TEXT}; font-family: Segoe UI, Ubuntu, sans-serif; }}
QTabWidget::pane {{ border: 1px solid {BORDER}; background-color: {BG}; }}
QTabBar::tab {{
    background-color: {BG_PANEL}; color: {TEXT_DIM}; padding: 7px 16px;
    border: 1px solid {BORDER}; border-bottom: none;
}}
QTabBar::tab:selected {{ background-color: {BG}; color: {TEXT}; border-bottom: 2px solid {ACCENT}; }}
QTabBar::tab:hover {{ color: {TEXT}; }}
QPushButton {{
    background-color: {BG_ALT}; color: {TEXT}; border: 1px solid {BORDER};
    padding: 6px 14px; border-radius: 2px;
}}
QPushButton:hover {{ border: 1px solid {ACCENT}; }}
QPushButton:pressed {{ background-color: {ACCENT_DIM}; }}
QPushButton:disabled {{ color: {TEXT_DIM}; border: 1px solid #2a2a2a; }}
QPushButton#primary {{ background-color: {ACCENT_DIM}; border: 1px solid {ACCENT}; font-weight: 600; }}
QPushButton#primary:hover {{ background-color: {ACCENT}; }}
QTableWidget {{
    background-color: {BG_PANEL}; color: {TEXT}; gridline-color: {BORDER};
    border: 1px solid {BORDER}; font-family: {MONO_FONT}; font-size: 12px;
    selection-background-color: {ACCENT_DIM}; selection-color: {TEXT};
}}
QHeaderView::section {{
    background-color: {BG_ALT}; color: {TEXT_DIM};
    border: 1px solid {BORDER}; padding: 5px; font-weight: 600; font-size: 11px;
}}
QLineEdit, QComboBox {{
    background-color: {BG_PANEL}; color: {TEXT}; border: 1px solid {BORDER};
    padding: 5px; border-radius: 2px;
}}
QLineEdit:focus, QComboBox:focus {{ border: 1px solid {ACCENT}; }}
QTextEdit, QListWidget {{
    background-color: {BG_PANEL}; color: {TEXT};
    border: 1px solid {BORDER}; font-family: {MONO_FONT}; font-size: 12px;
}}
QStatusBar {{ background-color: {BG_PANEL}; color: {TEXT_DIM}; border-top: 1px solid {BORDER}; }}
QLabel {{ color: {TEXT}; }}
QLabel#sectionTitle {{ color: {TEXT_DIM}; font-weight: 600; font-size: 11px; letter-spacing: 1px; }}
QLabel#logo {{ color: {ACCENT}; font-weight: 700; font-size: 15px; letter-spacing: 2px; }}
QMenuBar {{ background-color: {BG_PANEL}; color: {TEXT}; border-bottom: 1px solid {BORDER}; }}
QMenuBar::item:selected {{ background-color: {BG_ALT}; }}
QMenu {{ background-color: {BG_PANEL}; color: {TEXT}; border: 1px solid {BORDER}; }}
QMenu::item:selected {{ background-color: {ACCENT_DIM}; }}
QToolBar {{ background-color: {BG_PANEL}; border-bottom: 1px solid {BORDER}; spacing: 2px; padding: 3px; }}
QToolButton {{ color: {TEXT}; padding: 5px 8px; border-radius: 2px; }}
QToolButton:hover {{ background-color: {BG_ALT}; }}
QDialog {{ background-color: {BG}; color: {TEXT}; }}
QGroupBox {{
    border: 1px solid {BORDER}; margin-top: 10px; padding-top: 10px;
    color: {TEXT_DIM}; font-weight: 600; font-size: 11px;
}}
QGroupBox::title {{ subcontrol-origin: margin; left: 8px; padding: 0 4px; }}
QCheckBox {{ color: {TEXT}; }}
QSplitter::handle {{ background-color: {BORDER}; }}
"""


def format_bytes(n):
    for unit in ["B", "KB", "MB", "GB"]:
        if n < 1024:
            return f"{n:.1f}{unit}"
        n /= 1024
    return f"{n:.1f}TB"


def status_color(level):
    return {"safe": OK, "warn": WARN, "danger": DANGER}.get(level, TEXT)


class StatusDot(QWidget):
    """A static, non-animated colored dot + label — the sober
    equivalent of a connection-status indicator used in real tools
    (editor git status, build status badges). No motion; the color and
    text are the only state."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setFixedSize(110, 20)
        self._color = TEXT_DIM
        self._label = "IDLE"

    def set_state(self, color, label):
        self._color = color
        self._label = label
        self.update()

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)
        painter.setBrush(QColor(self._color))
        painter.setPen(Qt.NoPen)
        painter.drawEllipse(2, 6, 8, 8)
        painter.setPen(QPen(QColor(self._color)))
        font = painter.font()
        font.setBold(True)
        font.setPointSize(9)
        painter.setFont(font)
        painter.drawText(16, 15, self._label)


class ThroughputGraph(QWidget):
    """A flat, muted line graph — functional, not decorative. Grid
    lines and axis-style framing like a real monitoring tool chart,
    accent-colored line, no glow or fill gradients."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.history = deque(maxlen=150)
        self.setMinimumHeight(140)
        self.setStyleSheet(f"background-color: {BG_PANEL}; border: 1px solid {BORDER};")

    def add_value(self, value):
        self.history.append(value)
        self.update()

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)
        painter.fillRect(self.rect(), QColor(BG_PANEL))

        w, h = self.width(), self.height()
        margin = 34

        # gridlines
        grid_pen = QPen(QColor(BORDER))
        grid_pen.setWidth(1)
        painter.setPen(grid_pen)
        for i in range(5):
            y = margin + i * (h - margin - 10) / 4
            painter.drawLine(margin, y, w - 10, y)

        if len(self.history) < 2:
            painter.setPen(QColor(TEXT_DIM))
            painter.drawText(self.rect(), Qt.AlignCenter, "No data yet")
            return

        vals = list(self.history)
        vmax = max(vals) or 1
        plot_w = w - margin - 10
        plot_h = h - margin - 10

        path = QPainterPath()
        step = plot_w / (len(vals) - 1)
        for i, v in enumerate(vals):
            x = margin + i * step
            y = (margin + plot_h) - (v / vmax) * plot_h
            if i == 0:
                path.moveTo(x, y)
            else:
                path.lineTo(x, y)

        pen = QPen(QColor(ACCENT))
        pen.setWidth(2)
        painter.setPen(pen)
        painter.drawPath(path)

        # Y axis labels
        painter.setPen(QColor(TEXT_DIM))
        font = painter.font()
        font.setPointSize(8)
        painter.setFont(font)
        painter.drawText(4, margin + 4, format_bytes(vmax) + "/s")
        painter.drawText(4, margin + plot_h, "0")


class DeviceHistoryDialog(QDialog):
    """Chronological hostname history for one device — resolved via DNS
    and TLS SNI. Non-modal, self-refreshing while the session is live."""

    def __init__(self, parent, stats_getter, ip, device_name=None):
        super().__init__(parent)
        self.stats_getter = stats_getter
        self.ip = ip
        self.setWindowTitle(f"WireHawk — History: {device_name or ip}")
        self.resize(580, 420)
        self.setStyleSheet(STYLESHEET)

        layout = QVBoxLayout(self)
        header = QLabel(f"Hostname history — {device_name or ip} ({ip})")
        header.setObjectName("sectionTitle")
        layout.addWidget(header)
        self.subheader = QLabel("")
        self.subheader.setStyleSheet(f"color: {TEXT_DIM};")
        layout.addWidget(self.subheader)

        self.table = QTableWidget(0, 3)
        self.table.setHorizontalHeaderLabels(["TIME", "PROTOCOL", "HOSTNAME"])
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        layout.addWidget(self.table)

        self._refresh()
        self.timer = QTimer(self)
        self.timer.timeout.connect(self._refresh)
        self.timer.start(2000)

    def _refresh(self):
        stats = self.stats_getter()
        if stats is None:
            self.subheader.setText("No active session.")
            return
        history = stats.device_history(self.ip)
        self.subheader.setText(
            f"{len(history)} hostname(s) this session — most recent first (DNS + HTTPS/TLS SNI)"
        )
        self.table.setRowCount(len(history))
        for row, (ts, hostname, proto) in enumerate(reversed(history)):
            time_str = time.strftime("%H:%M:%S", time.localtime(ts))
            for col, val in enumerate([time_str, proto, hostname]):
                self.table.setItem(row, col, QTableWidgetItem(val))

    def closeEvent(self, event):
        self.timer.stop()
        super().closeEvent(event)


# ---------------------------------------------------------------------------
# Background workers
# ---------------------------------------------------------------------------

class ScanWorker(QThread):
    finished_ok = Signal(list, str)
    finished_err = Signal(str)

    def __init__(self, iface):
        super().__init__()
        self.iface = iface

    def run(self):
        try:
            own_ip = get_own_ip()
            try:
                gateway_ip = get_gateway_ip()
            except Exception:
                gateway_ip = ""
            subnet = get_local_subnet(own_ip)
            devices = scan_network(subnet, iface=self.iface)
            self.finished_ok.emit(devices, gateway_ip)
        except Exception as e:
            self.finished_err.emit(str(e))


class WifiScanWorker(QThread):
    finished_ok = Signal(list)
    finished_err = Signal(str)

    def run(self):
        try:
            networks = scan_wifi_networks()
            if networks is None:
                self.finished_err.emit("nmcli not found. Install with: sudo apt install network-manager")
            else:
                self.finished_ok.emit(networks)
        except Exception as e:
            self.finished_err.emit(str(e))


class SessionSetupWorker(QThread):
    ready = Signal(object, object)
    failed = Signal(str)

    def __init__(self, iface, scan_all, targets_str):
        super().__init__()
        self.iface = iface
        self.scan_all = scan_all
        self.targets_str = targets_str

    def run(self):
        try:
            if is_vpn_interface(self.iface):
                self.failed.emit(
                    f"'{self.iface}' is a VPN tunnel interface, not a real LAN adapter. "
                    f"ARP spoofing can't work over a VPN tunnel — pick your actual "
                    f"Wi-Fi/Ethernet interface in the Interfaces tab."
                )
                return

            own_ip = get_own_ip()
            gateway_ip = get_gateway_ip()
            gateway_mac = get_mac(gateway_ip, iface=self.iface)
            if not gateway_mac:
                self.failed.emit("Could not resolve gateway MAC address.")
                return

            targets = {}
            if self.targets_str.strip():
                for ip in self.targets_str.split(","):
                    ip = ip.strip()
                    mac = get_mac(ip, iface=self.iface)
                    if mac:
                        targets[ip] = mac
            elif self.scan_all:
                subnet = get_local_subnet(own_ip)
                devices = scan_network(subnet, iface=self.iface)
                for d in devices:
                    if d["ip"] not in (own_ip, gateway_ip):
                        targets[d["ip"]] = d["mac"]

            gateway_info = {"gateway_ip": gateway_ip, "gateway_mac": gateway_mac,
                             "own_mac": get_own_mac(self.iface)}
            self.ready.emit(targets, gateway_info)
        except Exception as e:
            self.failed.emit(str(e))


# ---------------------------------------------------------------------------
# Capture tab — the main live monitoring view
# ---------------------------------------------------------------------------

class CaptureTab(QWidget):
    def __init__(self, main_window):
        super().__init__()
        self.mw = main_window
        self._build_ui()

    def _build_ui(self):
        layout = QVBoxLayout(self)

        control_group = QGroupBox("CAPTURE CONTROL")
        control_layout = QHBoxLayout(control_group)
        control_layout.addWidget(QLabel("Targets:"))
        self.targets_input = QLineEdit()
        self.targets_input.setPlaceholderText("blank = scan all devices, or 192.168.1.10,192.168.1.15")
        control_layout.addWidget(self.targets_input, stretch=2)
        control_layout.addWidget(QLabel("Focus:"))
        self.focus_input = QLineEdit()
        self.focus_input.setPlaceholderText("optional: one IP to spotlight")
        self.focus_input.setMaximumWidth(180)
        control_layout.addWidget(self.focus_input)

        self.demo_btn = QPushButton("Start Demo")
        self.run_btn = QPushButton("Start Capture")
        self.run_btn.setObjectName("primary")
        self.stop_btn = QPushButton("Stop")
        self.stop_btn.setEnabled(False)
        self.demo_btn.clicked.connect(self.mw.start_demo)
        self.run_btn.clicked.connect(self.mw.start_run)
        self.stop_btn.clicked.connect(self.mw.stop_session)
        control_layout.addWidget(self.demo_btn)
        control_layout.addWidget(self.run_btn)
        control_layout.addWidget(self.stop_btn)
        layout.addWidget(control_group)

        self.graph = ThroughputGraph()
        layout.addWidget(self.graph, stretch=0)

        splitter = QSplitter(Qt.Horizontal)
        self.table = QTableWidget(0, 6)
        self.table.setHorizontalHeaderLabels(["TARGET", "TX", "RX", "RATE (up/down)", "PROTO", "HOST"])
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.table.cellDoubleClicked.connect(self._on_double_click)
        self.table.setToolTip("Double-click: view hostname history. Right-click name: rename device.")
        splitter.addWidget(self.table)

        stats_panel = QWidget()
        stats_layout = QVBoxLayout(stats_panel)
        stats_layout.setContentsMargins(0, 0, 0, 0)
        stats_title = QLabel("SESSION STATS")
        stats_title.setObjectName("sectionTitle")
        stats_layout.addWidget(stats_title)
        self.stats_table = QTableWidget(0, 2)
        self.stats_table.horizontalHeader().setVisible(False)
        self.stats_table.verticalHeader().setVisible(False)
        self.stats_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.stats_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        stats_layout.addWidget(self.stats_table, stretch=1)

        proto_title = QLabel("PROTOCOL MIX")
        proto_title.setObjectName("sectionTitle")
        stats_layout.addWidget(proto_title)
        self.proto_list = QListWidget()
        self.proto_list.setMaximumHeight(140)
        stats_layout.addWidget(self.proto_list)

        splitter.addWidget(stats_panel)
        splitter.setStretchFactor(0, 3)
        splitter.setStretchFactor(1, 1)
        splitter.setSizes([700, 260])
        layout.addWidget(splitter, stretch=1)

    def _on_double_click(self, row, _col):
        item = self.table.item(row, 0)
        if not item:
            return
        ip = item.data(Qt.UserRole) or item.text()
        self.mw.open_history_dialog(ip, item.text())

    def set_stat_rows(self, rows):
        self.stats_table.setRowCount(len(rows))
        for i, (k, v) in enumerate(rows):
            key_item = QTableWidgetItem(k)
            key_item.setForeground(QColor(TEXT_DIM))
            val_item = QTableWidgetItem(str(v))
            self.stats_table.setItem(i, 0, key_item)
            self.stats_table.setItem(i, 1, val_item)

    def reset(self):
        self.targets_input.clear()
        self.focus_input.clear()
        self.table.setRowCount(0)
        self.stats_table.setRowCount(0)
        self.proto_list.clear()
        self.graph.history.clear()
        self.graph.update()
        self.demo_btn.setEnabled(True)
        self.run_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)


# ---------------------------------------------------------------------------
# Devices tab — read-only discovery + aliasing
# ---------------------------------------------------------------------------

class DevicesTab(QWidget):
    def __init__(self, main_window):
        super().__init__()
        self.mw = main_window
        self._build_ui()

    def _build_ui(self):
        layout = QVBoxLayout(self)
        top = QHBoxLayout()
        self.scan_btn = QPushButton("Scan Devices")
        self.scan_btn.setObjectName("primary")
        self.scan_btn.clicked.connect(self._on_scan)
        top.addWidget(self.scan_btn)
        top.addStretch()
        layout.addLayout(top)

        self.table = QTableWidget(0, 3)
        self.table.setHorizontalHeaderLabels(["IP", "MAC", "ALIAS"])
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.table.cellDoubleClicked.connect(self._on_double_click)
        self.table.setToolTip("Double-click ALIAS column to set a friendly name. Double-click IP to view history.")
        layout.addWidget(self.table, stretch=1)

        self.status_label = QLabel("Not scanned yet.")
        self.status_label.setStyleSheet(f"color: {TEXT_DIM};")
        layout.addWidget(self.status_label)

    def _on_scan(self):
        self.scan_btn.setEnabled(False)
        self.status_label.setText("Scanning...")
        self.worker = ScanWorker(self.mw.iface)
        self.worker.finished_ok.connect(self._on_done)
        self.worker.finished_err.connect(self._on_error)
        self.worker.start()

    def _on_done(self, devices, gateway_ip):
        self.scan_btn.setEnabled(True)
        if not devices:
            diag = diagnose(gateway_ip)
            self.status_label.setText(f"0 devices found — {diag['headline']}")
            self.table.setRowCount(0)
            return
        aliases = load_aliases()
        self.status_label.setText(f"{len(devices)} device(s) found.")
        self.table.setRowCount(len(devices))
        for i, d in enumerate(devices):
            ip_item = QTableWidgetItem(d["ip"])
            mac_item = QTableWidgetItem(d["mac"])
            alias_item = QTableWidgetItem(aliases.get(d["ip"], ""))
            self.table.setItem(i, 0, ip_item)
            self.table.setItem(i, 1, mac_item)
            self.table.setItem(i, 2, alias_item)

    def _on_error(self, msg):
        self.scan_btn.setEnabled(True)
        self.status_label.setText(f"Error: {msg}")

    def _on_double_click(self, row, col):
        ip_item = self.table.item(row, 0)
        if not ip_item:
            return
        ip = ip_item.text()
        if col == 2:
            current = self.table.item(row, 2).text() if self.table.item(row, 2) else ""
            name, ok = QInputDialog.getText(self, "Set Alias", f"Friendly name for {ip}:", text=current)
            if ok:
                set_alias(ip, name.strip())
                self.table.setItem(row, 2, QTableWidgetItem(name.strip()))
                self.mw.reload_aliases()
        else:
            display = self.table.item(row, 2).text() if self.table.item(row, 2) else ""
            self.mw.open_history_dialog(ip, display or ip)

    def reset(self):
        self.table.setRowCount(0)
        self.status_label.setText("Not scanned yet.")


# ---------------------------------------------------------------------------
# Wi-Fi tab
# ---------------------------------------------------------------------------

class WifiTab(QWidget):
    def __init__(self, main_window):
        super().__init__()
        self.mw = main_window
        self._build_ui()

    def _build_ui(self):
        layout = QVBoxLayout(self)
        top = QHBoxLayout()
        self.scan_btn = QPushButton("Scan Nearby Networks")
        self.scan_btn.setObjectName("primary")
        self.scan_btn.clicked.connect(self._on_scan)
        top.addWidget(self.scan_btn)
        top.addStretch()
        layout.addLayout(top)

        self.table = QTableWidget(0, 5)
        self.table.setHorizontalHeaderLabels(["SSID", "SIGNAL", "SECURITY", "CHANNEL", "BSSID"])
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        layout.addWidget(self.table, stretch=1)

        self.status_label = QLabel("Not scanned yet.")
        self.status_label.setStyleSheet(f"color: {TEXT_DIM};")
        layout.addWidget(self.status_label)

    def _on_scan(self):
        self.scan_btn.setEnabled(False)
        self.status_label.setText("Scanning for Wi-Fi networks...")
        self.worker = WifiScanWorker()
        self.worker.finished_ok.connect(self._on_done)
        self.worker.finished_err.connect(self._on_error)
        self.worker.start()

    def _on_done(self, networks):
        self.scan_btn.setEnabled(True)
        if not networks:
            self.status_label.setText("No Wi-Fi networks found.")
            self.table.setRowCount(0)
            return
        danger_count = sum(1 for n in networks if n["security_level"] == "danger")
        self.status_label.setText(
            f"{len(networks)} network(s) found"
            + (f" — {danger_count} open/weak" if danger_count else "")
        )
        self.table.setRowCount(len(networks))
        for i, n in enumerate(networks):
            ssid_item = QTableWidgetItem(n["ssid"])
            signal_item = QTableWidgetItem(f"{n['signal']}%" if n["signal"].isdigit() else n["signal"])
            sec_item = QTableWidgetItem(n["security"])
            sec_item.setForeground(QColor(status_color(n["security_level"])))
            chan_item = QTableWidgetItem(n["channel"])
            bssid_item = QTableWidgetItem(n["bssid"])
            for col, item in enumerate([ssid_item, signal_item, sec_item, chan_item, bssid_item]):
                self.table.setItem(i, col, item)

    def _on_error(self, msg):
        self.scan_btn.setEnabled(True)
        self.status_label.setText(f"Error: {msg}")

    def reset(self):
        self.table.setRowCount(0)
        self.status_label.setText("Not scanned yet.")


# ---------------------------------------------------------------------------
# Guard tab — self-security check + live ARP watcher
# ---------------------------------------------------------------------------

class GuardTab(QWidget):
    def __init__(self, main_window):
        super().__init__()
        self.mw = main_window
        self.watcher = None
        self.watch_thread = None
        self.watch_stop = None
        self.watch_timer = QTimer()
        self.watch_timer.timeout.connect(self._refresh_watch)
        self._build_ui()

    def _build_ui(self):
        layout = QVBoxLayout(self)

        top = QHBoxLayout()
        self.check_btn = QPushButton("Run Self-Security Check")
        self.check_btn.setObjectName("primary")
        self.check_btn.clicked.connect(self._on_check)
        top.addWidget(self.check_btn)
        self.watch_btn = QPushButton("Start ARP Watch")
        self.watch_btn.clicked.connect(self._on_toggle_watch)
        top.addWidget(self.watch_btn)
        top.addStretch()
        layout.addLayout(top)

        check_title = QLabel("SELF-SECURITY REPORT")
        check_title.setObjectName("sectionTitle")
        layout.addWidget(check_title)
        self.check_table = QTableWidget(0, 2)
        self.check_table.horizontalHeader().setVisible(False)
        self.check_table.verticalHeader().setVisible(False)
        self.check_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.check_table.setMaximumHeight(150)
        self.check_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        layout.addWidget(self.check_table)

        splitter = QSplitter(Qt.Horizontal)
        arp_panel = QWidget()
        arp_layout = QVBoxLayout(arp_panel)
        arp_layout.setContentsMargins(0, 0, 0, 0)
        arp_title = QLabel("ARP ACTIVITY (passive — listens only, never sends)")
        arp_title.setObjectName("sectionTitle")
        arp_layout.addWidget(arp_title)
        self.arp_table = QTableWidget(0, 3)
        self.arp_table.setHorizontalHeaderLabels(["IP", "MAC(S) SEEN", "STATUS"])
        self.arp_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.arp_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        arp_layout.addWidget(self.arp_table)
        splitter.addWidget(arp_panel)

        alert_panel = QWidget()
        alert_layout = QVBoxLayout(alert_panel)
        alert_layout.setContentsMargins(0, 0, 0, 0)
        alert_title = QLabel("ALERTS")
        alert_title.setObjectName("sectionTitle")
        alert_layout.addWidget(alert_title)
        self.alert_list = QListWidget()
        alert_layout.addWidget(self.alert_list)
        splitter.addWidget(alert_panel)
        splitter.setStretchFactor(0, 2)
        splitter.setStretchFactor(1, 1)

        layout.addWidget(splitter, stretch=1)

    def _on_check(self):
        self.check_btn.setEnabled(False)
        try:
            sec = check_own_security()
        finally:
            self.check_btn.setEnabled(True)

        rows = []
        if sec["wifi"]:
            w = sec["wifi"]
            rows.append(("Connected Wi-Fi", f"{w['ssid']} — {w['security']}"))
        else:
            rows.append(("Connected Wi-Fi", "Not on Wi-Fi, or undetermined"))

        fw = sec["firewall"]
        fw_label = {"active": "Enabled", "inactive": "Disabled", "unknown": "Not detected (ufw not installed)"}.get(fw, fw)
        rows.append(("Firewall (ufw)", fw_label))

        ports = sec["open_ports"]
        if ports is None:
            rows.append(("Listening ports", "Could not check (ss/netstat unavailable)"))
        else:
            exposed = [p for p in ports if p["exposed"]]
            rows.append(("Listening ports", f"{len(ports)} total, {len(exposed)} exposed to LAN"))
            for p in exposed[:8]:
                rows.append((f"  exposed: {p['proto']}:{p['port']}", p["process"] or "?"))

        self.check_table.setRowCount(len(rows))
        for i, (k, v) in enumerate(rows):
            key_item = QTableWidgetItem(k)
            key_item.setForeground(QColor(TEXT_DIM))
            self.check_table.setItem(i, 0, key_item)
            self.check_table.setItem(i, 1, QTableWidgetItem(str(v)))

    def _on_toggle_watch(self):
        if self.watcher is None:
            try:
                gateway_ip = get_gateway_ip()
            except Exception:
                gateway_ip = None
            self.watcher = ArpWatcher(gateway_ip=gateway_ip)
            self.watch_stop = threading.Event()
            self.watch_thread = threading.Thread(
                target=run_arp_watcher, args=(self.mw.iface, self.watcher, self.watch_stop),
                daemon=True,
            )
            self.watch_thread.start()
            self.watch_timer.start(1000)
            self.watch_btn.setText("Stop ARP Watch")
            self.mw.status_dot.set_state(OK, "WATCHING")
        else:
            self._stop_watch()

    def _stop_watch(self):
        if self.watch_stop:
            self.watch_stop.set()
        self.watch_timer.stop()
        self.watcher = None
        self.watch_stop = None
        self.watch_btn.setText("Start ARP Watch")
        if self.mw.mode == "IDLE":
            self.mw.status_dot.set_state(TEXT_DIM, "IDLE")

    def _refresh_watch(self):
        if not self.watcher:
            return
        table_data, alerts, count = self.watcher.snapshot()
        gateway_ip = self.watcher.gateway_ip

        self.arp_table.setRowCount(len(table_data))
        for i, (ip, macs) in enumerate(sorted(table_data.items())):
            mac_list = ", ".join(macs.keys())
            is_gateway = ip == gateway_ip
            flagged = len(macs) > 1
            label = f"{ip} (gateway)" if is_gateway else ip
            status_item = QTableWidgetItem("MULTIPLE MACS" if flagged else "OK")
            status_item.setForeground(QColor(DANGER if flagged else OK))
            self.arp_table.setItem(i, 0, QTableWidgetItem(label))
            self.arp_table.setItem(i, 1, QTableWidgetItem(mac_list))
            self.arp_table.setItem(i, 2, status_item)

        self.alert_list.clear()
        for ts, sev, msg in alerts[-30:]:
            item = QListWidgetItem(f"[{ts}] {msg}")
            item.setForeground(QColor(DANGER if sev == "high" else WARN))
            self.alert_list.addItem(item)

    def reset(self):
        self._stop_watch()
        self.check_table.setRowCount(0)
        self.arp_table.setRowCount(0)
        self.alert_list.clear()


# ---------------------------------------------------------------------------
# History tab — browse a saved CSV log
# ---------------------------------------------------------------------------

class HistoryTab(QWidget):
    def __init__(self, main_window):
        super().__init__()
        self.mw = main_window
        self.log_path = None
        self._build_ui()

    def _build_ui(self):
        layout = QVBoxLayout(self)
        top = QHBoxLayout()
        self.open_btn = QPushButton("Open Log File...")
        self.open_btn.setObjectName("primary")
        self.open_btn.clicked.connect(self._on_open)
        top.addWidget(self.open_btn)
        self.device_combo = QComboBox()
        self.device_combo.setMinimumWidth(200)
        self.device_combo.currentTextChanged.connect(self._on_device_changed)
        top.addWidget(QLabel("Device:"))
        top.addWidget(self.device_combo)
        top.addStretch()
        layout.addLayout(top)

        self.path_label = QLabel("No log file open.")
        self.path_label.setStyleSheet(f"color: {TEXT_DIM};")
        layout.addWidget(self.path_label)

        self.table = QTableWidget(0, 7)
        self.table.setHorizontalHeaderLabels(
            ["TIME", "SENT", "RECV", "TOTAL", "RATE/S", "PROTOCOL", "HOSTNAME"]
        )
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        layout.addWidget(self.table, stretch=1)

    def _on_open(self):
        path, _ = QFileDialog.getOpenFileName(self, "Open WireHawk Log", "", "CSV files (*.csv)")
        if not path:
            return
        self.log_path = path
        self.path_label.setText(path)
        devices = list_logged_devices(path)
        self.device_combo.clear()
        self.device_combo.addItems(devices)
        if devices:
            self._load_device(devices[0])

    def _on_device_changed(self, text):
        if text and self.log_path:
            self._load_device(text)

    def _load_device(self, device):
        if not self.log_path:
            return
        rows = read_device_history(self.log_path, device)
        self.table.setRowCount(len(rows))
        for i, row in enumerate(rows):
            values = [
                row.get("timestamp", ""), row.get("bytes_sent", ""), row.get("bytes_recv", ""),
                row.get("total_bytes", ""), row.get("rate_bytes_per_sec", ""),
                row.get("top_protocol", ""), row.get("hostname", ""),
            ]
            for col, val in enumerate(values):
                self.table.setItem(i, col, QTableWidgetItem(str(val)))

    def reset(self):
        self.log_path = None
        self.path_label.setText("No log file open.")
        self.device_combo.clear()
        self.table.setRowCount(0)


# ---------------------------------------------------------------------------
# Interfaces tab
# ---------------------------------------------------------------------------

class InterfacesTab(QWidget):
    def __init__(self, main_window):
        super().__init__()
        self.mw = main_window
        self._build_ui()
        self._refresh()

    def _build_ui(self):
        layout = QVBoxLayout(self)
        top = QHBoxLayout()
        self.refresh_btn = QPushButton("Refresh List")
        self.refresh_btn.clicked.connect(self._refresh)
        top.addWidget(self.refresh_btn)
        self.use_btn = QPushButton("Use Selected Interface")
        self.use_btn.setObjectName("primary")
        self.use_btn.clicked.connect(self._on_use)
        top.addWidget(self.use_btn)
        top.addStretch()
        layout.addLayout(top)

        self.table = QTableWidget(0, 5)
        self.table.setHorizontalHeaderLabels(["NAME", "TYPE", "MAC", "HAS IP", "DEFAULT"])
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        layout.addWidget(self.table, stretch=1)

        note = QLabel(
            "VPN interfaces are flagged here and cannot be used for real capture — "
            "ARP spoofing operates at the LAN link layer and doesn't work over a tunnel."
        )
        note.setWordWrap(True)
        note.setStyleSheet(f"color: {TEXT_DIM};")
        layout.addWidget(note)

    def _refresh(self):
        interfaces = list_all_interfaces()
        self.table.setRowCount(len(interfaces))
        for i, iface in enumerate(interfaces):
            type_item = QTableWidgetItem(iface["type"])
            if iface["type"] == "VPN":
                type_item.setForeground(QColor(WARN))
            name_item = QTableWidgetItem(iface["name"])
            if iface["is_default"]:
                name_item.setForeground(QColor(ACCENT))
            self.table.setItem(i, 0, name_item)
            self.table.setItem(i, 1, type_item)
            self.table.setItem(i, 2, QTableWidgetItem(iface["mac"]))
            self.table.setItem(i, 3, QTableWidgetItem("yes" if iface["has_ip"] else "no"))
            self.table.setItem(i, 4, QTableWidgetItem("yes" if iface["is_default"] else ""))

    def _on_use(self):
        rows = self.table.selectionModel().selectedRows()
        if not rows:
            QMessageBox.information(self, "Select an interface", "Select a row first.")
            return
        name = self.table.item(rows[0].row(), 0).text()
        if is_vpn_interface(name):
            QMessageBox.warning(
                self, "VPN interface",
                f"'{name}' is a VPN tunnel. Real capture/ARP spoofing can't work over it — "
                f"pick a Wi-Fi or Ethernet interface instead.",
            )
            return
        self.mw.set_interface(name)

    def reset(self):
        self._refresh()


# ---------------------------------------------------------------------------
# Main window
# ---------------------------------------------------------------------------

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("WireHawk — Network Traffic Analyzer")
        self.resize(1200, 760)
        self.setStyleSheet(STYLESHEET)
        if ICON_PATH.exists():
            self.setWindowIcon(QIcon(str(ICON_PATH)))

        self.iface = get_default_iface() or "eth0"
        self.iface_type = get_iface_type(self.iface)
        self.aliases = load_aliases()

        self._init_session_state()
        self._open_history_dialogs = []

        self._build_menu_and_toolbar()
        self._build_central()
        self._build_status_bar()

        self.timer = QTimer()
        self.timer.timeout.connect(self._refresh_capture)
        self.timer.setInterval(1000)

    def _init_session_state(self):
        self.stats = None
        self.stop_event = None
        self.spoofer = None
        self.sim_thread = None
        self.capture_thread = None
        self.device_names = {}
        self.prev_totals = {}
        self.rate_history = {}
        self.session_start = None
        self.mode = "IDLE"

    # -- chrome --

    def _build_menu_and_toolbar(self):
        style = self.style()
        menubar = self.menuBar()

        file_menu = menubar.addMenu("&File")
        export_action = QAction("Export Session to CSV...", self)
        export_action.triggered.connect(self._on_export_csv)
        file_menu.addAction(export_action)
        file_menu.addSeparator()
        exit_action = QAction("Exit", self)
        exit_action.triggered.connect(self.close)
        file_menu.addAction(exit_action)

        capture_menu = menubar.addMenu("&Capture")
        self.action_demo = QAction("Start Demo", self)
        self.action_demo.triggered.connect(self.start_demo)
        capture_menu.addAction(self.action_demo)
        self.action_run = QAction("Start Capture", self)
        self.action_run.triggered.connect(self.start_run)
        capture_menu.addAction(self.action_run)
        self.action_stop = QAction("Stop", self)
        self.action_stop.triggered.connect(self.stop_session)
        self.action_stop.setEnabled(False)
        capture_menu.addAction(self.action_stop)
        capture_menu.addSeparator()
        self.action_refresh = QAction("Refresh (reset everything)", self)
        self.action_refresh.triggered.connect(self.full_reset)
        capture_menu.addAction(self.action_refresh)

        analyze_menu = menubar.addMenu("&Analyze")
        history_action = QAction("View Device History...", self)
        history_action.triggered.connect(self._on_view_history_prompt)
        analyze_menu.addAction(history_action)

        help_menu = menubar.addMenu("&Help")
        about_action = QAction("About WireHawk", self)
        about_action.triggered.connect(self._on_about)
        help_menu.addAction(about_action)

        toolbar = QToolBar("Main")
        toolbar.setMovable(False)
        self.addToolBar(toolbar)
        self.action_demo.setIcon(style.standardIcon(QStyle.SP_MediaPlay))
        self.action_run.setIcon(style.standardIcon(QStyle.SP_DialogYesButton))
        self.action_stop.setIcon(style.standardIcon(QStyle.SP_MediaStop))
        self.action_refresh.setIcon(style.standardIcon(QStyle.SP_RestoreDefaultsButton))
        export_action.setIcon(style.standardIcon(QStyle.SP_DialogSaveButton))
        for action in (self.action_demo, self.action_run, self.action_stop):
            toolbar.addAction(action)
        toolbar.addSeparator()
        toolbar.addAction(export_action)
        toolbar.addAction(self.action_refresh)

    def _build_central(self):
        central = QWidget()
        self.setCentralWidget(central)
        layout = QVBoxLayout(central)
        layout.setContentsMargins(0, 0, 0, 0)

        header = QHBoxLayout()
        header.setContentsMargins(10, 8, 10, 4)
        logo = QLabel("WIREHAWK")
        logo.setObjectName("logo")
        header.addWidget(logo)
        header.addStretch()
        self.iface_label = QLabel(f"{self.iface} ({self.iface_type})")
        self.iface_label.setStyleSheet(f"color: {TEXT_DIM};")
        header.addWidget(self.iface_label)
        layout.addLayout(header)

        self.diagnosis_label = QLabel("")
        self.diagnosis_label.setStyleSheet(f"color: {WARN}; font-weight: 600; padding: 4px 10px;")
        self.diagnosis_label.setWordWrap(True)
        self.diagnosis_label.setVisible(False)
        layout.addWidget(self.diagnosis_label)

        self.tabs = QTabWidget()
        self.capture_tab = CaptureTab(self)
        self.devices_tab = DevicesTab(self)
        self.wifi_tab = WifiTab(self)
        self.guard_tab = GuardTab(self)
        self.history_tab = HistoryTab(self)
        self.interfaces_tab = InterfacesTab(self)
        self.tabs.addTab(self.capture_tab, "Capture")
        self.tabs.addTab(self.devices_tab, "Devices")
        self.tabs.addTab(self.wifi_tab, "Wi-Fi")
        self.tabs.addTab(self.guard_tab, "Guard")
        self.tabs.addTab(self.history_tab, "History")
        self.tabs.addTab(self.interfaces_tab, "Interfaces")
        layout.addWidget(self.tabs, stretch=1)

    def _build_status_bar(self):
        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)
        self.status_dot = StatusDot()
        self.status_bar.addWidget(self.status_dot)
        self.status_text = QLabel("No session running.")
        self.status_bar.addWidget(self.status_text, stretch=1)

    def _on_about(self):
        QMessageBox.information(
            self, "About WireHawk",
            "WireHawk — Network Traffic Analyzer\n\n"
            "Per-device bandwidth, protocol, and hostname visibility on any "
            "LAN, without router admin access.\n\n"
            "Only use real capture/ARP features on networks and devices you "
            "own or have explicit permission to monitor.",
        )

    def set_interface(self, name):
        self.iface = name
        self.iface_type = get_iface_type(name)
        self.iface_label.setText(f"{self.iface} ({self.iface_type})")
        self.status_text.setText(f"Interface set to {name}.")

    def reload_aliases(self):
        self.aliases = load_aliases()

    # -- diagnosis banner --

    def _set_diagnosis(self, text):
        self.diagnosis_label.setText(text)
        self.diagnosis_label.setVisible(bool(text))

    def _error(self, message):
        QMessageBox.critical(self, "WireHawk — Error", message)

    # -- history dialog --

    def open_history_dialog(self, ip, display_name):
        dialog = DeviceHistoryDialog(self, lambda: self.stats, ip, display_name)
        self._open_history_dialogs.append(dialog)
        dialog.show()

    def _on_view_history_prompt(self):
        ip, ok = QInputDialog.getText(self, "View Device History", "Device IP address:")
        if ok and ip.strip():
            self.open_history_dialog(ip.strip(), ip.strip())

    # -- export --

    def _on_export_csv(self):
        if not self.stats:
            self._error("No active session to export. Start Demo or Capture first.")
            return
        path, _ = QFileDialog.getSaveFileName(self, "Export Session CSV", "wirehawk_session.csv", "CSV files (*.csv)")
        if not path:
            return
        snapshot = self.stats.snapshot()
        elapsed = time.time() - self.session_start if self.session_start else 0
        try:
            with open(path, "w", newline="") as f:
                writer = csv.writer(f)
                writer.writerow(["device", "bytes_sent", "bytes_recv", "total_bytes",
                                  "avg_rate_bytes_per_sec", "top_protocol", "hostname"])
                for ip, d in snapshot.items():
                    total = d["bytes_sent"] + d["bytes_recv"]
                    rate = total / elapsed if elapsed > 0 else 0
                    top_proto = max(d["protocols"].items(), key=lambda x: x[1])[0] if d["protocols"] else ""
                    hostname = d["hostnames"][0] if d["hostnames"] else ""
                    name = self.device_names.get(ip, ip)
                    writer.writerow([name, d["bytes_sent"], d["bytes_recv"], total,
                                      f"{rate:.1f}", top_proto, hostname])
            self.status_text.setText(f"Session exported to {path}")
        except Exception as e:
            self._error(f"Could not export: {e}")

    # -- demo --

    def start_demo(self):
        self._start_session(mode="DEMO")
        self.device_names = apply_aliases(fake_device_names())
        self.sim_thread = threading.Thread(
            target=run_simulation, args=(self.stats, self.stop_event), daemon=True,
        )
        self.sim_thread.start()

        try:
            gateway_ip = get_gateway_ip()
        except Exception:
            gateway_ip = None
        diag = diagnose(gateway_ip)
        self._set_diagnosis(f"Demo mode — real network diagnosis: {diag['headline']}")

        self.status_text.setText("Demo mode running — simulated traffic.")
        self.status_dot.set_state(OK, "DEMO")
        self._set_running_ui(True)

    # -- real capture --

    def start_run(self):
        self.action_run.setEnabled(False)
        self.capture_tab.run_btn.setEnabled(False)
        self.status_text.setText("Resolving network / gateway...")
        targets_str = self.capture_tab.targets_input.text()
        self.setup_worker = SessionSetupWorker(self.iface, scan_all=True, targets_str=targets_str)
        self.setup_worker.ready.connect(self._on_run_ready)
        self.setup_worker.failed.connect(self._on_run_failed)
        self.setup_worker.start()

    def _on_run_failed(self, msg):
        self.action_run.setEnabled(True)
        self.capture_tab.run_btn.setEnabled(True)
        self._error(f"Could not start capture: {msg}")
        self.status_text.setText("Setup failed.")

    def _on_run_ready(self, targets, gateway_info):
        if not targets:
            diag = diagnose(gateway_info.get("gateway_ip"))
            self._set_diagnosis(f"{diag['headline']}\n" + "\n".join(diag["details"]))
            self.action_run.setEnabled(True)
            self.capture_tab.run_btn.setEnabled(True)
            self.status_text.setText("No valid targets found — see diagnosis above.")
            return

        other_vpns = list_vpn_interfaces()
        if other_vpns:
            self._set_diagnosis(
                f"Note: a VPN is also active on this system ({', '.join(other_vpns)}). "
                f"Monitoring other LAN devices should still work, but your own traffic "
                f"may route through the VPN and not appear accurately here."
            )
        else:
            self._set_diagnosis("")

        self._start_session(mode="ACTIVE")
        self.device_names = apply_aliases({ip: ip for ip in targets})

        self.spoofer = ARPSpoofer(
            own_mac=gateway_info["own_mac"], gateway_ip=gateway_info["gateway_ip"],
            gateway_mac=gateway_info["gateway_mac"], iface=self.iface,
        )
        for ip, mac in targets.items():
            self.spoofer.add_target(ip, mac)

        try:
            with open("/proc/sys/net/ipv4/ip_forward", "w") as f:
                f.write("1")
        except Exception:
            pass

        self.spoofer.start()
        local_ips = set(targets.keys())
        self.capture_thread = threading.Thread(
            target=start_capture, args=(self.iface, self.stats, local_ips, self.stop_event),
            daemon=True,
        )
        self.capture_thread.start()

        self.status_text.setText(f"Capturing — monitoring {len(targets)} device(s).")
        self.status_dot.set_state(DANGER, "CAPTURING")
        self._set_running_ui(True)

    def _start_session(self, mode):
        self.stats = PacketStats()
        self.stop_event = threading.Event()
        self.prev_totals = {}
        self.rate_history = {}
        self.session_start = time.time()
        self.mode = mode
        self.capture_tab.graph.history.clear()
        self.capture_tab.table.setRowCount(0)
        self.timer.start()

    def _set_running_ui(self, running):
        self.action_demo.setEnabled(not running)
        self.action_run.setEnabled(not running)
        self.action_stop.setEnabled(running)
        self.capture_tab.demo_btn.setEnabled(not running)
        self.capture_tab.run_btn.setEnabled(not running)
        self.capture_tab.stop_btn.setEnabled(running)

    def stop_session(self):
        if self.stop_event:
            self.stop_event.set()
        if self.spoofer:
            self.spoofer.stop_and_restore()
            try:
                with open("/proc/sys/net/ipv4/ip_forward", "w") as f:
                    f.write("0")
            except Exception:
                pass
            self.spoofer = None
        self.timer.stop()
        self._set_running_ui(False)
        self.status_text.setText("Session stopped — network restored.")
        self.mode = "IDLE"
        if not (self.guard_tab.watcher):
            self.status_dot.set_state(TEXT_DIM, "IDLE")

    def _refresh_capture(self):
        if not self.stats:
            return
        now = time.time()
        elapsed = now - self.session_start
        snapshot = self.stats.snapshot()

        total_rate = 0.0
        rows = []
        for ip, d in snapshot.items():
            total = d["bytes_sent"] + d["bytes_recv"]
            prev = self.prev_totals.get(ip, total)
            rate = max(total - prev, 0)
            total_rate += rate
            self.prev_totals[ip] = total
            rows.append((ip, d, rate))

        self.capture_tab.graph.add_value(total_rate)

        rows.sort(key=lambda r: r[1]["bytes_sent"] + r[1]["bytes_recv"], reverse=True)
        focus_ip = self.capture_tab.focus_input.text().strip()
        if focus_ip:
            rows = [r for r in rows if r[0] == focus_ip] or rows

        table = self.capture_tab.table
        table.setRowCount(len(rows))
        for i, (ip, d, rate) in enumerate(rows):
            name = self.device_names.get(ip, ip)
            up = d["bytes_sent"] / elapsed if elapsed > 0 else 0
            down = d["bytes_recv"] / elapsed if elapsed > 0 else 0
            proto = " ".join(f"{p}x{c}" for p, c in sorted(d["protocols"].items(), key=lambda x: -x[1])[:2])
            host = ", ".join(d["hostnames"][:1]) or "-"
            values = [name, format_bytes(d["bytes_sent"]), format_bytes(d["bytes_recv"]),
                      f"{format_bytes(up)}/s / {format_bytes(down)}/s", proto, host]
            for col, val in enumerate(values):
                item = QTableWidgetItem(val)
                if col == 0:
                    item.setData(Qt.UserRole, ip)
                table.setItem(i, col, item)

        proto_totals = Counter()
        for d in snapshot.values():
            for p, c in d["protocols"].items():
                proto_totals[p] += c
        total_proto = sum(proto_totals.values()) or 1

        self.capture_tab.set_stat_rows([
            ("Mode", self.mode),
            ("Devices", len(snapshot)),
            ("Uptime", f"{int(elapsed)}s"),
            ("Current rate", f"{format_bytes(total_rate)}/s"),
            ("Interface", f"{self.iface} ({self.iface_type})"),
        ])
        self.capture_tab.proto_list.clear()
        for p, c in proto_totals.most_common(8):
            self.capture_tab.proto_list.addItem(f"{p:<8} {c/total_proto*100:5.1f}%  ({c} pkts)")

    # -- global refresh --

    def full_reset(self):
        """Stops any active session, stops the ARP watcher if running,
        closes every open history window, and resets every tab back to
        its empty, freshly-launched state."""
        if self.mode != "IDLE":
            self.stop_session()
        self.guard_tab._stop_watch()

        for dialog in self._open_history_dialogs:
            try:
                dialog.close()
            except RuntimeError:
                pass
        self._open_history_dialogs = []

        self._init_session_state()
        self._set_diagnosis("")
        self.status_text.setText("No session running.")
        self.status_dot.set_state(TEXT_DIM, "IDLE")

        self.capture_tab.reset()
        self.devices_tab.reset()
        self.wifi_tab.reset()
        self.guard_tab.reset()
        self.history_tab.reset()
        self.interfaces_tab.reset()
        self.tabs.setCurrentIndex(0)

    def closeEvent(self, event):
        """Safety net: if the window is closed (× button, Alt+F4, etc.)
        while a real capture session is active, the ARP tables and IP
        forwarding setting would otherwise never get restored — the
        target devices would be left with poisoned ARP caches pointing
        at this now-closed app until the entries naturally expire.
        This runs the same cleanup Stop does, and stops the ARP
        watcher too, before actually allowing the window to close."""
        if self.mode != "IDLE":
            self.stop_session()
        if self.guard_tab.watcher is not None:
            self.guard_tab._stop_watch()
        for dialog in self._open_history_dialogs:
            try:
                dialog.close()
            except RuntimeError:
                pass
        super().closeEvent(event)


def main():
    app = QApplication(sys.argv)
    if ICON_PATH.exists():
        app.setWindowIcon(QIcon(str(ICON_PATH)))
    window = MainWindow()
    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
