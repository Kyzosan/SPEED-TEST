import sys
from PyQt5.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, 
                             QPushButton, QLineEdit, QTextEdit, QLabel, QTabWidget, QStatusBar,
                             QGroupBox, QRadioButton, QButtonGroup, QProgressBar, QFileDialog,
                             QMessageBox, QCheckBox, QSpinBox, QFormLayout, QDialog, QMenu)
from PyQt5.QtCore import QThread, pyqtSignal, QTimer
from PyQt5.QtGui import QFont
from network_ops import detect_ips, ping_host, traceroute_host, port_scan, run_speedtest, whois_lookup
from settings import AppSettings
from logger import app_logger

class IPDetectionThread(QThread):
    finished = pyqtSignal(str, str)

    def run(self):
        local, public = detect_ips(timeout=AppSettings().get_public_ip_timeout())
        self.finished.emit(local, public)

class SettingsDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Settings")
        self.setGeometry(300, 300, 400, 200)

        layout = QVBoxLayout()

        self.settings = AppSettings()

        form_layout = QFormLayout()
        self.timeout_spin = QSpinBox()
        self.timeout_spin.setRange(1, 30)
        self.timeout_spin.setValue(self.settings.get_public_ip_timeout())
        form_layout.addRow("Public IP Timeout (s):", self.timeout_spin)

        self.threads_spin = QSpinBox()
        self.threads_spin.setRange(1, 500)
        self.threads_spin.setValue(self.settings.get_port_scan_threads())
        form_layout.addRow("Port Scan Threads:", self.threads_spin)

        self.default_ip_group = QButtonGroup()
        rb_public = QRadioButton("Public IP")
        rb_local = QRadioButton("Local IP")
        self.default_ip_group.addButton(rb_public, 0)
        self.default_ip_group.addButton(rb_local, 1)
        if self.settings.get_default_ip_choice() == "local":
            rb_local.setChecked(True)
        else:
            rb_public.setChecked(True)
        ip_layout = QHBoxLayout()
        ip_layout.addWidget(rb_public)
        ip_layout.addWidget(rb_local)
        form_layout.addRow("Default IP Choice:", ip_layout)

        self.advanced_mode_check = QCheckBox("Enable Advanced Mode")
        self.advanced_mode_check.setChecked(self.settings.get_advanced_mode())
        form_layout.addRow("", self.advanced_mode_check)

        layout.addLayout(form_layout)

        btn_layout = QHBoxLayout()
        self.save_btn = QPushButton("Save")
        self.cancel_btn = QPushButton("Cancel")
        btn_layout.addWidget(self.save_btn)
        btn_layout.addWidget(self.cancel_btn)

        layout.addLayout(btn_layout)

        self.save_btn.clicked.connect(self.save_settings)
        self.cancel_btn.clicked.connect(self.reject)

        self.setLayout(layout)

    def save_settings(self):
        self.settings.set_public_ip_timeout(self.timeout_spin.value())
        self.settings.set_port_scan_threads(self.threads_spin.value())
        if self.default_ip_group.checkedId() == 1:
            self.settings.set_default_ip_choice("local")
        else:
            self.settings.set_default_ip_choice("public")
        self.settings.set_advanced_mode(self.advanced_mode_check.isChecked())
        self.accept()

class NetworkToolTab(QWidget):
    def __init__(self, tool_func, input_label="Target Host/IP:", output_label="Output:", requires_target=True):
        super().__init__()
        self.tool_func = tool_func
        self.requires_target = requires_target
        self.local_ip = None
        self.public_ip = None
        self.is_running = False
        self.settings = AppSettings()

        layout = QVBoxLayout()

        # Input area
        input_layout = QHBoxLayout()
        input_layout.addWidget(QLabel(input_label))
        self.input_field = QLineEdit()
        self.input_field.setPlaceholderText("Enter IP or domain (leave empty to auto-detect)")
        input_layout.addWidget(self.input_field)

        self.detect_btn = QPushButton("Detect IP")
        self.detect_btn.clicked.connect(self.detect_ips)
        input_layout.addWidget(self.detect_btn)

        layout.addLayout(input_layout)

        # Advanced options (initially hidden)
        self.advanced_widget = QWidget()
        self.advanced_layout = QHBoxLayout()
        self.advanced_widget.setLayout(self.advanced_layout)
        self.advanced_widget.setVisible(self.settings.get_advanced_mode())
        layout.addWidget(self.advanced_widget)

        # IP selection group (hidden initially)
        self.ip_group = QGroupBox("Detected IPs (click 'Detect IP' or Run to show)")
        self.ip_group.setVisible(False)
        ip_layout = QVBoxLayout()
        self.rb_public = QRadioButton("Public IP")
        self.rb_local = QRadioButton("Local IP")
        self.rb_public.setChecked(self.settings.get_default_ip_choice() == "public")
        self.rb_local.setChecked(self.settings.get_default_ip_choice() == "local")
        self.ip_group_box = QButtonGroup()
        self.ip_group_box.addButton(self.rb_public)
        self.ip_group_box.addButton(self.rb_local)
        ip_layout.addWidget(self.rb_public)
        ip_layout.addWidget(self.rb_local)
        self.ip_group.setLayout(ip_layout)
        layout.addWidget(self.ip_group)

        # Run button
        self.run_btn = QPushButton("Run")
        self.run_btn.clicked.connect(self.run_tool)
        layout.addWidget(self.run_btn)

        # Progress bar
        self.progress = QProgressBar()
        self.progress.setVisible(False)
        layout.addWidget(self.progress)

        # Output area
        layout.addWidget(QLabel(output_label))
        self.output_area = QTextEdit()
        self.output_area.setReadOnly(True)
        layout.addWidget(self.output_area)

        self.setLayout(layout)

    def detect_ips(self):
        if self.is_running:
            return
        self.ip_detection_thread = IPDetectionThread()
        self.ip_detection_thread.finished.connect(self.on_ip_detected)
        self.ip_detection_thread.start()
        self.progress.setVisible(True)
        self.progress.setRange(0, 0)  # Indeterminate

    def on_ip_detected(self, local, public):
        self.local_ip = local
        self.public_ip = public
        self.progress.setVisible(False)
        self.progress.setRange(0, 1)

        if not public:
            self.output_area.append("⚠️ Public IP detection failed — using local IP.")
            self.rb_public.setEnabled(False)
            if self.settings.get_default_ip_choice() == "public":
                self.rb_local.setChecked(True)
        else:
            self.rb_public.setText(f"Public IP: {public}")
            self.rb_public.setEnabled(True)
            if self.settings.get_default_ip_choice() == "public":
                self.rb_public.setChecked(True)

        if local:
            self.rb_local.setText(f"Local IP: {local}")
        else:
            self.rb_local.setEnabled(False)

        self.ip_group.setVisible(True)
        self.update_status_bar()

    def update_status_bar(self):
        if self.local_ip or self.public_ip:
            status_text = f"Local: {self.local_ip or 'N/A'} | Public: {self.public_ip or 'N/A'}"
            self.parent().parent().statusBar().showMessage(status_text)

    def run_tool(self):
        if self.is_running:
            return

        target = self.input_field.text().strip()
        if not target:
            if not self.requires_target:
                target = "localhost" # Contoh untuk speedtest
            else:
                if not self.public_ip and not self.local_ip:
                    self.detect_ips()
                    return
                # Auto-select IP based on availability and default setting
                if self.rb_public.isChecked() and self.public_ip:
                    target = self.public_ip
                elif self.local_ip:
                    target = self.local_ip
                else:
                    self.output_area.append("❌ No IP detected to run test.")
                    return

        self.is_running = True
        self.progress.setVisible(True)
        self.progress.setRange(0, 0)
        self.run_btn.setEnabled(False)
        self.output_area.append(f"⏳ Running on target: {target}...")

        # Jalankan fungsi di thread terpisah
        self.tool_thread = ToolThread(self.tool_func, target)
        self.tool_thread.result_ready.connect(self.on_tool_finished)
        self.tool_thread.start()

    def on_tool_finished(self, result):
        self.output_area.append("\n" + result)
        self.is_running = False
        self.progress.setVisible(False)
        self.run_btn.setEnabled(True)

class ToolThread(QThread):
    result_ready = pyqtSignal(str)

    def __init__(self, func, *args):
        super().__init__()
        self.func = func
        self.args = args

    def run(self):
        try:
            result = self.func(*self.args)
            self.result_ready.emit(str(result))
        except Exception as e:
            self.result_ready.emit(f"❌ Error: {e}")

class PortScannerTab(NetworkToolTab):
    def __init__(self):
        super().__init__(self.scan_ports, "Target Host/IP:", "Port Scan Results:", requires_target=True)
        port_layout = QHBoxLayout()
        port_layout.addWidget(QLabel("Port Range (e.g., 1-1000):"))
        self.port_range = QLineEdit("1-1000")
        port_layout.addWidget(self.port_range)
        self.layout().insertLayout(1, port_layout)

    def scan_ports(self, host):
        range_text = self.port_range.text()
        try:
            start, end = map(int, range_text.split('-'))
        except ValueError:
            return "❌ Invalid port range. Please use format: start-end (e.g., 1-1000)."

        self.output_area.append(f"⏳ Scanning ports {start}-{end} on {host}...")
        open_ports = port_scan(
            host,
            start,
            end,
            max_threads=AppSettings().get_port_scan_threads()
        )
        if open_ports:
            return f"✅ Open ports: {open_ports}"
        else:
            return "✅ No open ports found in range."

class SpeedtestTab(QWidget):
    def __init__(self):
        super().__init__()
        layout = QVBoxLayout()

        self.run_btn = QPushButton("Run Speedtest")
        self.run_btn.clicked.connect(self.run_speedtest)
        layout.addWidget(self.run_btn)

        self.progress = QProgressBar()
        self.progress.setVisible(False)
        layout.addWidget(self.progress)

        layout.addWidget(QLabel("Speedtest Results:"))
        self.output_area = QTextEdit()
        self.output_area.setReadOnly(True)
        layout.addWidget(self.output_area)

        self.setLayout(layout)

    def run_speedtest(self):
        if hasattr(self, 'is_running') and self.is_running:
            return

        self.is_running = True
        self.progress.setVisible(True)
        self.progress.setRange(0, 0)
        self.run_btn.setEnabled(False)
        self.output_area.append("⏳ Running speedtest...")

        self.speedtest_thread = ToolThread(run_speedtest)
        self.speedtest_thread.result_ready.connect(self.on_speedtest_finished)
        self.speedtest_thread.start()

    def on_speedtest_finished(self, result):
        if "error" in result.lower():
            self.output_area.append(result)
        else:
            self.output_area.append("\n" + result)
        self.is_running = False
        self.progress.setVisible(False)
        self.run_btn.setEnabled(True)

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Network Tools")
        self.setGeometry(100, 100, 900, 700)

        # Create tabs
        tabs = QTabWidget()
        tabs.addTab(NetworkToolTab(ping_host), "Ping")
        tabs.addTab(NetworkToolTab(traceroute_host), "Traceroute")
        tabs.addTab(PortScannerTab(), "Port Scanner")
        tabs.addTab(SpeedtestTab(), "Speedtest")
        tabs.addTab(NetworkToolTab(whois_lookup, "Domain:", requires_target=True), "WHOIS")

        self.setCentralWidget(tabs)

        # Status bar
        self.statusBar().showMessage("Ready")

        # Menu
        menubar = self.menuBar()
        file_menu = menubar.addMenu('File')
        save_action = file_menu.addAction('Save Output')
        save_action.triggered.connect(self.save_output)

        settings_menu = menubar.addMenu('Settings')
        settings_action = settings_menu.addAction('Preferences')
        settings_action.triggered.connect(self.open_settings)

    def save_output(self):
        current_tab = self.centralWidget().currentWidget()
        if hasattr(current_tab, 'output_area'):
            output_text = current_tab.output_area.toPlainText()
            if output_text:
                options = QFileDialog.Options()
                file_name, _ = QFileDialog.getSaveFileName(self, "Save Output", "", "Text Files (*.txt)", options=options)
                if file_name:
                    with open(file_name, 'w', encoding='utf-8') as f:
                        f.write(output_text)
                    self.statusBar().showMessage(f"Output saved to {file_name}", 3000)
            else:
                QMessageBox.information(self, "Info", "No output to save.")

    def open_settings(self):
        dialog = SettingsDialog(self)
        if dialog.exec_() == QDialog.Accepted:
            # Refresh advanced mode visibility on all tabs
            for i in range(self.centralWidget().count()):
                tab = self.centralWidget().widget(i)
                if hasattr(tab, 'advanced_widget'):
                    tab.advanced_widget.setVisible(AppSettings().get_advanced_mode())
            self.statusBar().showMessage("Settings saved.", 2000)

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec_())