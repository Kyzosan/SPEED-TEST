"""
settings.py
Modul untuk menyimpan dan mengelola pengaturan aplikasi.
"""

from PyQt5.QtCore import QSettings

class AppSettings:
    def __init__(self):
        self.settings = QSettings("NetworkTools", "App")

    def get(self, key, default=None):
        """Mengambil nilai pengaturan dengan kunci 'key'."""
        return self.settings.value(key, default)

    def set(self, key, value):
        """Menyimpan nilai pengaturan."""
        self.settings.setValue(key, value)

    # Default settings
    def get_public_ip_timeout(self):
        return self.get("public_ip_timeout", 5)

    def set_public_ip_timeout(self, value):
        self.set("public_ip_timeout", value)

    def get_port_scan_threads(self):
        return self.get("port_scan_threads", 100)

    def set_port_scan_threads(self, value):
        self.set("port_scan_threads", value)

    def get_default_ip_choice(self):
        # 'public' atau 'local'
        return self.get("default_ip_choice", "public")

    def set_default_ip_choice(self, value):
        self.set("default_ip_choice", value)

    def get_advanced_mode(self):
        return self.get("advanced_mode", False, type=bool)

    def set_advanced_mode(self, value):
        self.set("advanced_mode", value)