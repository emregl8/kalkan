import os
import gi
gi.require_version("Gtk", "4.0")
from gi.repository import Gtk, GLib

from .window import MainWindow
from core.config import REPO_DIR

_DESKTOP_PATH = os.path.expanduser("~/.local/share/applications/org.debian.kalkan.desktop")

_DESKTOP_ENTRY = f"""[Desktop Entry]
Name=Kalkan
Exec=python3 {REPO_DIR}/kalkan
Icon=security-high
Type=Application
StartupWMClass=kalkan
"""


def _ensure_desktop_entry() -> None:
    if not os.path.exists(_DESKTOP_PATH):
        os.makedirs(os.path.dirname(_DESKTOP_PATH), exist_ok=True)
        with open(_DESKTOP_PATH, "w") as f:
            f.write(_DESKTOP_ENTRY)


class KalkanApp(Gtk.Application):
    def __init__(self):
        super().__init__(application_id="org.debian.kalkan")
        GLib.set_application_name("Kalkan")
        GLib.set_prgname("kalkan")
        _ensure_desktop_entry()

    def do_activate(self):
        Gtk.Settings.get_default().set_property("gtk-application-prefer-dark-theme", True)
        win = MainWindow(application=self)
        win.present()
