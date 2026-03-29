import gi
gi.require_version("Gtk", "4.0")
from gi.repository import Gtk

from .window import MainWindow


class KalkanApp(Gtk.Application):
    def __init__(self):
        super().__init__(application_id="org.debian.kalkan")

    def do_activate(self):
        Gtk.Settings.get_default().set_property("gtk-application-prefer-dark-theme", True)
        win = MainWindow(application=self)
        win.present()
