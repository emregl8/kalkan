import threading
import gi
gi.require_version("Gtk", "4.0")
from gi.repository import Gtk, GLib, Gdk

from modules import ALL_MODULES
from core.models import ModuleStatus
from core.logger import log, log_separator
from .module_row import ModuleRow

_CSS = b"""
.badge-active {
    background-color: #26a269;
    color: white;
    border-radius: 100px;
    padding: 3px 12px;
    font-size: 0.78em;
    font-weight: bold;
    min-width: 96px;
}
.badge-partial {
    background-color: #cd9309;
    color: white;
    border-radius: 100px;
    padding: 3px 12px;
    font-size: 0.78em;
    font-weight: bold;
    min-width: 96px;
}
.badge-missing {
    background-color: #c01c28;
    color: white;
    border-radius: 100px;
    padding: 3px 12px;
    font-size: 0.78em;
    font-weight: bold;
    min-width: 96px;
}

"""


class MainWindow(Gtk.ApplicationWindow):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.set_title("Kalkan")
        self.set_default_size(880, 640)

        _load_css()

        self._modules = [M() for M in ALL_MODULES]
        self._rows: list[ModuleRow] = []

        main_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL)
        self.set_child(main_box)

        header = Gtk.HeaderBar()
        self.set_titlebar(header)

        self._spinner = Gtk.Spinner()
        header.pack_start(self._spinner)

        scrolled = Gtk.ScrolledWindow()
        scrolled.set_vexpand(True)
        main_box.append(scrolled)

        self._list_box = Gtk.ListBox()
        self._list_box.set_selection_mode(Gtk.SelectionMode.NONE)
        self._list_box.add_css_class("boxed-list")
        self._list_box.set_margin_top(12)
        self._list_box.set_margin_bottom(12)
        self._list_box.set_margin_start(12)
        self._list_box.set_margin_end(12)
        scrolled.set_child(self._list_box)

        for module in self._modules:
            row = ModuleRow(module)
            self._rows.append(row)
            self._list_box.append(row)

        bottom_bar = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)

        bottom_bar.set_margin_start(16)
        bottom_bar.set_margin_end(16)
        bottom_bar.set_margin_top(10)
        bottom_bar.set_margin_bottom(12)
        main_box.append(bottom_bar)

        self._status = Gtk.Label(label="Scanning system…")
        GLib.idle_add(self._on_scan, None)
        self._status.set_halign(Gtk.Align.START)
        self._status.set_hexpand(True)
        self._status.add_css_class("dim-label")
        bottom_bar.append(self._status)

        self._select_btn = Gtk.Button(label="Select All")
        self._select_btn.set_sensitive(False)
        self._select_btn.connect("clicked", self._on_toggle_select)
        bottom_bar.append(self._select_btn)

        self._apply_btn = Gtk.Button(label="Apply Selected")
        self._apply_btn.add_css_class("suggested-action")
        self._apply_btn.set_sensitive(False)
        self._apply_btn.connect("clicked", self._on_apply)
        self._apply_btn.set_halign(Gtk.Align.END)
        bottom_bar.append(self._apply_btn)

    def _set_busy(self, busy: bool):
        self._apply_btn.set_sensitive(not busy)
        self._select_btn.set_sensitive(not busy)
        if busy:
            self._spinner.start()
        else:
            self._spinner.stop()

    def _on_toggle_select(self, _btn):
        all_selected = all(r.is_selected for r in self._rows)
        for row in self._rows:
            row.set_checked(not all_selected)
        self._select_btn.set_label("Deselect All" if not all_selected else "Select All")

    def _on_scan(self, _btn):
        self._set_busy(True)
        self._status.set_label("Scanning system…")

        def worker():
            log_separator("SCAN")
            for row in self._rows:
                try:
                    result = row.module.scan()
                except Exception as e:
                    from core.models import ScanResult
                    result = ScanResult(ModuleStatus.ERROR, str(e))
                log(f"[{row.module.display_name}] {result.label} - {result.detail}")
                GLib.idle_add(row.update_status, result)
            GLib.idle_add(self._on_scan_done)

        threading.Thread(target=worker, daemon=True).start()

    def _on_scan_done(self):
        self._set_busy(False)
        self._apply_btn.set_sensitive(True)
        self._status.set_label("")

    def _on_apply(self, _btn):
        selected = [r for r in self._rows if r.is_selected]
        if not selected:
            self._status.set_label("No modules selected.")
            return

        self._set_busy(True)
        names = ", ".join(r.module.display_name for r in selected)
        self._status.set_label(f"Applying: {names}…")

        def worker():
            log_separator("APPLY")
            failed = []
            for row in selected:
                try:
                    result = row.module.apply()
                    if result.success:
                        log(f"[OK] {row.module.display_name}: {result.detail}")
                    else:
                        log(f"[SKIP] {row.module.display_name}: {result.detail}")
                except Exception as e:
                    failed.append(row.module.display_name)
                    log(f"[FAIL] {row.module.display_name}: {e}")

                try:
                    verified = row.module.verify()
                except Exception as e:
                    from core.models import ScanResult
                    verified = ScanResult(ModuleStatus.ERROR, str(e))
                GLib.idle_add(row.update_status, verified)

            for row in self._rows:
                if row not in selected:
                    try:
                        verified = row.module.verify()
                    except Exception as e:
                        from core.models import ScanResult
                        verified = ScanResult(ModuleStatus.ERROR, str(e))
                    GLib.idle_add(row.update_status, verified)

            GLib.idle_add(self._on_apply_done, failed)

        threading.Thread(target=worker, daemon=True).start()

    def _on_apply_done(self, failed: list[str]):
        self._set_busy(False)
        if failed:
            self._status.set_label(f"Completed with errors: {', '.join(failed)}")
        else:
            self._status.set_label("All selected modules applied and verified successfully.")


def _load_css():
    provider = Gtk.CssProvider()
    provider.load_from_data(_CSS)
    Gtk.StyleContext.add_provider_for_display(
        Gdk.Display.get_default(),
        provider,
        Gtk.STYLE_PROVIDER_PRIORITY_APPLICATION,
    )
