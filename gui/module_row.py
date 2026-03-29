import gi
gi.require_version("Gtk", "4.0")
from gi.repository import Gtk, GLib
import threading

from modules.base import SecurityModule
from core.models import ScanResult, ModuleStatus


class ModuleRow(Gtk.ListBoxRow):
    def __init__(self, module: SecurityModule):
        super().__init__()
        self.module = module

        self.set_margin_top(2)
        self.set_margin_bottom(2)
        self.set_margin_start(6)
        self.set_margin_end(6)

        if module.detail_info.__func__ is not SecurityModule.detail_info:
            gesture = Gtk.GestureClick.new()
            gesture.connect("released", self._on_click)
            self.add_controller(gesture)
            self.set_tooltip_text("Click to view details")

        outer = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=12)
        outer.set_margin_top(12)
        outer.set_margin_bottom(12)
        outer.set_margin_start(12)
        outer.set_margin_end(12)
        self.set_child(outer)

        self._check = Gtk.CheckButton()
        self._check.set_sensitive(False)
        self._check.set_valign(Gtk.Align.CENTER)
        outer.append(self._check)

        if module.icon_name:
            icon = Gtk.Image.new_from_icon_name(module.icon_name)
            icon.set_pixel_size(24)
            icon.set_valign(Gtk.Align.CENTER)
            icon.set_opacity(0.75)
            outer.append(icon)

        text_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=3)
        text_box.set_hexpand(True)
        outer.append(text_box)

        name_label = Gtk.Label(label=module.display_name)
        name_label.set_halign(Gtk.Align.START)
        name_label.add_css_class("heading")
        text_box.append(name_label)

        self._desc_label = Gtk.Label(label=module.description)
        self._desc_label.set_halign(Gtk.Align.START)
        self._desc_label.add_css_class("dim-label")
        text_box.append(self._desc_label)

        self._profile_checks: dict[str, Gtk.CheckButton] = {}
        self._profiles_container: Gtk.Widget | None = None

        profiles = module.custom_profiles()
        if profiles:
            container = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=4)
            container.set_margin_top(6)
            container.set_visible(False)

            header_label = Gtk.Label(label=module.sub_items_label())
            header_label.set_halign(Gtk.Align.START)
            header_label.add_css_class("dim-label")
            container.append(header_label)

            if module.sub_items_flow():
                items_box = Gtk.FlowBox()
                items_box.set_selection_mode(Gtk.SelectionMode.NONE)
                items_box.set_max_children_per_line(6)
                items_box.set_row_spacing(2)
                items_box.set_column_spacing(4)
                items_box.set_homogeneous(False)
            else:
                items_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=2)

            for name in profiles:
                cb = Gtk.CheckButton(label=name)
                cb.set_sensitive(False)
                cb.connect("toggled", self._on_profile_toggled, name)
                items_box.append(cb)
                self._profile_checks[name] = cb

            container.append(items_box)
            text_box.append(container)
            self._profiles_container = container

        self._badge = Gtk.Label(label="—")
        self._badge.set_halign(Gtk.Align.END)
        self._badge.set_valign(Gtk.Align.CENTER)
        self._badge.set_xalign(0.5)
        outer.append(self._badge)

        self._check.connect("toggled", self._on_check_toggled)

    def _on_check_toggled(self, cb: Gtk.CheckButton):
        if self._profiles_container:
            self._profiles_container.set_visible(cb.get_active())

    def _on_profile_toggled(self, cb: Gtk.CheckButton, name: str):
        self.module.set_profile_selected(name, cb.get_active())

    def _on_click(self, _gesture, _n_press, _x, _y):
        def fetch():
            info = self.module.detail_info()
            GLib.idle_add(self._show_detail_dialog, info)

        threading.Thread(target=fetch, daemon=True).start()

    def _show_detail_dialog(self, info: str | None):
        window = self.get_root()
        dialog = Gtk.Dialog(title=self.module.display_name, transient_for=window, modal=True)
        dialog.set_default_size(780, 560)

        scrolled = Gtk.ScrolledWindow()
        scrolled.set_vexpand(True)
        scrolled.set_margin_top(12)
        scrolled.set_margin_bottom(12)
        scrolled.set_margin_start(12)
        scrolled.set_margin_end(12)

        text_view = Gtk.TextView()
        text_view.set_editable(False)
        text_view.set_monospace(True)
        text_view.set_cursor_visible(False)
        text_view.get_buffer().set_text(info or "No detail available.")
        scrolled.set_child(text_view)

        dialog.get_content_area().append(scrolled)
        dialog.add_button("Close", Gtk.ResponseType.CLOSE)
        dialog.connect("response", lambda d, _: d.destroy())
        dialog.present()

    @property
    def is_selected(self) -> bool:
        return self._check.get_active()

    def update_status(self, result: ScanResult):
        self._desc_label.set_label(result.detail)

        for cls in ("badge-active", "badge-partial", "badge-missing"):
            self._badge.remove_css_class(cls)
        self._badge.set_label(result.label)
        self._badge.add_css_class(result.badge_class)

        self._check.set_active(result.status != ModuleStatus.APPLIED)
        self._check.set_sensitive(True)

        for name, cb in self._profile_checks.items():
            cb.handler_block_by_func(self._on_profile_toggled)
            cb.set_active(self.module.profile_enforced(name))
            cb.handler_unblock_by_func(self._on_profile_toggled)
            cb.set_sensitive(True)
