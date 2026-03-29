import os
import subprocess
import threading
import gi
gi.require_version("Gtk", "4.0")
from gi.repository import Gtk, GLib

from .base import SecurityModule
from core.models import ScanResult, ApplyResult, ModuleStatus
from core.system import pkg_installed, install_pkg
from core.priv import sudo_read

CRYPTTAB = "/etc/crypttab"


def _get_luks_devices() -> list[str]:
    devices = []
    try:
        content = sudo_read(CRYPTTAB)
        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split()
            if len(parts) < 2:
                continue
            dev = parts[1]
            if dev.startswith("UUID="):
                r = subprocess.run(["blkid", "-U", dev[5:]], capture_output=True, text=True)
                if r.returncode == 0 and r.stdout.strip():
                    devices.append(r.stdout.strip())
            elif os.path.exists(dev):
                devices.append(dev)
    except Exception:
        pass
    return devices


def _tpm2_available() -> bool:
    return os.path.exists("/dev/tpmrm0") or os.path.exists("/dev/tpm0")


def _tpm2_enrolled(dev: str) -> bool:
    r = subprocess.run(
        ["sudo", "systemd-cryptenroll", dev],
        capture_output=True, text=True
    )
    return "tpm2" in r.stdout


def _ask_passphrase() -> str | None:
    event = threading.Event()
    result = [None]

    def build_and_show():
        dialog = Gtk.Dialog()
        dialog.set_title("LUKS Passphrase Required")
        dialog.set_modal(True)

        box = dialog.get_content_area()
        box.set_spacing(8)
        box.set_margin_top(12)
        box.set_margin_bottom(12)
        box.set_margin_start(12)
        box.set_margin_end(12)

        label = Gtk.Label(label="Enter your disk encryption passphrase to enroll TPM2:")
        label.set_wrap(True)
        box.append(label)

        entry = Gtk.PasswordEntry()
        entry.set_show_peek_icon(True)
        box.append(entry)

        dialog.add_button("Cancel", Gtk.ResponseType.CANCEL)
        dialog.add_button("Enroll", Gtk.ResponseType.OK)
        dialog.set_default_response(Gtk.ResponseType.OK)

        def on_response(d, response):
            if response == Gtk.ResponseType.OK:
                result[0] = entry.get_text()
            d.destroy()
            event.set()

        dialog.connect("response", on_response)
        dialog.present()

    GLib.idle_add(build_and_show)
    event.wait()
    return result[0]


class TPMUnlockModule(SecurityModule):
    display_name = "TPM2 Disk Unlock"
    description = "Automatically unlocks LUKS-encrypted disk at boot using TPM2"
    icon_name = "drive-harddisk-symbolic"

    def scan(self) -> ScanResult:
        if not _tpm2_available():
            return ScanResult(ModuleStatus.NOT_APPLIED, "No TPM2 device found")

        devices = _get_luks_devices()
        if not devices:
            return ScanResult(ModuleStatus.NOT_APPLIED, "No LUKS devices in /etc/crypttab")

        if not pkg_installed("tpm2-tools"):
            return ScanResult(ModuleStatus.PARTIAL, "TPM2 found but tpm2-tools not installed")

        enrolled = [d for d in devices if _tpm2_enrolled(d)]
        if not enrolled:
            return ScanResult(ModuleStatus.PARTIAL, f"TPM2 found but not enrolled for {', '.join(devices)}")

        return ScanResult(ModuleStatus.APPLIED, f"TPM2 enrolled for {', '.join(enrolled)}")

    def apply(self) -> ApplyResult:
        devices = _get_luks_devices()
        if not devices:
            raise RuntimeError("No LUKS devices found in /etc/crypttab")

        install_pkg("tpm2-tools")

        passphrase = _ask_passphrase()
        if passphrase is None:
            raise RuntimeError("Cancelled by user")

        enrolled = []
        for dev in devices:
            if _tpm2_enrolled(dev):
                enrolled.append(dev)
                continue
            r = subprocess.run(
                ["sudo", "systemd-cryptenroll",
                 "--tpm2-device=auto",
                 "--tpm2-pcrs=0+7",
                 dev],
                input=passphrase + "\n",
                capture_output=True,
                text=True,
            )
            if r.returncode != 0:
                raise RuntimeError(f"Enrollment failed for {dev}: {r.stderr.strip()}")
            enrolled.append(dev)

        subprocess.run(
            ["sudo", "update-initramfs", "-u", "-k", "all"],
            check=True, capture_output=True
        )

        return ApplyResult(True, f"TPM2 enrolled for {', '.join(enrolled)}, initramfs updated")

    def detail_info(self) -> str | None:
        devices = _get_luks_devices()
        if not devices:
            return "No LUKS devices found in /etc/crypttab."

        lines = []
        for dev in devices:
            r = subprocess.run(
                ["sudo", "systemd-cryptenroll", dev],
                capture_output=True, text=True
            )
            lines.append(f"Device: {dev}")
            lines.append(r.stdout.strip() if r.returncode == 0 else "  (could not read keyslots)")
            lines.append("")
        return "\n".join(lines).strip()

    def verify(self) -> ScanResult:
        return self.scan()
