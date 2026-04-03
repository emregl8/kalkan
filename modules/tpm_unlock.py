import ctypes
import ctypes.util
import os
import subprocess

import threading
import gi
gi.require_version("Gtk", "4.0")
from gi.repository import Gtk, GLib

from .base import SecurityModule
from core.models import ScanResult, ApplyResult, ModuleStatus
from core.system import pkg_installed, install_pkg
from core.logger import log


CRYPTTAB = "/etc/crypttab"
CLEVIS_PKGS = ["clevis", "clevis-luks", "clevis-tpm2", "clevis-initramfs"]
_BIND_HELPER = os.path.join(os.path.dirname(__file__), "clevis_bind_helper")
_TPM2_CONFIG = '{"pcr_bank":"sha256","pcr_ids":"0,4,7"}'

_libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)


def _zero_passphrase(buf: bytearray) -> None:
    if buf:
        addr = ctypes.addressof(ctypes.c_char.from_buffer(buf))
        _libc.explicit_bzero(ctypes.cast(addr, ctypes.c_void_p), len(buf))


def _read_crypttab() -> str:
    try:
        r = subprocess.run(["sudo", "cat", CRYPTTAB], capture_output=True, text=True, timeout=5)
        return r.stdout if r.returncode == 0 else ""
    except Exception:
        return ""


def _get_luks_devices() -> list[str]:
    devices = []
    content = _read_crypttab()
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        if len(parts) < 2:
            continue
        dev = parts[1]
        if dev.startswith("UUID="):
            uuid_path = f"/dev/disk/by-uuid/{dev[5:]}"
            if os.path.exists(uuid_path):
                devices.append(os.path.realpath(uuid_path))
        elif os.path.exists(dev):
            devices.append(dev)
    return devices


def _tpm2_available() -> bool:
    return os.path.exists("/dev/tpmrm0") or os.path.exists("/dev/tpm0")


def _clevis_tpm2_bound(dev: str) -> bool:
    try:
        r = subprocess.run(
            ["sudo", "clevis", "luks", "list", "-d", dev],
            capture_output=True, text=True, timeout=8
        )
        return "tpm2" in r.stdout
    except Exception:
        return False


def _systemd_tpm2_enrolled(dev: str) -> bool:
    try:
        r = subprocess.run(
            ["sudo", "systemd-cryptenroll", dev],
            capture_output=True, text=True, timeout=8
        )
        return "tpm2" in r.stdout
    except Exception:
        return False


def _ask_passphrase() -> bytearray | None:
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
                text = entry.get_text()
                result[0] = bytearray(text.encode())
                entry.set_text("")
            d.destroy()
            event.set()

        dialog.connect("response", on_response)
        dialog.present()

    GLib.idle_add(build_and_show)
    event.wait(timeout=300)
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

        all_pkgs = all(pkg_installed(p) for p in CLEVIS_PKGS)
        if not all_pkgs:
            return ScanResult(ModuleStatus.PARTIAL, "TPM2 found but clevis packages not installed")

        bound = [d for d in devices if _clevis_tpm2_bound(d)]
        if not bound:
            return ScanResult(ModuleStatus.PARTIAL, f"TPM2 found but not bound for {', '.join(devices)}")

        return ScanResult(ModuleStatus.APPLIED, f"TPM2 bound for {', '.join(bound)}")

    def apply(self) -> ApplyResult:
        log("[TPM2] apply started")
        if not _tpm2_available():
            return ApplyResult(False, "No TPM2 device found on this system")

        devices = _get_luks_devices()
        log(f"[TPM2] LUKS devices: {devices}")
        if not devices:
            return ApplyResult(False, "No LUKS devices found in /etc/crypttab")

        log("[TPM2] installing clevis packages")
        for pkg in CLEVIS_PKGS:
            install_pkg(pkg)

        for dev in devices:
            if _systemd_tpm2_enrolled(dev):
                log(f"[TPM2] wiping old systemd-cryptenroll tpm2 slot on {dev}")
                subprocess.run(
                    ["sudo", "systemd-cryptenroll", "--wipe-slot=tpm2", dev],
                    capture_output=True, text=True
                )

        log("[TPM2] asking passphrase")
        passphrase = _ask_passphrase()
        if passphrase is None:
            log("[TPM2] passphrase dialog cancelled or timed out")
            return ApplyResult(False, "Cancelled by user")
        if len(passphrase) == 0:
            return ApplyResult(False, "Passphrase cannot be empty")

        if not os.path.isfile(_BIND_HELPER):
            return ApplyResult(False, f"Helper binary not found: {_BIND_HELPER} — run 'make build'")

        bound = []
        errors = []
        try:
            for dev in devices:
                if _clevis_tpm2_bound(dev):
                    log(f"[TPM2] {dev} already bound, skipping")
                    bound.append(dev)
                    continue
                log(f"[TPM2] binding {dev} with clevis tpm2")
                r = subprocess.run(
                    [_BIND_HELPER, dev, _TPM2_CONFIG],
                    input=bytes(passphrase) + b"\n",
                    capture_output=True,
                )
                if r.returncode != 0:
                    msg = r.stderr.decode(errors="replace").strip()
                    log(f"[TPM2] bind failed for {dev}: {msg}")
                    errors.append(f"{dev}: {msg}")
                    continue
                log(f"[TPM2] {dev} bound successfully")
                bound.append(dev)
        finally:
            _zero_passphrase(passphrase)

        if errors and not bound:
            return ApplyResult(False, f"Bind failed: {'; '.join(errors)}")
        if errors:
            return ApplyResult(False, f"Partial bind — succeeded: {', '.join(bound)}, failed: {'; '.join(errors)}")

        self._cleanup_grub_tpm2()

        log("[TPM2] running update-initramfs (this may take several minutes)")
        subprocess.run(
            ["sudo", "update-initramfs", "-u", "-k", "all"],
            check=True, capture_output=True
        )
        log("[TPM2] update-initramfs done")

        return ApplyResult(True, f"TPM2 bound for {', '.join(bound)}, initramfs updated")

    def _cleanup_grub_tpm2(self):
        tpm_opt = "rd.luks.options=tpm2-device=auto"
        try:
            r = subprocess.run(
                ["sudo", "cat", "/etc/default/grub"],
                capture_output=True, text=True, timeout=5
            )
            if r.returncode != 0 or tpm_opt not in r.stdout:
                return
            new_content = r.stdout.replace(f" {tpm_opt}", "").replace(tpm_opt, "")
            subprocess.run(
                ["sudo", "tee", "/etc/default/grub"],
                input=new_content, capture_output=True, text=True
            )
            subprocess.run(["sudo", "update-grub"], capture_output=True, text=True)
            log("[TPM2] cleaned up old GRUB tpm2 kernel option")
        except Exception:
            pass

    def detail_info(self) -> str | None:
        devices = _get_luks_devices()
        if not devices:
            return "No LUKS devices found in /etc/crypttab."

        lines = []
        for dev in devices:
            lines.append(f"Device: {dev}")
            r = subprocess.run(
                ["sudo", "clevis", "luks", "list", "-d", dev],
                capture_output=True, text=True
            )
            if r.returncode == 0 and r.stdout.strip():
                lines.append(f"  Clevis: {r.stdout.strip()}")
            else:
                lines.append("  Clevis: not bound")
            lines.append("")
        return "\n".join(lines).strip()

    def verify(self) -> ScanResult:
        return self.scan()
