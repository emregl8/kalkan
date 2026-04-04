import os
import subprocess

from .base import SecurityModule
from core.models import ScanResult, ApplyResult, ModuleStatus
from core.priv import sudo_write, sudo_chmod, sudo_read, sudo_exists, sudo_run
from core.backup import ensure_backup
from core.logger import log

GRUB_PASSWORD_FILE = "/etc/grub.d/01_kalkan_password"
GRUB_LINUX_SCRIPT  = "/etc/grub.d/10_linux"
_HASH_HELPER       = os.path.join(os.path.dirname(__file__), "grub_password_helper")

_CLASS_ORIGINAL = 'CLASS="--class gnu-linux --class gnu --class os"'
_CLASS_PATCHED   = 'CLASS="--class gnu-linux --class gnu --class os --unrestricted"'


def _run_helper() -> str | None:
    r = subprocess.run([_HASH_HELPER], capture_output=True)
    if r.returncode == 2:
        return None
    if r.returncode != 0:
        raise RuntimeError(r.stderr.decode(errors="replace").strip())
    return r.stdout.decode().strip()


def _build_password_script(pw_hash: str) -> str:
    return (
        "#!/bin/sh\n"
        "# Managed by Kalkan — do not edit manually\n"
        "cat << 'EOF'\n"
        'set superusers="kalkan"\n'
        f"password_pbkdf2 kalkan {pw_hash}\n"
        "EOF\n"
    )


def _password_file_ok() -> bool:
    if not sudo_exists(GRUB_PASSWORD_FILE):
        return False
    try:
        content = sudo_read(GRUB_PASSWORD_FILE)
        return "set superusers=" in content and "password_pbkdf2" in content
    except Exception:
        return False


def _10_linux_patched() -> bool:
    try:
        return _CLASS_PATCHED in sudo_read(GRUB_LINUX_SCRIPT)
    except Exception:
        return False


def _10_linux_has_original() -> bool:
    try:
        return _CLASS_ORIGINAL in sudo_read(GRUB_LINUX_SCRIPT)
    except Exception:
        return False


def _grub_cfg_has_superusers() -> bool:
    try:
        return "set superusers=" in sudo_read("/boot/grub/grub.cfg")
    except Exception:
        return False


def _grub_cfg_permissions_ok() -> bool:
    r = sudo_run(["stat", "-c", "%a", "/boot/grub/grub.cfg"],
                 capture_output=True, text=True)
    return r.returncode == 0 and r.stdout.strip() == "600"


class GRUBPasswordModule(SecurityModule):
    display_name = "GRUB Boot Password"
    description  = (
        "Protects the GRUB boot menu with a password; "
        "the default boot entry remains open"
    )
    icon_name = "system-lock-screen-symbolic"

    def scan(self) -> ScanResult:
        pw_ok   = _password_file_ok()
        patched = _10_linux_patched()
        cfg_ok  = _grub_cfg_has_superusers()
        perm_ok = _grub_cfg_permissions_ok()

        if pw_ok and patched and cfg_ok and perm_ok:
            return ScanResult(
                ModuleStatus.APPLIED,
                "GRUB password active; default boot entry unrestricted",
            )

        if not pw_ok and not patched and not cfg_ok:
            return ScanResult(ModuleStatus.NOT_APPLIED, "GRUB boot password not configured")

        reasons = []
        if not pw_ok:
            reasons.append("password script missing or incomplete")
        if not patched:
            reasons.append("10_linux not patched (--unrestricted)")
        if not cfg_ok:
            reasons.append("grub.cfg out of sync")
        if not perm_ok:
            reasons.append("grub.cfg world-readable (hash exposed)")
        return ScanResult(ModuleStatus.PARTIAL, "; ".join(reasons))

    def apply(self) -> ApplyResult:
        log("[GRUBPassword] apply started")

        if not sudo_exists(GRUB_LINUX_SCRIPT):
            return ApplyResult(False, f"{GRUB_LINUX_SCRIPT} not found — is grub-pc/grub-efi installed?")

        if not _10_linux_has_original() and not _10_linux_patched():
            return ApplyResult(
                False,
                f"{GRUB_LINUX_SCRIPT} does not contain the expected CLASS line. "
                "Cannot safely patch — unsupported GRUB version.",
            )

        if not os.path.isfile(_HASH_HELPER):
            return ApplyResult(False, f"Helper binary not found: {_HASH_HELPER} — run 'make build'")

        log("[GRUBPassword] launching password dialog")
        try:
            pw_hash = _run_helper()
        except RuntimeError as e:
            return ApplyResult(False, f"Helper failed: {e}")
        if pw_hash is None:
            return ApplyResult(False, "Cancelled by user")

        log("[GRUBPassword] writing password script")
        ensure_backup(GRUB_PASSWORD_FILE)
        sudo_write(GRUB_PASSWORD_FILE, _build_password_script(pw_hash))
        sudo_chmod(GRUB_PASSWORD_FILE, 0o700)

        if not _10_linux_patched():
            log("[GRUBPassword] patching 10_linux for --unrestricted on default entry")
            ensure_backup(GRUB_LINUX_SCRIPT)
            content     = sudo_read(GRUB_LINUX_SCRIPT)
            new_content = content.replace(_CLASS_ORIGINAL, _CLASS_PATCHED)
            sudo_write(GRUB_LINUX_SCRIPT, new_content)
            sudo_chmod(GRUB_LINUX_SCRIPT, 0o755)

        log("[GRUBPassword] running update-grub")
        r = subprocess.run(
            ["sudo", "update-grub"],
            capture_output=True, text=True,
        )
        if r.returncode != 0:
            return ApplyResult(False, f"update-grub failed: {r.stderr.strip()}")

        sudo_chmod("/boot/grub/grub.cfg", 0o600)

        log("[GRUBPassword] done")
        return ApplyResult(
            True,
            "GRUB password set; default boot entry unrestricted; grub.cfg updated",
        )

    def detail_info(self) -> str | None:
        lines = []

        if sudo_exists(GRUB_PASSWORD_FILE):
            lines.append(f"Password script : {GRUB_PASSWORD_FILE} (present)")
        else:
            lines.append(f"Password script : {GRUB_PASSWORD_FILE} (missing)")

        if _10_linux_patched():
            lines.append("10_linux        : patched — default entry has --unrestricted")
        elif _10_linux_has_original():
            lines.append("10_linux        : not patched")
        else:
            lines.append("10_linux        : CLASS line not found (custom or unsupported grub)")

        if _grub_cfg_has_superusers():
            lines.append("grub.cfg        : superusers configured")
        else:
            lines.append("grub.cfg        : no superusers found")

        if _grub_cfg_permissions_ok():
            lines.append("grub.cfg perms  : 600 (hash protected)")
        else:
            lines.append("grub.cfg perms  : world-readable — hash exposed")

        return "\n".join(lines)

    def verify(self) -> ScanResult:
        return self.scan()
