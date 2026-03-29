import subprocess
from .base import SecurityModule
from core.models import ScanResult, ApplyResult, ModuleStatus
from core.system import pkg_installed, service_active, install_pkg
from core.backup import ensure_backup
from core.priv import sudo_exists, sudo_file_nonempty, sudo_write, sudo_chown, sudo_chmod, sudo_read

RULES_FILE = "/etc/usbguard/rules.conf"


class USBGuardModule(SecurityModule):
    display_name = "USBGuard"
    description = "Blocks unknown USB devices, whitelists connected ones"
    icon_name = "drive-removable-media-symbolic"

    def scan(self) -> ScanResult:
        if not pkg_installed("usbguard"):
            return ScanResult(ModuleStatus.NOT_APPLIED, "Package not installed")

        if not sudo_file_nonempty(RULES_FILE):
            return ScanResult(ModuleStatus.PARTIAL, "Installed but no policy generated")

        if not service_active("usbguard"):
            return ScanResult(ModuleStatus.PARTIAL, "Policy exists but service inactive")

        return ScanResult(ModuleStatus.APPLIED, "Active, current devices whitelisted")

    def apply(self) -> ApplyResult:
        installed = install_pkg("usbguard")
        ensure_backup(RULES_FILE)

        result = subprocess.run(
            ["sudo", "usbguard", "generate-policy"],
            capture_output=True, text=True, check=True,
        )
        sudo_write(RULES_FILE, result.stdout)
        sudo_chown(RULES_FILE, 0, 0)
        sudo_chmod(RULES_FILE, 0o600)

        subprocess.run(
            ["sudo", "systemctl", "enable", "--now", "usbguard"],
            check=True, capture_output=True,
        )
        detail = "Policy generated from current devices, service enabled"
        if installed:
            detail = f"Installed usbguard, {detail.lower()}"
        return ApplyResult(True, detail)

    def detail_info(self) -> str | None:
        if not sudo_exists(RULES_FILE):
            return "No rules file found."
        content = sudo_read(RULES_FILE).strip()
        return content or "Rules file is empty."

    def verify(self) -> ScanResult:
        return self.scan()
