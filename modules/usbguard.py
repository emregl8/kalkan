import os
import subprocess
from .base import SecurityModule
from core.models import ScanResult, ApplyResult, ModuleStatus
from core.system import pkg_installed, service_active, install_pkg
from core.backup import ensure_backup

RULES_FILE = "/etc/usbguard/rules.conf"


class USBGuardModule(SecurityModule):
    display_name = "USBGuard"
    description = "Blocks unknown USB devices, whitelists connected ones"
    icon_name = "drive-removable-media-symbolic"

    def scan(self) -> ScanResult:
        if not pkg_installed("usbguard"):
            return ScanResult(ModuleStatus.NOT_APPLIED, "Package not installed")

        if not os.path.exists(RULES_FILE) or os.path.getsize(RULES_FILE) == 0:
            return ScanResult(ModuleStatus.PARTIAL, "Installed but no policy generated")

        if not service_active("usbguard"):
            return ScanResult(ModuleStatus.PARTIAL, "Policy exists but service inactive")

        return ScanResult(ModuleStatus.APPLIED, "Active, current devices whitelisted")

    def apply(self) -> ApplyResult:
        installed = install_pkg("usbguard")
        ensure_backup(RULES_FILE)

        result = subprocess.run(
            ["usbguard", "generate-policy"],
            capture_output=True, text=True, check=True,
        )
        with open(RULES_FILE, "w") as f:
            f.write(result.stdout)
        os.chown(RULES_FILE, 0, 0)
        os.chmod(RULES_FILE, 0o600)

        subprocess.run(
            ["systemctl", "enable", "--now", "usbguard"],
            check=True, capture_output=True,
        )
        detail = "Policy generated from current devices, service enabled"
        if installed:
            detail = f"Installed usbguard, {detail.lower()}"
        return ApplyResult(True, detail)

    def detail_info(self) -> str | None:
        if not os.path.exists(RULES_FILE):
            return "No rules file found."
        with open(RULES_FILE) as f:
            content = f.read().strip()
        return content or "Rules file is empty."

    def verify(self) -> ScanResult:
        return self.scan()
