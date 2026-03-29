import os
import subprocess
from .base import SecurityModule
from core.models import ScanResult, ApplyResult, ModuleStatus
from core.system import pkg_installed, service_active, install_pkg
from core.backup import ensure_backup
from core.priv import sudo_write, sudo_chown, sudo_chmod

CONF_FILE = "/etc/rsyslog.d/99-kalkan-hardening.conf"

_CONF = """\
$FileOwner root
$FileGroup adm
$FileCreateMode 0640
$DirCreateMode 0755
$Umask 0022
"""

_MARKER = "$FileCreateMode 0640"


class RsyslogModule(SecurityModule):
    display_name = "rsyslog"
    description = "Restricts log file permissions, disables remote log reception"
    icon_name = "text-x-generic-symbolic"

    def scan(self) -> ScanResult:
        if not pkg_installed("rsyslog"):
            return ScanResult(ModuleStatus.NOT_APPLIED, "Package not installed")

        if not service_active("rsyslog"):
            return ScanResult(ModuleStatus.PARTIAL, "Installed but service inactive")

        if not os.path.exists(CONF_FILE):
            return ScanResult(ModuleStatus.PARTIAL, "Running but hardening config not deployed")

        try:
            with open(CONF_FILE) as f:
                if _MARKER not in f.read():
                    return ScanResult(ModuleStatus.PARTIAL, "Config exists but does not match")
        except OSError:
            return ScanResult(ModuleStatus.PARTIAL, "Could not read hardening config")

        return ScanResult(ModuleStatus.APPLIED, "Active with hardened configuration")

    def apply(self) -> ApplyResult:
        installed = install_pkg("rsyslog")

        ensure_backup(CONF_FILE)
        sudo_write(CONF_FILE, _CONF)
        sudo_chown(CONF_FILE, 0, 0)
        sudo_chmod(CONF_FILE, 0o644)

        subprocess.run(
            ["sudo", "rsyslogd", "-N1"],
            check=True, capture_output=True
        )

        subprocess.run(
            ["sudo", "systemctl", "enable", "--now", "rsyslog"],
            check=True, capture_output=True
        )
        subprocess.run(
            ["sudo", "systemctl", "restart", "rsyslog"],
            check=True, capture_output=True
        )

        detail = "Hardening config deployed, service enabled"
        if installed:
            detail = f"Installed rsyslog, {detail.lower()}"
        return ApplyResult(True, detail)

    def detail_info(self) -> str | None:
        lines = []

        r = subprocess.run(
            ["sudo", "systemctl", "status", "rsyslog", "--no-pager", "-l"],
            capture_output=True, text=True
        )
        if r.returncode == 0:
            lines.append(r.stdout.strip())

        if os.path.exists(CONF_FILE):
            lines.append(f"\n--- {CONF_FILE} ---")
            try:
                with open(CONF_FILE) as f:
                    lines.append(f.read().strip())
            except OSError:
                lines.append("(permission denied)")

        return "\n".join(lines) if lines else None

    def verify(self) -> ScanResult:
        return self.scan()
