import os
import subprocess
from .base import SecurityModule
from core.models import ScanResult, ApplyResult, ModuleStatus
from core.system import pkg_installed, service_active, install_pkg
from core.backup import ensure_backup
from core.priv import sudo_write, sudo_chown, sudo_chmod

UPGRADES_CONF = "/etc/apt/apt.conf.d/50unattended-upgrades"
AUTO_UPGRADES_CONF = "/etc/apt/apt.conf.d/20auto-upgrades"

_UPGRADES_CONTENT = """\
Unattended-Upgrade::Allowed-Origins {
    "${distro_id}:${distro_codename}-security";
};
Unattended-Upgrade::AutoFixInterruptedDpkg "true";
Unattended-Upgrade::MinimalSteps "true";
Unattended-Upgrade::Remove-Unused-Dependencies "true";
Unattended-Upgrade::Automatic-Reboot "false";
"""

_AUTO_UPGRADES_CONTENT = """\
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::AutocleanInterval "7";
"""


def _write_conf(path: str, content: str):
    sudo_write(path, content)
    sudo_chown(path, 0, 0)
    sudo_chmod(path, 0o644)


class UnattendedUpgradesModule(SecurityModule):
    display_name = "Unattended Upgrades"
    description = "Automatically installs security patches in the background"
    icon_name = "software-update-available-symbolic"

    def scan(self) -> ScanResult:
        if not pkg_installed("unattended-upgrades"):
            return ScanResult(ModuleStatus.NOT_APPLIED, "Package not installed")

        conf_ok = (
            os.path.exists(UPGRADES_CONF)
            and os.path.exists(AUTO_UPGRADES_CONF)
            and 'distro_codename}-security' in open(UPGRADES_CONF).read()
        )
        if not conf_ok:
            return ScanResult(ModuleStatus.PARTIAL, "Installed but not configured")

        if not service_active("unattended-upgrades"):
            return ScanResult(ModuleStatus.PARTIAL, "Configured but service inactive")

        return ScanResult(ModuleStatus.APPLIED, "Active, security updates only")

    def apply(self) -> ApplyResult:
        installed = install_pkg("unattended-upgrades", "apt-listchanges")
        ensure_backup(UPGRADES_CONF)
        ensure_backup(AUTO_UPGRADES_CONF)
        _write_conf(UPGRADES_CONF, _UPGRADES_CONTENT)
        _write_conf(AUTO_UPGRADES_CONF, _AUTO_UPGRADES_CONTENT)
        subprocess.run(
            ["sudo", "systemctl", "enable", "--now", "unattended-upgrades"],
            check=True, capture_output=True,
        )
        detail = "Configured and service enabled"
        if installed:
            detail = f"Installed {', '.join(installed)}, configured and enabled"
        return ApplyResult(True, detail)

    def verify(self) -> ScanResult:
        return self.scan()
