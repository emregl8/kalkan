import subprocess
from .base import SecurityModule
from core.models import ScanResult, ApplyResult, ModuleStatus
from core.system import pkg_installed, install_pkg

_COMMON_PORTS: dict[str, str] = {
    "SSH (22/tcp)": "22/tcp",
    "FTP (21/tcp)": "21/tcp",
    "HTTP (80/tcp)": "80/tcp",
    "HTTPS (443/tcp)": "443/tcp",
    "DNS (53/udp)": "53/udp",
    "SMTP (25/tcp)": "25/tcp",
    "SMTPS (587/tcp)": "587/tcp",
    "IMAP (143/tcp)": "143/tcp",
    "IMAPS (993/tcp)": "993/tcp",
    "SMB (445/tcp)": "445/tcp",
    "RDP (3389/tcp)": "3389/tcp",
    "VNC (5900/tcp)": "5900/tcp",
}


class UFWModule(SecurityModule):
    display_name = "UFW Firewall"
    description = "Blocks all inbound connections"
    icon_name = "network-wired-symbolic"

    def __init__(self):
        self._allowed_ports: set[str] = set()
        self._selected_ports: set[str] = set()

    def sub_items_label(self) -> str:
        return "Allow Inbound"

    def sub_items_flow(self) -> bool:
        return True

    def custom_profiles(self) -> list[str]:
        return list(_COMMON_PORTS.keys())

    def profile_enforced(self, name: str) -> bool:
        return name in self._allowed_ports

    def set_profile_selected(self, name: str, selected: bool) -> None:
        if selected:
            self._selected_ports.add(name)
        else:
            self._selected_ports.discard(name)

    def scan(self) -> ScanResult:
        if not pkg_installed("ufw"):
            return ScanResult(ModuleStatus.NOT_APPLIED, "Package not installed")

        r = subprocess.run(["ufw", "status"], capture_output=True, text=True)
        if "Status: active" not in r.stdout:
            return ScanResult(ModuleStatus.PARTIAL, "Installed but inactive")

        self._allowed_ports = {
            name for name, port in _COMMON_PORTS.items()
            if port in r.stdout
        }
        self._selected_ports = set(self._allowed_ports)

        return ScanResult(ModuleStatus.APPLIED, "Active, click to view rules")

    def detail_info(self) -> str | None:
        r = subprocess.run(["ufw", "status", "numbered"], capture_output=True, text=True)
        return r.stdout.strip() if r.returncode == 0 else None

    def apply(self) -> ApplyResult:
        installed = install_pkg("ufw")
        subprocess.run(["ufw", "--force", "reset"], check=True, capture_output=True)
        subprocess.run(["ufw", "default", "deny", "incoming"], check=True, capture_output=True)
        subprocess.run(["ufw", "default", "allow", "outgoing"], check=True, capture_output=True)
        subprocess.run(["ufw", "default", "deny", "forward"], check=True, capture_output=True)

        for name in self._selected_ports:
            port = _COMMON_PORTS[name]
            subprocess.run(["ufw", "allow", port], check=True, capture_output=True)

        subprocess.run(["ufw", "--force", "enable"], check=True, capture_output=True)

        opened = ", ".join(self._selected_ports) if self._selected_ports else "none"
        detail = f"Configured and enabled, allowed: {opened}"
        if installed:
            detail = f"Installed {', '.join(installed)}, " + detail.lower()
        return ApplyResult(True, detail)

    def verify(self) -> ScanResult:
        return self.scan()
