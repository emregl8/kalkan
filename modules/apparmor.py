import json
import os
import subprocess
from .base import SecurityModule
from core.models import ScanResult, ApplyResult, ModuleStatus
from core.system import pkg_installed, service_active, install_pkg
from core.backup import ensure_backup
from core.priv import sudo_copy, sudo_chown, sudo_chmod
from core.config import APPARMOR_PROFILES_DIR

APPARMOR_D = "/etc/apparmor.d"
PACKAGES = ["apparmor", "apparmor-utils", "apparmor-profiles", "apparmor-profiles-extra"]


def _aa_profile_modes() -> dict[str, str]:
    r = subprocess.run(["sudo", "aa-status", "--json"], capture_output=True, text=True)
    if r.returncode != 0:
        return {}
    return json.loads(r.stdout).get("profiles", {})


class AppArmorModule(SecurityModule):
    display_name = "AppArmor"
    description = "Confines applications via MAC, re-enforces existing profiles"
    icon_name = "security-high-symbolic"

    def __init__(self):
        self._system_enforced: set[str] = set()
        self._enforced_custom: set[str] = set()
        self._selected: set[str] = set()

    def sub_items_label(self) -> str:
        return "Custom Profiles"

    def custom_profiles(self) -> list[str]:
        if not os.path.isdir(APPARMOR_PROFILES_DIR):
            return []
        return sorted(os.listdir(APPARMOR_PROFILES_DIR))

    def profile_enforced(self, name: str) -> bool:
        return name in self._enforced_custom

    def set_profile_selected(self, name: str, selected: bool) -> None:
        if selected:
            self._selected.add(name)
        else:
            self._selected.discard(name)

    def scan(self) -> ScanResult:
        if not pkg_installed("apparmor"):
            return ScanResult(ModuleStatus.NOT_APPLIED, "Package not installed")
        if not service_active("apparmor"):
            return ScanResult(ModuleStatus.PARTIAL, "Installed but service inactive")

        modes = _aa_profile_modes()
        enforced_all = {k for k, v in modes.items() if v == "enforce"}
        custom = self.custom_profiles()

        self._enforced_custom = {p for p in custom if any(p in e for e in enforced_all)}
        self._system_enforced = {e for e in enforced_all if not any(p in e for p in custom)}
        self._selected = set(self._enforced_custom)

        if custom and not self._enforced_custom:
            return ScanResult(ModuleStatus.PARTIAL, "Active but custom profiles not enforced")
        return ScanResult(ModuleStatus.APPLIED, f"Active, {len(enforced_all)} profiles enforced")

    def apply(self) -> ApplyResult:
        installed = install_pkg(*PACKAGES)
        subprocess.run(["sudo", "systemctl", "enable", "--now", "apparmor"], check=True, capture_output=True)

        for profile in self._system_enforced:
            subprocess.run(["sudo", "aa-enforce", profile], capture_output=True)

        for profile in self._selected:
            src = os.path.join(APPARMOR_PROFILES_DIR, profile)
            if not os.path.exists(src):
                raise FileNotFoundError(f"Custom profile not found: {src}")
            dest = os.path.join(APPARMOR_D, profile)
            ensure_backup(dest)
            sudo_copy(src, dest)
            sudo_chown(dest, 0, 0)
            sudo_chmod(dest, 0o644)
            subprocess.run(["sudo", "aa-enforce", dest], check=True, capture_output=True)

        custom_detail = ", ".join(self._selected) if self._selected else "none"
        detail = f"System: {len(self._system_enforced)} profiles re-enforced, custom: {custom_detail}"
        if installed:
            detail = f"Installed {', '.join(installed)}. " + detail
        return ApplyResult(True, detail)

    def detail_info(self) -> str | None:
        modes = _aa_profile_modes()
        if not modes:
            return "No profiles found."

        enforced = sorted(k for k, v in modes.items() if v == "enforce")
        complain = sorted(k for k, v in modes.items() if v == "complain")

        lines = []
        if enforced:
            lines.append(f"ENFORCED ({len(enforced)})")
            lines.extend(f"  {p}" for p in enforced)
        if complain:
            if lines:
                lines.append("")
            lines.append(f"COMPLAIN ({len(complain)})")
            lines.extend(f"  {p}" for p in complain)

        return "\n".join(lines)

    def verify(self) -> ScanResult:
        return self.scan()
