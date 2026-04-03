import os
import subprocess
from .base import SecurityModule
from core.models import ScanResult, ApplyResult, ModuleStatus
from core.system import pkg_installed, service_active, install_pkg
from core.priv import sudo_write, sudo_chown, sudo_chmod, sudo_read, sudo_makedirs
from core.backup import ensure_backup

CONF_FILE = "/etc/ssh/sshd_config.d/99-kalkan.conf"

_BASE_PARAMS = {
    "PermitEmptyPasswords":    "no",
    "MaxAuthTries":            "3",
    "LoginGraceTime":          "30",
    "ClientAliveInterval":     "300",
    "ClientAliveCountMax":     "2",
    "LogLevel":                "VERBOSE",
    "StrictModes":             "yes",
    "IgnoreRhosts":            "yes",
    "HostbasedAuthentication": "no",
    "PubkeyAuthentication":    "yes",
    "PrintLastLog":            "yes",
    "UseDNS":                  "no",
}

_OPT_PARAMS: dict[str, dict[str, str]] = {
    "Disable Password Auth":    {"PasswordAuthentication": "no"},
    "Disable Root Login":       {"PermitRootLogin": "no"},
    "Disable X11 Forwarding":   {"X11Forwarding": "no"},
    "Disable TCP Forwarding":   {"AllowTcpForwarding": "no"},
    "Disable Agent Forwarding": {"AllowAgentForwarding": "no"},
}


def _parse_conf(content: str) -> dict[str, str]:
    params = {}
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(None, 1)
        if len(parts) == 2:
            params[parts[0].lower()] = parts[1].strip().lower()
    return params


def _build_conf(selected: set[str]) -> str:
    lines = ["# Managed by Kalkan — do not edit manually"]
    for key, val in _BASE_PARAMS.items():
        lines.append(f"{key} {val}")
    for opt_name, opt_params in _OPT_PARAMS.items():
        if opt_name in selected:
            for key, val in opt_params.items():
                lines.append(f"{key} {val}")
    return "\n".join(lines) + "\n"


class SSHHardeningModule(SecurityModule):
    display_name = "SSH Hardening"
    description = "Hardens OpenSSH: disables password auth, root login, forwarding"
    icon_name = "network-server-symbolic"

    def __init__(self):
        self._selected: set[str] = set(_OPT_PARAMS.keys())

    def sub_items_label(self) -> str:
        return "Options"

    def sub_items_flow(self) -> bool:
        return False

    def custom_profiles(self) -> list[str]:
        return list(_OPT_PARAMS.keys())

    def profile_enforced(self, name: str) -> bool:
        return name in self._selected

    def set_profile_selected(self, name: str, selected: bool) -> None:
        if selected:
            self._selected.add(name)
        else:
            self._selected.discard(name)

    def scan(self) -> ScanResult:
        if not pkg_installed("openssh-server"):
            return ScanResult(ModuleStatus.NOT_APPLIED, "openssh-server not installed")

        if not os.path.exists(CONF_FILE):
            self._selected = set(_OPT_PARAMS.keys())
            authorized_keys = os.path.expanduser("~/.ssh/authorized_keys")
            if not os.path.exists(authorized_keys) or os.path.getsize(authorized_keys) == 0:
                self._selected.discard("Disable Password Auth")
            return ScanResult(ModuleStatus.NOT_APPLIED, "Hardening config not deployed")

        try:
            params = _parse_conf(sudo_read(CONF_FILE))
        except Exception:
            return ScanResult(ModuleStatus.ERROR, "Could not read hardening config")

        missing_base = [
            k for k, v in _BASE_PARAMS.items()
            if params.get(k.lower()) != v.lower()
        ]

        self._selected = set()
        for opt_name, opt_params in _OPT_PARAMS.items():
            if all(params.get(k.lower()) == v.lower() for k, v in opt_params.items()):
                self._selected.add(opt_name)

        if missing_base:
            return ScanResult(ModuleStatus.PARTIAL,
                              f"{len(missing_base)} base parameter(s) not in config")

        if not service_active("ssh"):
            return ScanResult(ModuleStatus.PARTIAL, "Configured but SSH service inactive")

        n = len(self._selected)
        return ScanResult(ModuleStatus.APPLIED,
                          f"Active, {n}/{len(_OPT_PARAMS)} optional restriction(s) enabled")

    def apply(self) -> ApplyResult:
        if "Disable Password Auth" in self._selected:
            authorized_keys = os.path.expanduser("~/.ssh/authorized_keys")
            has_keys = (
                os.path.exists(authorized_keys)
                and os.path.getsize(authorized_keys) > 0
            )
            if not has_keys:
                raise RuntimeError(
                    "Cannot disable password auth: no SSH public keys found in "
                    "~/.ssh/authorized_keys. Add your public key first or "
                    "uncheck 'Disable Password Auth'."
                )

        install_pkg("openssh-server")

        sudo_makedirs("/etc/ssh/sshd_config.d", 0o755)
        ensure_backup(CONF_FILE)
        sudo_write(CONF_FILE, _build_conf(self._selected))
        sudo_chown(CONF_FILE, 0, 0)
        sudo_chmod(CONF_FILE, 0o600)

        r = subprocess.run(["sudo", "sshd", "-t"], capture_output=True, text=True)
        if r.returncode != 0:
            raise RuntimeError(f"SSH config validation failed: {r.stderr.strip()}")

        subprocess.run(
            ["sudo", "systemctl", "restart", "ssh"],
            check=True, capture_output=True,
        )

        active = sorted(self._selected)
        detail = "Hardening deployed and SSH restarted"
        if active:
            detail += f" ({', '.join(active)})"
        return ApplyResult(True, detail)

    def detail_info(self) -> str | None:
        r = subprocess.run(
            ["sudo", "sshd", "-T"],
            capture_output=True, text=True,
        )
        if r.returncode != 0:
            return None
        relevant_keys = {k.lower() for k in _BASE_PARAMS} | {
            k.lower()
            for opts in _OPT_PARAMS.values()
            for k in opts
        }
        lines = []
        for line in r.stdout.splitlines():
            parts = line.split(None, 1)
            if parts and parts[0].lower() in relevant_keys:
                lines.append(line)
        return "\n".join(lines) if lines else None

    def verify(self) -> ScanResult:
        return self.scan()
