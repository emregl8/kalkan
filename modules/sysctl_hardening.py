import re
import subprocess
from .base import SecurityModule
from core.models import ScanResult, ApplyResult, ModuleStatus
from core.priv import sudo_write, sudo_chown, sudo_chmod, sudo_read
from core.backup import ensure_backup

_SYSCTL_CONF = "/etc/sysctl.conf"

CONF_FILE = "/etc/sysctl.d/99-kalkan-hardening.conf"

_PARAMS = {
    "kernel.randomize_va_space":                   "2",
    "kernel.kptr_restrict":                        "2",
    "kernel.dmesg_restrict":                       "1",
    "kernel.perf_event_paranoid":                  "3",
    "kernel.yama.ptrace_scope":                    "1",
    "kernel.sysrq":                                "0",
    "kernel.ctrl-alt-del":                         "0",
    "kernel.unprivileged_bpf_disabled":            "1",
    "fs.protected_hardlinks":                      "1",
    "fs.protected_symlinks":                       "1",
    "fs.suid_dumpable":                            "0",
    "net.ipv4.conf.all.rp_filter":                 "1",
    "net.ipv4.conf.default.rp_filter":             "1",
    "net.ipv4.conf.all.accept_redirects":          "0",
    "net.ipv4.conf.default.accept_redirects":      "0",
    "net.ipv4.conf.all.secure_redirects":          "0",
    "net.ipv4.conf.default.secure_redirects":      "0",
    "net.ipv4.conf.all.send_redirects":            "0",
    "net.ipv4.conf.default.send_redirects":        "0",
    "net.ipv4.conf.all.accept_source_route":       "0",
    "net.ipv4.conf.default.accept_source_route":   "0",
    "net.ipv4.conf.all.log_martians":              "1",
    "net.ipv4.conf.default.log_martians":          "1",
    "net.ipv4.icmp_echo_ignore_broadcasts":        "1",
    "net.ipv4.icmp_ignore_bogus_error_responses":  "1",
    "net.ipv4.tcp_syncookies":                     "1",
    "net.ipv4.ip_forward":                         "0",
    "net.ipv6.conf.all.accept_redirects":          "0",
    "net.ipv6.conf.default.accept_redirects":      "0",
    "net.ipv6.conf.all.accept_source_route":       "0",
}

_CONF = "\n".join(f"{k} = {v}" for k, v in _PARAMS.items()) + "\n"


def _neutralise_sysctl_conf() -> None:
    try:
        original = sudo_read(_SYSCTL_CONF)
    except Exception:
        return

    keys = set(_PARAMS.keys())
    new_lines = []
    changed = False
    for line in original.splitlines():
        stripped = line.strip()
        if stripped.startswith("#") or not stripped:
            new_lines.append(line)
            continue
        m = re.match(r"^\s*([^=\s]+)\s*=", stripped)
        if m and m.group(1) in keys:
            new_lines.append(f"# kalkan: {line}")
            changed = True
        else:
            new_lines.append(line)

    if changed:
        ensure_backup(_SYSCTL_CONF)
        sudo_write(_SYSCTL_CONF, "\n".join(new_lines) + "\n")


def _read_current(key: str) -> str | None:
    r = subprocess.run(["/usr/sbin/sysctl", "-n", key], capture_output=True, text=True)
    return r.stdout.strip() if r.returncode == 0 else None


class SysctlHardeningModule(SecurityModule):
    display_name = "Kernel Sysctl"
    description = "Hardens kernel parameters: ASLR, ptrace, network stack, filesystem protections"
    icon_name = "system-run-symbolic"

    def scan(self) -> ScanResult:
        mismatched = [
            k for k, v in _PARAMS.items()
            if _read_current(k) not in (v, None)
        ]

        import os
        if not os.path.exists(CONF_FILE):
            return ScanResult(ModuleStatus.NOT_APPLIED, "Config not deployed")

        if mismatched:
            return ScanResult(ModuleStatus.PARTIAL,
                              f"{len(mismatched)} parameter(s) not applied")

        return ScanResult(ModuleStatus.APPLIED, f"All {len(_PARAMS)} parameters active")

    def apply(self) -> ApplyResult:
        ensure_backup(CONF_FILE)
        sudo_write(CONF_FILE, _CONF)
        sudo_chown(CONF_FILE, 0, 0)
        sudo_chmod(CONF_FILE, 0o644)

        _neutralise_sysctl_conf()

        r = subprocess.run(
            ["sudo", "/usr/sbin/sysctl", "--system"],
            capture_output=True, text=True
        )
        if r.returncode != 0:
            raise RuntimeError(r.stderr.strip())

        for key, val in _PARAMS.items():
            subprocess.run(
                ["sudo", "/usr/sbin/sysctl", "-w", f"{key}={val}"],
                capture_output=True,
            )

        return ApplyResult(True, f"{len(_PARAMS)} kernel parameters applied")

    def detail_info(self) -> str | None:
        lines = []
        for key, expected in _PARAMS.items():
            current = _read_current(key)
            if current is None:
                status = "N/A"
            elif current == expected:
                status = f"{current} ✓"
            else:
                status = f"{current} (expected {expected})"
            lines.append(f"{key} = {status}")
        return "\n".join(lines)

    def verify(self) -> ScanResult:
        return self.scan()
