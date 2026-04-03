import os
import subprocess
from .base import SecurityModule
from core.models import ScanResult, ApplyResult, ModuleStatus
from core.system import pkg_installed, service_active, install_pkg
from core.priv import sudo_write, sudo_chown, sudo_chmod, sudo_read, sudo_makedirs, sudo_exists
from core.backup import ensure_backup

RULES_FILE = "/etc/audit/rules.d/99-kalkan.rules"
AUDITD_CONF = "/etc/audit/auditd.conf"

_MARKER = "# kalkan-auditd"

_RULES = """\
# kalkan-auditd
-D
-b 8192
-f 1
-w /etc/passwd -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/group -p wa -k identity
-w /etc/gshadow -p wa -k identity
-w /etc/security/opasswd -p wa -k identity
-w /etc/sudoers -p wa -k scope
-w /etc/sudoers.d/ -p wa -k scope
-w /etc/ssh/sshd_config -p wa -k sshd
-w /etc/ssh/sshd_config.d/ -p wa -k sshd
-w /sbin/insmod -p x -k modules
-w /sbin/rmmod -p x -k modules
-w /sbin/modprobe -p x -k modules
-a always,exit -F arch=b64 -S init_module,finit_module,delete_module -k modules
-w /var/log/faillog -p wa -k logins
-w /var/log/lastlog -p wa -k logins
-w /var/run/utmp -p wa -k session
-w /var/log/wtmp -p wa -k session
-w /var/log/btmp -p wa -k session
-w /etc/crontab -p wa -k cron
-w /etc/cron.d/ -p wa -k cron
-w /etc/cron.daily/ -p wa -k cron
-w /etc/cron.hourly/ -p wa -k cron
-w /etc/cron.monthly/ -p wa -k cron
-w /etc/cron.weekly/ -p wa -k cron
-w /var/spool/cron/ -p wa -k cron
-a always,exit -F arch=b64 -S sethostname,setdomainname -k system-locale
-w /etc/hosts -p wa -k system-locale
-w /etc/network/ -p wa -k system-locale
-w /etc/resolv.conf -p wa -k system-locale
-a always,exit -F arch=b64 -S adjtimex,settimeofday,clock_settime -k time-change
-w /etc/localtime -p wa -k time-change
-a always,exit -F arch=b64 -S chmod,fchmod,fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b64 -S chown,fchown,lchown,fchownat -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b64 -S open,openat,truncate,ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access
-a always,exit -F arch=b64 -S open,openat,truncate,ftruncate -F exit=-EPERM  -F auid>=1000 -F auid!=4294967295 -k access
-a always,exit -F path=/usr/bin/sudo -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/bin/su   -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/bin/newgrp -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/bin/chsh  -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
-a always,exit -F path=/usr/bin/passwd -F perm=x -F auid>=1000 -F auid!=4294967295 -k privileged
"""

_AUDITD_CONF_OVERRIDES = {
    "max_log_file":        "50",
    "num_logs":            "10",
    "max_log_file_action": "rotate",
    "space_left_action":   "syslog",
    "admin_space_left_action": "suspend",
}


def _apply_auditd_conf() -> None:
    try:
        content = sudo_read(AUDITD_CONF)
    except Exception:
        return

    lines = content.splitlines()
    new_lines = []
    applied = set()
    for line in lines:
        stripped = line.strip()
        if stripped.startswith("#") or "=" not in stripped:
            new_lines.append(line)
            continue
        key = stripped.split("=", 1)[0].strip().lower()
        if key in _AUDITD_CONF_OVERRIDES:
            new_lines.append(f"{key} = {_AUDITD_CONF_OVERRIDES[key]}")
            applied.add(key)
        else:
            new_lines.append(line)

    for key, val in _AUDITD_CONF_OVERRIDES.items():
        if key not in applied:
            new_lines.append(f"{key} = {val}")

    ensure_backup(AUDITD_CONF)
    sudo_write(AUDITD_CONF, "\n".join(new_lines) + "\n")
    sudo_chown(AUDITD_CONF, 0, 0)
    sudo_chmod(AUDITD_CONF, 0o640)


class AuditdModule(SecurityModule):
    display_name = "auditd"
    description = "Audits system calls and file access: auth, sudo, modules, cron, network"
    icon_name = "security-medium-symbolic"

    def scan(self) -> ScanResult:
        if not pkg_installed("auditd"):
            return ScanResult(ModuleStatus.NOT_APPLIED, "Package not installed")

        if not sudo_exists(RULES_FILE):
            return ScanResult(ModuleStatus.NOT_APPLIED, "Audit rules not deployed")

        try:
            content = sudo_read(RULES_FILE)
            if _MARKER not in content:
                return ScanResult(ModuleStatus.PARTIAL, "Rules file exists but not managed by Kalkan")
        except Exception:
            return ScanResult(ModuleStatus.PARTIAL, "Could not read rules file")

        if not service_active("auditd"):
            return ScanResult(ModuleStatus.PARTIAL, "Rules deployed but auditd inactive")

        r = subprocess.run(
            ["sudo", "auditctl", "-s"],
            capture_output=True, text=True, timeout=5,
        )
        if r.returncode == 0 and "enabled 1" in r.stdout:
            return ScanResult(ModuleStatus.APPLIED, "Active, rules loaded")

        return ScanResult(ModuleStatus.PARTIAL, "Service running but rules not loaded")

    def apply(self) -> ApplyResult:
        install_pkg("auditd")

        sudo_makedirs("/etc/audit/rules.d", 0o750)
        ensure_backup(RULES_FILE)
        sudo_write(RULES_FILE, _RULES)
        sudo_chown(RULES_FILE, 0, 0)
        sudo_chmod(RULES_FILE, 0o640)

        _apply_auditd_conf()

        subprocess.run(
            ["sudo", "augenrules", "--load"],
            capture_output=True, check=True,
        )
        subprocess.run(
            ["sudo", "systemctl", "enable", "--now", "auditd"],
            capture_output=True, check=True,
        )

        return ApplyResult(True, "Rules deployed and auditd enabled")

    def detail_info(self) -> str | None:
        status = subprocess.run(
            ["sudo", "auditctl", "-s"],
            capture_output=True, text=True, timeout=5,
        )
        rules = subprocess.run(
            ["sudo", "auditctl", "-l"],
            capture_output=True, text=True, timeout=5,
        )
        parts = []
        if status.returncode == 0:
            parts.append("=== Status ===\n" + status.stdout.strip())
        if rules.returncode == 0:
            parts.append("=== Active Rules ===\n" + rules.stdout.strip())
        return "\n\n".join(parts) if parts else None

    def verify(self) -> ScanResult:
        return self.scan()
