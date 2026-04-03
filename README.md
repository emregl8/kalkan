# Kalkan

A GNOME application for hardening Debian 13 Trixie. On launch, it scans the current security state of the system and lets you selectively apply hardening measures. Each run is idempotent: original config files are backed up once and overwritten on subsequent runs. Tested on systems with `gnome-core` installed.

![Platform](https://img.shields.io/badge/platform-Debian%2013%20Trixie-red)
![Python](https://img.shields.io/badge/python-3.12%2B-blue)
![GNOME](https://img.shields.io/badge/GNOME-gnome--core-green)

## Modules

| Module | What it does |
|---|---|
| **UFW Firewall** | Blocks all inbound connections. Optionally opens common ports (HTTP, HTTPS, RDP, SSH, etc.) |
| **AppArmor** | Enables MAC enforcement. Re-enforces profiles currently active on this machine. Supports custom profiles. |
| **Firefox Policy** | Enforces HTTPS-only mode, disables telemetry and data collection. Optional: remember history, per-extension whitelist (Privacy Badger, Bitwarden, Dark Reader, etc.) |
| **Unattended Upgrades** | Automatically installs security patches in the background |
| **USBGuard** | Blocks unknown USB devices. Whitelists devices connected at time of apply. |
| **Google Authenticator** | Configures TOTP-based 2FA via PAM. Displays QR code on setup. |
| **TPM2 Disk Unlock** | Enrolls LUKS-encrypted disks for automatic unlock via TPM2 (PCRs 0+7) |
| **Rsyslog Hardening** | Restricts log file ownership and permissions via rsyslog drop-in config |
| **Kernel Sysctl** | Hardens kernel parameters: ASLR, ptrace scope, network stack, filesystem protections |
| **SSH Hardening** | Deploys a drop-in sshd config: disables password auth (only if authorized_keys exists), root login, X11/TCP/agent forwarding. Validates config before restarting sshd. |
| **auditd** | Deploys kernel-level audit rules: monitors auth files, sudo, SSH config, kernel modules, cron, network, login events, privilege escalation, and unauthorized access attempts |

## How it works

Kalkan scans the system on startup and reports the state of each module: **Active**, **Partial**, or **Not Applied**. Check the modules you want to apply and hit **Apply Selected**.

- The GUI runs as a normal user; individual privileged operations use `sudo`
- Original config files are backed up to `~/.local/share/kalkan/backups/` before any changes, mirroring the original path structure
- Backups are never placed next to system configs, preventing daemons from accidentally loading them
- Every run overwrites the live config with Kalkan's hardened settings, safe to run multiple times
- All actions are logged to `~/.local/share/kalkan/kalkan.log`

## Requirements

- Debian 13 Trixie
- Python 3.12+
- GNOME / GTK 4.0
- `python3-gi`, `gir1.2-gtk-4.0`

```
make deps   # install dependencies
make        # run
```

> **Warning:** This project is under active development and is not yet ready for production use. Apply at your own risk.
