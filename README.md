# Kalkan

A GTK4 desktop tool for hardening Debian 13 Trixie. On launch, it scans the current security state of the system and lets you selectively apply hardening measures. Each run is idempotent — original config files are backed up once and overwritten on subsequent runs.

![Platform](https://img.shields.io/badge/platform-Debian%2013%20Trixie-red)
![Python](https://img.shields.io/badge/python-3.12%2B-blue)
![GTK](https://img.shields.io/badge/GTK-4.0-green)

---

## Modules

| Module | What it does |
|---|---|
| **UFW Firewall** | Blocks all inbound connections. Optionally opens common ports (HTTP, HTTPS, RDP, SSH, etc.) |
| **AppArmor** | Enables MAC enforcement. Re-enforces profiles currently active on this machine. Supports custom profiles. |
| **Unattended Upgrades** | Automatically installs security patches in the background |
| **USBGuard** | Blocks unknown USB devices. Whitelists devices connected at time of apply. |
| **Firefox Policy** | Enforces HTTPS-only mode, disables telemetry and data collection |
| **Google Authenticator** | Configures TOTP-based 2FA for PAM and SSH. Opens QR code on setup. |

## How it works

Kalkan scans the system on startup and reports the state of each module — **Active**, **Partial**, or **Not Applied**. Check the modules you want to apply and hit **Apply Selected**.

- Original config files are backed up with a `.backup` suffix before any changes
- Backups are root-only readable (`600`)
- Every run overwrites the live config with Kalkan's hardened settings — safe to run multiple times
- All actions are logged to `kalkan.log` in the project directory

## Requirements

- Debian 13 Trixie
- Python 3.12+
- GTK 4.0

```
make deps   # install dependencies
make        # run
```

> **Warning:** This project is under active development and is not yet ready for production use. Apply at your own risk.