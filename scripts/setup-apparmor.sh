#!/bin/bash
set -euo pipefail

REPO_DIR="$(cd "$(dirname "$0")/.." && pwd)"
APPARMOR_DIR="/etc/apparmor.d"

SYSTEM_PROFILES=(
    usr.sbin.cups-browsed
    usr.sbin.cupsd
    usr.bin.evince
    usr.bin.man
    usr.libexec.geoclue
    nvidia_modprobe
    unix-chkpwd
    lsb_release
    systemd-coredump
)

CUSTOM_PROFILES=(
    firefox
)

info()  { echo "[INFO]  $*"; }
error() { echo "[ERROR] $*" >&2; exit 1; }

[[ "$EUID" -eq 0 ]] && error "Do not run as root."

for pkg in apparmor apparmor-utils apparmor-profiles apparmor-profiles-extra; do
    if ! dpkg-query -W -f='${Status}' "$pkg" 2>/dev/null | grep -q "install ok installed"; then
        info "Installing ${pkg}..."
        sudo apt-get update -qq
        sudo apt-get install -y "$pkg"
    fi
done

sudo systemctl enable --now apparmor

info "Enforcing system profiles..."
for profile in "${SYSTEM_PROFILES[@]}"; do
    if [[ -f "${APPARMOR_DIR}/${profile}" ]]; then
        sudo aa-enforce "${APPARMOR_DIR}/${profile}"
        info "  enforced: ${profile}"
    fi
done

info "Installing and enforcing custom profiles..."
for profile in "${CUSTOM_PROFILES[@]}"; do
    src="${REPO_DIR}/apparmor-profiles/${profile}"
    [[ -f "$src" ]] || error "Custom profile not found: ${src}"
    sudo cp "$src" "${APPARMOR_DIR}/${profile}"
    sudo aa-enforce "${APPARMOR_DIR}/${profile}"
    info "  enforced: ${profile}"
done

info "AppArmor status:"
sudo aa-status --pretty-print 2>/dev/null || sudo aa-status
