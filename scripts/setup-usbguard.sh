#!/bin/bash
set -euo pipefail

POLICY_FILE="/etc/usbguard/rules.conf"

info()  { echo "[INFO]  $*"; }
error() { echo "[ERROR] $*" >&2; exit 1; }

[[ "$EUID" -eq 0 ]] && error "Do not run as root."

if ! dpkg-query -W -f='${Status}' usbguard 2>/dev/null | grep -q "install ok installed"; then
    info "Installing usbguard..."
    sudo apt-get update -qq
    sudo apt-get install -y usbguard
fi

info "Generating policy from currently connected devices..."
sudo usbguard generate-policy | sudo tee "$POLICY_FILE" > /dev/null

sudo systemctl enable --now usbguard

info "USBGuard active. Currently connected devices are allowed."