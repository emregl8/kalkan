#!/bin/bash
set -euo pipefail

info()  { echo "[INFO]  $*"; }
error() { echo "[ERROR] $*" >&2; exit 1; }

[[ "$EUID" -eq 0 ]] && error "Do not run as root."

if ! dpkg-query -W -f='${Status}' ufw 2>/dev/null | grep -q "install ok installed"; then
    info "Installing ufw..."
    sudo apt-get update -qq
    sudo apt-get install -y ufw
fi

sudo ufw --force reset

sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw default deny forward

sudo ufw limit ssh comment "SSH with rate limiting"

sudo ufw --force enable

info "UFW status:"
sudo ufw status verbose
