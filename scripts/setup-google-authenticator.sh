#!/bin/bash
set -euo pipefail

TARGET_USER="$USER"
GA_SECRET_DIR="/etc/google-authenticator"
GA_SECRET_FILE="${GA_SECRET_DIR}/${TARGET_USER}"
GA_SCRATCH_FILE="${GA_SECRET_FILE}.scratch"
PAM_COMMON_AUTH="/etc/pam.d/common-auth"
SSHD_DROPIN="/etc/ssh/sshd_config.d/99-2fa.conf"
QR_PNG="$(mktemp /tmp/2fa-qr-XXXXXX.png)"

info()  { echo "[INFO]  $*"; }
error() { echo "[ERROR] $*" >&2; exit 1; }

[[ "$EUID" -eq 0 ]] && error "Do not run as root."

for pkg in libpam-google-authenticator qrencode; do
    if ! dpkg-query -W -f='${Status}' "$pkg" 2>/dev/null | grep -q "install ok installed"; then
        info "Installing ${pkg}..."
        sudo apt-get update -qq
        sudo apt-get install -y "$pkg"
    fi
done

if [[ -f "$GA_SECRET_FILE" ]]; then
    read -r -p "[WARN]  Existing config found. Overwrite? (y/N): " answer
    [[ "${answer,,}" == "y" ]] || { info "Aborted."; exit 0; }
fi

sudo mkdir -p "$GA_SECRET_DIR"
sudo chmod 700 "$GA_SECRET_DIR"

info "Generating TOTP secret for ${TARGET_USER}..."
google-authenticator \
    --time-based \
    --disallow-reuse \
    --force \
    --window-size=3 \
    --emergency-codes=5 \
    --rate-limit=3 \
    --rate-time=30 \
    --secret="$GA_SECRET_FILE"

SECRET_KEY="$(head -1 "$GA_SECRET_FILE")"

sudo grep -E '^[0-9]{8}$' "$GA_SECRET_FILE" | sudo tee "$GA_SCRATCH_FILE" > /dev/null
sudo chown root:root "$GA_SCRATCH_FILE"
sudo chmod 400 "$GA_SCRATCH_FILE"

sudo chown root:root "$GA_SECRET_FILE"
sudo chmod 400 "$GA_SECRET_FILE"

qrencode -o "$QR_PNG" -s 6 "otpauth://totp/${TARGET_USER}?secret=${SECRET_KEY}&issuer=SSH"
chmod 600 "$QR_PNG"
xdg-open "$QR_PNG" 2>/dev/null
info "QR code opened: ${QR_PNG} — delete after scanning."

if ! sudo grep -qF "pam_google_authenticator.so" "$PAM_COMMON_AUTH"; then
    sudo tee -a "$PAM_COMMON_AUTH" > /dev/null <<'EOF'
auth required pam_google_authenticator.so user=root secret=/etc/google-authenticator/${USER}
EOF
    info "PAM common-auth updated."
fi

sudo mkdir -p /etc/ssh/sshd_config.d
sudo tee "$SSHD_DROPIN" > /dev/null <<'EOF'
KbdInteractiveAuthentication yes
UsePAM yes
AuthenticationMethods publickey,keyboard-interactive keyboard-interactive
EOF

if ! sudo sshd -t 2>/dev/null; then
    sudo rm -f "$SSHD_DROPIN"
    error "Invalid SSHD config, reverted."
fi

sudo systemctl restart ssh

info "Backup codes: sudo cat ${GA_SCRATCH_FILE}"
info "2FA setup complete. Test in a new terminal before closing this session."
