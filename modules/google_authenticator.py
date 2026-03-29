import os
import subprocess
from .base import SecurityModule
from core.models import ScanResult, ApplyResult, ModuleStatus
from core.system import pkg_installed, install_pkg
from core.backup import ensure_backup

GA_DIR = "/etc/google-authenticator"
PAM_FILE = "/etc/pam.d/common-auth"
PAM_LINE = "auth required pam_google_authenticator.so user=root secret=/etc/google-authenticator/${USER}"
SSHD_DROPIN = "/etc/ssh/sshd_config.d/99-2fa.conf"
PACKAGES = ["libpam-google-authenticator", "qrencode"]


def _target_user() -> str:
    return os.environ.get("SUDO_USER") or "root"


class GoogleAuthenticatorModule(SecurityModule):
    display_name = "Google Authenticator"
    description = "TOTP-based two-factor authentication for PAM and SSH"
    icon_name = "dialog-password-symbolic"

    def scan(self) -> ScanResult:
        if not pkg_installed("libpam-google-authenticator"):
            return ScanResult(ModuleStatus.NOT_APPLIED, "Package not installed")

        user = _target_user()
        secret_file = os.path.join(GA_DIR, user)

        if not os.path.exists(secret_file):
            return ScanResult(ModuleStatus.PARTIAL, f"Installed but no secret for {user}")

        with open(PAM_FILE) as f:
            if "pam_google_authenticator.so" not in f.read():
                return ScanResult(ModuleStatus.PARTIAL, "Secret exists but PAM not configured")

        return ScanResult(ModuleStatus.APPLIED, f"2FA active for {user}")

    def apply(self) -> ApplyResult:
        installed = install_pkg(*PACKAGES)
        user = _target_user()
        secret_file = os.path.join(GA_DIR, user)

        os.makedirs(GA_DIR, mode=0o700, exist_ok=True)
        os.chown(GA_DIR, 0, 0)

        subprocess.run([
            "google-authenticator",
            "--time-based", "--disallow-reuse", "--force",
            "--window-size=3", "--rate-limit=3", "--rate-time=30",
            "--emergency-codes=5",
            f"--secret={secret_file}",
        ], check=True, capture_output=True)

        os.chown(secret_file, 0, 0)
        os.chmod(secret_file, 0o400)

        ensure_backup(PAM_FILE)
        with open(PAM_FILE) as f:
            content = f.read()
        if "pam_google_authenticator.so" not in content:
            with open(PAM_FILE, "a") as f:
                f.write(f"\n{PAM_LINE}\n")

        os.makedirs("/etc/ssh/sshd_config.d", exist_ok=True)
        ensure_backup(SSHD_DROPIN)
        with open(SSHD_DROPIN, "w") as f:
            f.write(
                "KbdInteractiveAuthentication yes\n"
                "UsePAM yes\n"
                "AuthenticationMethods publickey,keyboard-interactive keyboard-interactive\n"
            )
        os.chown(SSHD_DROPIN, 0, 0)
        os.chmod(SSHD_DROPIN, 0o644)

        r = subprocess.run(["sshd", "-t"], capture_output=True)
        if r.returncode != 0:
            os.remove(SSHD_DROPIN)
            raise RuntimeError("Invalid SSHD config — dropin reverted")

        subprocess.run(["systemctl", "restart", "ssh"], check=True, capture_output=True)

        secret_key = open(secret_file).readline().strip()
        qr_file = f"/tmp/kalkan-2fa-{user}.png"
        subprocess.run([
            "qrencode", "-o", qr_file, "-s", "6",
            f"otpauth://totp/{user}?secret={secret_key}&issuer=Kalkan",
        ], check=True, capture_output=True)
        os.chmod(qr_file, 0o600)
        subprocess.Popen(["xdg-open", qr_file])

        detail = f"2FA configured for {user}, QR code opened"
        if installed:
            detail = f"Installed {', '.join(installed)}, " + detail.lower()
        return ApplyResult(True, detail)

    def verify(self) -> ScanResult:
        return self.scan()
