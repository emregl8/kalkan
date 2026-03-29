import os
import subprocess
from .base import SecurityModule
from core.models import ScanResult, ApplyResult, ModuleStatus
from core.system import pkg_installed, install_pkg
from core.backup import ensure_backup
from core.priv import sudo_exists, sudo_read, sudo_write, sudo_chown, sudo_chmod, sudo_makedirs

GA_DIR = "/etc/google-authenticator"
PAM_FILE = "/etc/pam.d/common-auth"
PAM_LINE = "auth required pam_google_authenticator.so user=root secret=/etc/google-authenticator/${USER}"
PACKAGES = ["libpam-google-authenticator", "qrencode"]


def _target_user() -> str:
    return os.environ.get("SUDO_USER") or os.environ.get("USER") or "root"


class GoogleAuthenticatorModule(SecurityModule):
    display_name = "Google Authenticator"
    description = "TOTP-based two-factor authentication via PAM"
    icon_name = "dialog-password-symbolic"

    def scan(self) -> ScanResult:
        if not pkg_installed("libpam-google-authenticator"):
            return ScanResult(ModuleStatus.NOT_APPLIED, "Package not installed")

        user = _target_user()
        secret_file = os.path.join(GA_DIR, user)

        if not sudo_exists(secret_file):
            return ScanResult(ModuleStatus.PARTIAL, f"Installed but no secret for {user}")

        if "pam_google_authenticator.so" not in sudo_read(PAM_FILE):
            return ScanResult(ModuleStatus.PARTIAL, "Secret exists but PAM not configured")

        return ScanResult(ModuleStatus.APPLIED, f"2FA active for {user}")

    def apply(self) -> ApplyResult:
        installed = install_pkg(*PACKAGES)
        user = _target_user()
        secret_file = os.path.join(GA_DIR, user)

        sudo_makedirs(GA_DIR, 0o700)
        sudo_chown(GA_DIR, 0, 0)

        r = subprocess.run([
            "sudo", "google-authenticator",
            "--time-based", "--disallow-reuse", "--force", "--no-confirm", "--quiet",
            "--window-size=3", "--rate-limit=3", "--rate-time=30",
            "--emergency-codes=5",
            f"--secret={secret_file}",
        ], capture_output=True, stdin=subprocess.DEVNULL)
        if r.returncode != 0:
            raise RuntimeError(r.stderr.decode().strip() or "google-authenticator failed")

        sudo_chown(secret_file, 0, 0)
        sudo_chmod(secret_file, 0o400)

        ensure_backup(PAM_FILE)
        pam_content = sudo_read(PAM_FILE)
        if "pam_google_authenticator.so" not in pam_content:
            sudo_write(PAM_FILE, pam_content + f"\n{PAM_LINE}\n")

        secret_key = sudo_read(secret_file).split('\n')[0].strip()
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
