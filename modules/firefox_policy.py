import json
import os
from .base import SecurityModule
from core.models import ScanResult, ApplyResult, ModuleStatus
from core.backup import ensure_backup
from core.priv import sudo_makedirs, sudo_copy, sudo_chown, sudo_chmod
from core.config import FIREFOX_POLICY_SRC

POLICY_DIR = "/etc/firefox-esr/policies"
POLICY_FILE = os.path.join(POLICY_DIR, "policies.json")

_FIREFOX_BINARY = "/usr/lib/firefox-esr/firefox-esr"


def _load_json(path: str) -> dict:
    with open(path) as f:
        return json.load(f)


class FirefoxPolicyModule(SecurityModule):
    display_name = "Firefox Policy"
    description = "Enforces HTTPS-only mode, disables telemetry and data collection"
    icon_name = "applications-internet-symbolic"

    def scan(self) -> ScanResult:
        if not os.path.exists(_FIREFOX_BINARY):
            return ScanResult(ModuleStatus.NOT_APPLIED, "Firefox ESR not installed")
        if not os.path.exists(POLICY_FILE):
            return ScanResult(ModuleStatus.NOT_APPLIED, "No enterprise policy deployed")

        try:
            deployed = _load_json(POLICY_FILE)
            expected = _load_json(FIREFOX_POLICY_SRC)
            if deployed == expected:
                return ScanResult(ModuleStatus.APPLIED, "Policy deployed and up to date")
            return ScanResult(ModuleStatus.PARTIAL, "Policy exists but differs from source")
        except (json.JSONDecodeError, OSError) as e:
            return ScanResult(ModuleStatus.ERROR, str(e))

    def apply(self) -> ApplyResult:
        sudo_makedirs(POLICY_DIR)
        ensure_backup(POLICY_FILE)
        sudo_copy(FIREFOX_POLICY_SRC, POLICY_FILE)
        sudo_chown(POLICY_FILE, 0, 0)
        sudo_chmod(POLICY_FILE, 0o644)
        return ApplyResult(True, f"Policy deployed to {POLICY_FILE}")

    def verify(self) -> ScanResult:
        return self.scan()
