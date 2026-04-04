import copy
import json
import os
from .base import SecurityModule
from core.models import ScanResult, ApplyResult, ModuleStatus
from core.backup import ensure_backup
from core.priv import sudo_makedirs, sudo_write, sudo_chown, sudo_chmod

POLICY_DIR = "/etc/firefox-esr/policies"
POLICY_FILE = os.path.join(POLICY_DIR, "policies.json")

_DIST_DIR = "/usr/lib/firefox-esr/distribution"
_DIST_FILE = os.path.join(_DIST_DIR, "policies.json")

_FIREFOX_BINARY = "/usr/lib/firefox-esr/firefox-esr"

_OPT_HISTORY = "Remember History"

_EXTENSION_WHITELIST = {
    "Privacy Badger":    "jid1-MnnxcxisBPnSXQ@jetpack",
    "NoScript":          "{73a6fe31-595d-460b-a920-fcc0f8843232}",
    "KeePassXC-Browser": "keepassxc-browser@keepassxc.org",
    "Bitwarden":         "{446900e4-71c2-419f-a6a7-df9c091e268b}",
    "Dark Reader":       "addon@darkreader.org",
    "Decentraleyes":     "jid1-BoFifL9Vbdl2zQ@jetpack",
    "Cookie AutoDelete": "CookieAutoDelete@kennydo.com",
}

_BASE_POLICY = {
    "DisableTelemetry": True,
    "DisableFirefoxStudies": True,
    "DisableFirefoxAccounts": False,
    "DisablePocket": True,
    "DisableFeedbackCommands": True,
    "DisableSetDesktopBackground": True,
    "OverrideFirstRunPage": "",
    "OverridePostUpdatePage": "",
    "DontCheckDefaultBrowser": True,
    "CaptivePortal": False,
    "PasswordManagerEnabled": False,
    "OfferToSaveLogins": False,
    "AutofillCreditCardEnabled": False,
    "AutofillAddressEnabled": False,
    "HttpsOnlyMode": "force_enabled",
    "NetworkPrediction": False,
    "TranslateEnabled": False,
    "DisableBuiltinPDFViewer": True,
    "BlockAboutConfig": True,
    "EnableTrackingProtection": {
        "Value": True, "Locked": True,
        "Cryptomining": True, "Fingerprinting": True, "EmailTracking": True,
    },
    "FirefoxSuggest": {
        "WebSuggestions": False, "SponsoredSuggestions": False,
        "ImproveSuggest": False, "Locked": True,
    },
    "DNSOverHTTPS": {"Enabled": False, "Locked": True},
    "EncryptedMediaExtensions": {"Enabled": False, "Locked": True},
    "FirefoxHome": {
        "Search": True, "TopSites": False, "SponsoredTopSites": False,
        "Highlights": False, "Pocket": False, "SponsoredPocket": False,
        "Snippets": False, "Locked": True,
    },
    "SearchEngines": {"PreventInstalls": True},
    "UserMessaging": {
        "WhatsNew": False, "ExtensionRecommendations": False,
        "FeatureRecommendations": False, "UrlbarInterventions": False,
        "SkipOnboarding": True, "MoreFromMozilla": False,
        "FirefoxLabs": False, "Locked": True,
    },
    "Permissions": {
        "Camera":        {"BlockNewRequests": True, "Locked": True},
        "Microphone":    {"BlockNewRequests": True, "Locked": True},
        "Location":      {"BlockNewRequests": True, "Locked": True},
        "Notifications": {"BlockNewRequests": True, "Locked": True},
        "Autoplay":      {"Default": "block-audio-video", "Locked": True},
    },
    "Cookies": {"Behavior": "reject-tracker-and-partition-foreign", "Locked": True},
    "PopupBlocking": {"Default": True, "Locked": True},
}


def _build_policy(remember_history: bool, allowed_extensions: set[str]) -> dict:
    policy = copy.deepcopy(_BASE_POLICY)

    policy["SanitizeOnShutdown"] = {
        "Cache": not remember_history,
        "Cookies": not remember_history,
        "History": not remember_history,
        "Sessions": False,
        "FormData": not remember_history,
        "DownloadHistory": not remember_history,
        "OfflineApps": not remember_history,
        "Locked": True,
    }

    ext_settings: dict = {
        "*": {
            "installation_mode": "blocked",
            "blocked_install_message": "Extension installation is restricted by the administrator.",
        },
        "uBlock0@raymondhill.net": {
            "installation_mode": "force_installed",
            "install_url": "https://addons.mozilla.org/firefox/downloads/latest/ublock-origin/latest.xpi",
        },
    }
    for name, ext_id in _EXTENSION_WHITELIST.items():
        if name in allowed_extensions:
            ext_settings[ext_id] = {"installation_mode": "allowed"}

    policy["ExtensionSettings"] = ext_settings
    return {"policies": policy}


def _read_deployed() -> dict:
    try:
        with open(_DIST_FILE) as f:
            return json.load(f).get("policies", {})
    except (OSError, json.JSONDecodeError):
        return {}


class FirefoxPolicyModule(SecurityModule):
    display_name = "Firefox Policy"
    description = "Enforces HTTPS-only mode, disables telemetry and data collection"
    icon_name = "applications-internet-symbolic"

    def __init__(self):
        self._selected: set[str] = set()

    def sub_items_label(self) -> str:
        return "Options & Extension Whitelist"

    def sub_items_flow(self) -> bool:
        return True

    def custom_profiles(self) -> list[str]:
        return [_OPT_HISTORY] + list(_EXTENSION_WHITELIST.keys())

    def profile_enforced(self, name: str) -> bool:
        return name in self._selected

    def set_profile_selected(self, name: str, selected: bool) -> None:
        if selected:
            self._selected.add(name)
        else:
            self._selected.discard(name)

    def scan(self) -> ScanResult:
        if not os.path.exists(_FIREFOX_BINARY):
            return ScanResult(ModuleStatus.NOT_APPLIED, "Firefox ESR not installed")
        if not os.path.exists(_DIST_FILE):
            return ScanResult(ModuleStatus.NOT_APPLIED, "No enterprise policy deployed")

        deployed = _read_deployed()
        if not deployed:
            return ScanResult(ModuleStatus.PARTIAL, "Policy file unreadable")

        if "HttpsOnlyMode" not in deployed or "DisableTelemetry" not in deployed:
            return ScanResult(ModuleStatus.PARTIAL, "Policy exists but differs from expected")

        sanitize = deployed.get("SanitizeOnShutdown", {})
        history_cleared = sanitize.get("History", True)

        self._selected = set()
        if not history_cleared:
            self._selected.add(_OPT_HISTORY)

        ext_settings = deployed.get("ExtensionSettings", {})
        for name, ext_id in _EXTENSION_WHITELIST.items():
            mode = ext_settings.get(ext_id, {}).get("installation_mode")
            if mode == "allowed":
                self._selected.add(name)

        return ScanResult(ModuleStatus.APPLIED, "Policy deployed and up to date")

    def apply(self) -> ApplyResult:
        remember_history = _OPT_HISTORY in self._selected
        allowed_exts = {n for n in _EXTENSION_WHITELIST if n in self._selected}

        policy_json = json.dumps(_build_policy(remember_history, allowed_exts), indent=2)

        sudo_makedirs(POLICY_DIR)
        ensure_backup(POLICY_FILE)
        sudo_write(POLICY_FILE, policy_json)
        sudo_chown(POLICY_FILE, 0, 0)
        sudo_chmod(POLICY_FILE, 0o644)

        ensure_backup(_DIST_FILE)
        sudo_write(_DIST_FILE, policy_json)
        sudo_chown(_DIST_FILE, 0, 0)
        sudo_chmod(_DIST_FILE, 0o644)

        parts = []
        if remember_history:
            parts.append("history retained")
        if allowed_exts:
            parts.append(f"whitelisted: {', '.join(sorted(allowed_exts))}")
        detail = "; ".join(parts) if parts else "default settings"
        return ApplyResult(True, f"Policy deployed ({detail})")

    def verify(self) -> ScanResult:
        return self.scan()
