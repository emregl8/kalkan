from .ufw import UFWModule
from .apparmor import AppArmorModule
from .firefox_policy import FirefoxPolicyModule
from .unattended_upgrades import UnattendedUpgradesModule
from .usbguard import USBGuardModule
from .google_authenticator import GoogleAuthenticatorModule

ALL_MODULES = [
    UFWModule,
    AppArmorModule,
    FirefoxPolicyModule,
    UnattendedUpgradesModule,
    USBGuardModule,
    GoogleAuthenticatorModule,
]
