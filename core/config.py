import os

REPO_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
APPARMOR_PROFILES_DIR = os.path.join(REPO_DIR, "apparmor-profiles")
FIREFOX_POLICY_SRC = os.path.join(REPO_DIR, "firefox-policy", "policies.json")
