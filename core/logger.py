import os
from datetime import datetime

LOG_FILE = os.path.join(os.path.expanduser("~"), ".local", "share", "kalkan", "kalkan.log")
os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)


def init_log() -> None:
    open(LOG_FILE, "w").close()


def log(message: str) -> None:
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(LOG_FILE, "a") as f:
        f.write(f"[{timestamp}] {message}\n")


def log_separator(label: str) -> None:
    with open(LOG_FILE, "a") as f:
        f.write(f"\n--- {label} {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} ---\n")
