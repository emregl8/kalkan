import os
from datetime import datetime
from core.config import REPO_DIR

LOG_FILE = os.path.join(REPO_DIR, "kalkan.log")


def init_log() -> None:
    open(LOG_FILE, "w").close()


def log(message: str) -> None:
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(LOG_FILE, "a") as f:
        f.write(f"[{timestamp}] {message}\n")


def log_separator(label: str) -> None:
    with open(LOG_FILE, "a") as f:
        f.write(f"\n--- {label} {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} ---\n")
