import os
from core.priv import sudo_exists, sudo_copy

BACKUP_DIR = os.path.join(
    os.path.expanduser("~/.local/share/kalkan"),
    "backups",
)


def _backup_path(original: str) -> str:
    return os.path.join(BACKUP_DIR, original.lstrip("/"))


def ensure_backup(path: str) -> str:
    backup = _backup_path(path)
    if not os.path.exists(backup) and sudo_exists(path):
        os.makedirs(os.path.dirname(backup), exist_ok=True)
        sudo_copy(path, backup)
    return backup
