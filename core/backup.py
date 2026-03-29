from core.priv import sudo_exists, sudo_copy, sudo_chown, sudo_chmod


def ensure_backup(path: str) -> str:
    backup = path + ".backup"
    if not sudo_exists(backup) and sudo_exists(path):
        sudo_copy(path, backup)
        sudo_chown(backup, 0, 0)
        sudo_chmod(backup, 0o600)
    return backup
