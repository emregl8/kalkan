import os
import shutil
import stat


def ensure_backup(path: str) -> str:
    backup = path + ".backup"
    if not os.path.exists(backup) and os.path.exists(path):
        shutil.copy2(path, backup)
        os.chown(backup, 0, 0)
        os.chmod(backup, stat.S_IRUSR | stat.S_IWUSR)
    return backup
