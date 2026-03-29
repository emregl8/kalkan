import subprocess


def sudo_run(cmd: list, **kwargs) -> subprocess.CompletedProcess:
    return subprocess.run(["sudo"] + list(cmd), **kwargs)


def sudo_write(path: str, content: str) -> None:
    subprocess.run(["sudo", "tee", path], input=content, text=True,
                   capture_output=True, check=True)


def sudo_copy(src: str, dst: str) -> None:
    subprocess.run(["sudo", "cp", "-p", src, dst], check=True, capture_output=True)


def sudo_chown(path: str, uid: int, gid: int) -> None:
    subprocess.run(["sudo", "chown", f"{uid}:{gid}", path],
                   check=True, capture_output=True)


def sudo_chmod(path: str, mode: int) -> None:
    subprocess.run(["sudo", "chmod", oct(mode)[2:], path],
                   check=True, capture_output=True)


def sudo_makedirs(path: str, mode: int = 0o755) -> None:
    subprocess.run(["sudo", "mkdir", "-p", path], check=True, capture_output=True)
    sudo_chmod(path, mode)


def sudo_exists(path: str) -> bool:
    return subprocess.run(["sudo", "test", "-e", path]).returncode == 0


def sudo_file_nonempty(path: str) -> bool:
    return subprocess.run(["sudo", "test", "-s", path]).returncode == 0


def sudo_read(path: str) -> str:
    r = subprocess.run(["sudo", "cat", path], capture_output=True, text=True, check=True)
    return r.stdout


def sudo_remove(path: str) -> None:
    subprocess.run(["sudo", "rm", "-f", path], check=True, capture_output=True)
