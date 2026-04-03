import os
import subprocess
import threading

_lock = threading.Lock()
_tracked_procs: list[subprocess.Popen] = []


def _track(proc: subprocess.Popen) -> None:
    with _lock:
        _tracked_procs.append(proc)


def _untrack(proc: subprocess.Popen) -> None:
    with _lock:
        try:
            _tracked_procs.remove(proc)
        except ValueError:
            pass


def kill_tracked() -> None:
    with _lock:
        procs = list(_tracked_procs)
    for proc in procs:
        try:
            subprocess.run(
                ["sudo", "kill", "-9", str(proc.pid)],
                capture_output=True, timeout=3,
            )
        except Exception:
            pass


def pkg_installed(pkg: str) -> bool:
    r = subprocess.run(
        ["dpkg-query", "-W", "-f=${Status}", pkg],
        capture_output=True, text=True,
    )
    return "install ok installed" in r.stdout


def service_active(name: str) -> bool:
    r = subprocess.run(
        ["systemctl", "is-active", name],
        capture_output=True, text=True,
    )
    return r.stdout.strip() == "active"


def install_pkg(*packages: str) -> list[str]:
    installed = []
    for pkg in packages:
        if not pkg_installed(pkg):
            proc = subprocess.Popen(
                ["sudo", "apt-get", "install", "-y", "-q", pkg],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
                env={**os.environ, "DEBIAN_FRONTEND": "noninteractive"},
            )
            _track(proc)
            try:
                _, stderr_data = proc.communicate()
                if proc.returncode != 0:
                    msg = stderr_data.decode(errors="replace").strip()
                    raise RuntimeError(f"apt-get failed (exit {proc.returncode}): {msg}")
            finally:
                _untrack(proc)
            installed.append(pkg)
    return installed
