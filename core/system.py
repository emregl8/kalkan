import subprocess


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
            subprocess.run(
                ["sudo", "apt-get", "install", "-y", "-q", pkg],
                check=True,
            )
            installed.append(pkg)
    return installed
