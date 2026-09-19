"""Software packages from a closed catalog (Debian/Ubuntu ``apt`` only).

The catalog is code, not config: each short name maps to a fixed tuple of apt
package names. The LLM picks a catalog key; it never supplies a package name,
a version, a repository, or a flag (invariant 4).
"""

from __future__ import annotations

from bastion.tools import tool
from bastion.tools._exec import run_cmd
from bastion.tools._types import PACKAGES, Package

#: Catalog key -> exact apt packages installed for it, in order.
CATALOG: dict[str, tuple[str, ...]] = {
    "nginx": ("nginx",),
    "apache": ("apache2",),
    "php": (
        "php-fpm",
        "php-cli",
        "php-mysql",
        "php-pgsql",
        "php-curl",
        "php-mbstring",
        "php-xml",
        "php-zip",
    ),
    "python": ("python3", "python3-venv", "python3-pip"),
    "django": ("python3-django", "python3-venv", "python3-pip"),
    "nodejs": ("nodejs", "npm"),
    "mysql": ("mysql-server", "mysql-client"),
    "mariadb": ("mariadb-server", "mariadb-client"),
    "postgresql": ("postgresql", "postgresql-contrib"),
    "redis": ("redis-server",),
    "memcached": ("memcached",),
    "certbot": ("certbot", "python3-certbot-nginx"),
}

#: The systemd unit each catalog entry provides, if any (``service_status`` after install).
CATALOG_SERVICES: dict[str, str | None] = {
    "nginx": "nginx",
    "apache": "apache2",
    "php": None,  # php<version>-fpm; the unit name depends on the distro release
    "python": None,
    "django": None,
    "nodejs": None,
    "mysql": "mysql",
    "mariadb": "mariadb",
    "postgresql": "postgresql",
    "redis": "redis-server",
    "memcached": "memcached",
    "certbot": None,
}

assert set(CATALOG) == set(PACKAGES), "catalog and Package enum must match"
assert set(CATALOG_SERVICES) == set(PACKAGES), "catalog services and Package enum must match"

_DPKG_FORMAT = "${binary:Package}\\t${Version}\\t${db:Status-Status}\\n"


def apt_packages(package: str) -> tuple[str, ...]:
    """The exact apt package names behind a catalog key."""
    return CATALOG[package]


def dpkg_query_argv(package: str) -> list[str]:
    return ["dpkg-query", "-W", "-f", _DPKG_FORMAT, *apt_packages(package)]


def _status_plan(package: str) -> str:
    return f"dpkg-query -W -f '{_DPKG_FORMAT}' {' '.join(apt_packages(package))}"


@tool(risk="read", plan=_status_plan)
def package_status(package: Package) -> str:
    """Show whether the apt packages behind a catalog entry are installed, and which version.

    Args:
        package: catalog key, one of nginx, apache, php, python, django, nodejs, mysql,
            mariadb, postgresql, redis, memcached, certbot.
    """
    wanted = apt_packages(package)
    result = run_cmd(dpkg_query_argv(package), timeout=20)
    installed: dict[str, tuple[str, str]] = {}
    for line in result.stdout.splitlines():
        parts = line.split("\t")
        if len(parts) == 3:
            name, version, status = parts
            installed[name] = (version or "-", status or "unknown")
    lines = [f"package: {package}", f"apt packages: {' '.join(wanted)}"]
    for name in wanted:
        if name in installed and installed[name][1] == "installed":
            version, _ = installed[name]
            lines.append(f"  {name}: installed {version}")
        elif name in installed:
            version, status = installed[name]
            lines.append(f"  {name}: {status} {version}")
        else:
            lines.append(f"  {name}: not installed")
    missing = [n for n in wanted if installed.get(n, ("", ""))[1] != "installed"]
    lines.append(f"summary: {'all installed' if not missing else 'missing ' + ' '.join(missing)}")
    return "\n".join(lines)
