"""Software packages from a closed catalog (Debian/Ubuntu ``apt`` only).

The catalog is code, not config: each short name maps to a fixed tuple of apt
package names. The LLM picks a catalog key; it never supplies a package name,
a version, a repository, or a flag (invariant 4).

Bastion can *install* from the catalog. It can never remove, purge, or
downgrade a package: no such tool exists and no sudoers rule allows it.

``apt-get`` cannot run inside the executor's ``ProtectSystem=strict`` sandbox
(the whole filesystem is read-only there), so the install is handed to
``systemd-run --wait --pipe``: PID 1 spawns a transient unit outside the
sandbox, the executor waits for it and relays its output and exit status.
The sudoers file lists one exact ``systemd-run ... apt-get install -y <pkgs>``
line per catalog entry, so nothing else can be passed through this path.
"""

from __future__ import annotations

from bastion.tools import tool
from bastion.tools._exec import CmdResult, render_argv, run_cmd
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

APT_GET = "/usr/bin/apt-get"
#: Fixed prefix for every apt call: synchronous, output piped back, unit
#: unloaded afterwards even on failure, debconf never prompts.
SYSTEMD_RUN_PREFIX: tuple[str, ...] = (
    "systemd-run",
    "--wait",
    "--pipe",
    "--collect",
    "--quiet",
    "--setenv=DEBIAN_FRONTEND=noninteractive",
)
UPDATE_TIMEOUT = 180.0
INSTALL_TIMEOUT = 600.0
#: apt prints hundreds of progress lines; keep the tail, which holds the outcome.
_TAIL_LINES = 40


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


def apt_update_argv() -> list[str]:
    return [*SYSTEMD_RUN_PREFIX, "--unit=bastion-apt-update", APT_GET, "update", "-q"]


def apt_install_argv(package: str) -> list[str]:
    return [
        *SYSTEMD_RUN_PREFIX,
        f"--unit=bastion-apt-install-{package}",
        APT_GET,
        "install",
        "-y",
        *apt_packages(package),
    ]


def _install_plan(package: str) -> str:
    return "\n".join(
        (
            render_argv(apt_update_argv(), sudo=True),
            render_argv(apt_install_argv(package), sudo=True),
        )
    )


def _tail(result: CmdResult) -> str:
    lines = result.output().splitlines()
    if len(lines) > _TAIL_LINES:
        skipped = len(lines) - _TAIL_LINES
        lines = [f"...[{skipped} lines omitted]", *lines[-_TAIL_LINES:]]
    body = "\n".join(lines) or "(no output)"
    return f"$ {' '.join(result.argv)}\n{body}\n[exit {result.returncode}]"


@tool(risk="admin", approve=True, plan=_install_plan, verify_with="package_status")
def install_package(package: Package) -> str:
    """Install a catalog entry with apt-get (Debian/Ubuntu): refresh the package index, then
    install the fixed list of apt packages behind the entry.

    Only the catalog keys can be installed, with the exact package names shown in the
    plan; there is no free-text package, version, or repository argument. Packages are
    never removed, purged, or downgraded. Runs outside the executor sandbox through a
    transient systemd unit. Requires admin approval and can take several minutes.

    Args:
        package: catalog key, one of nginx, apache, php, python, django, nodejs, mysql,
            mariadb, postgresql, redis, memcached, certbot.
    """
    update = run_cmd(apt_update_argv(), sudo=True, timeout=UPDATE_TIMEOUT)
    install = run_cmd(apt_install_argv(package), sudo=True, timeout=INSTALL_TIMEOUT)
    parts = [_tail(update), _tail(install)]
    if not install.ok:
        parts.append(f"apt-get install failed with exit {install.returncode}")
    parts.append(package_status.run({"package": package}))
    service = CATALOG_SERVICES.get(package)
    if install.ok and service:
        parts.append(f"hint: the unit is {service!r}; check it with service_status if listed")
    return "\n".join(parts)
