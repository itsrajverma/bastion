"""Package catalog: closed enum, exact apt names, read-only status, install-only apt."""

from __future__ import annotations

import re
from typing import Any

import pytest

from bastion.core.errors import ValidationFailed
from bastion.tools import REGISTRY, packages
from bastion.tools._exec import CmdResult
from bastion.tools._types import PACKAGES

APT_NAME = r"^[a-z0-9][a-z0-9+.-]+$"


def test_catalog_matches_enum() -> None:
    assert set(packages.CATALOG) == set(PACKAGES)
    assert set(packages.CATALOG_SERVICES) == set(PACKAGES)
    enum = REGISTRY["package_status"].input_schema()["properties"]["package"]["enum"]
    assert list(enum) == list(PACKAGES)
    assert REGISTRY["install_package"].input_schema()["properties"]["package"]["enum"] == enum


def test_catalog_entries_are_plain_apt_names() -> None:
    for key, apt in packages.CATALOG.items():
        assert apt, key
        for name in apt:
            assert re.match(APT_NAME, name), (key, name)
            assert " " not in name and not name.startswith("-"), (key, name)


def test_user_facing_stack_is_present() -> None:
    for key in ("nginx", "apache", "php", "django", "mysql", "postgresql", "redis"):
        assert key in packages.CATALOG
    assert packages.CATALOG["apache"] == ("apache2",)
    assert packages.CATALOG["redis"] == ("redis-server",)
    assert "python3-django" in packages.CATALOG["django"]
    assert "mysql-server" in packages.CATALOG["mysql"]


def test_catalog_units_are_in_the_service_enum() -> None:
    """Whatever install_package can install, service_status/restart_service can manage."""
    from bastion.tools._types import SERVICES

    for key, unit in packages.CATALOG_SERVICES.items():
        if unit is not None:
            assert unit in SERVICES, (key, unit)
            assert REGISTRY["service_status"].validate({"service": unit}) == {"service": unit}
            plan = REGISTRY["restart_service"].plan({"service": unit})
            assert plan == f"sudo systemctl restart {unit}"


def test_package_status_rejects_free_text() -> None:
    spec = REGISTRY["package_status"]
    assert spec.validate({"package": "nginx"}) == {"package": "nginx"}
    for bad in ("vim", "nginx; rm -rf /", "", "NGINX", "../etc", "nginx=1.0", "-y"):
        with pytest.raises(ValidationFailed):
            spec.validate({"package": bad})
    with pytest.raises(ValidationFailed):
        spec.validate({"package": "nginx", "version": "1.0"})


def test_package_status_plan_is_dpkg_query_only() -> None:
    plan = REGISTRY["package_status"].plan({"package": "postgresql"})
    assert plan.startswith("dpkg-query -W -f ")
    assert plan.endswith(" postgresql postgresql-contrib")
    assert "sudo" not in plan and "apt" not in plan


def test_package_status_renders_installed_and_missing(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: list[tuple[list[str], bool]] = []

    def fake_run(argv: list[str], *, timeout: float = 30.0, sudo: bool = False) -> Any:
        seen.append((list(argv), sudo))
        return CmdResult(
            tuple(argv),
            1,
            "php-fpm\t2:8.3+93ubuntu2\tinstalled\nphp-cli\t2:8.3+93ubuntu2\tinstalled\n"
            "php-zip\t\tnot-installed\n",
            "dpkg-query: no packages found matching php-mysql\n",
        )

    monkeypatch.setattr(packages, "run_cmd", fake_run)
    out = REGISTRY["package_status"].run({"package": "php"})
    assert seen[0][1] is False  # never sudo
    assert seen[0][0][:3] == ["dpkg-query", "-W", "-f"]
    assert "php-fpm: installed 2:8.3+93ubuntu2" in out
    assert "php-mysql: not installed" in out
    assert "php-zip: not-installed" in out
    assert out.splitlines()[-1].startswith("summary: missing php-mysql")


def test_package_status_all_installed(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_run(argv: list[str], *, timeout: float = 30.0, sudo: bool = False) -> Any:
        return CmdResult(tuple(argv), 0, "redis-server\t5:7.0.15-1\tinstalled\n", "")

    monkeypatch.setattr(packages, "run_cmd", fake_run)
    out = REGISTRY["package_status"].run({"package": "redis"})
    assert "redis-server: installed 5:7.0.15-1" in out
    assert out.endswith("summary: all installed")


# -- install_package ---------------------------------------------------------------------


def test_install_argv_is_fixed_and_absolute() -> None:
    argv = packages.apt_install_argv("nginx")
    assert argv[0] == "systemd-run"
    assert argv[1:6] == [
        "--wait",
        "--pipe",
        "--collect",
        "--quiet",
        "--setenv=DEBIAN_FRONTEND=noninteractive",
    ]
    assert argv[6] == "--unit=bastion-apt-install-nginx"
    assert argv[7:] == ["/usr/bin/apt-get", "install", "-y", "nginx"]
    update = packages.apt_update_argv()
    assert update[6:] == ["--unit=bastion-apt-update", "/usr/bin/apt-get", "update", "-q"]
    for key in PACKAGES:
        argv = packages.apt_install_argv(key)
        assert "install" in argv and "-y" in argv
        for banned in ("remove", "purge", "autoremove", "dist-upgrade", "--allow-downgrades", "-t"):
            assert banned not in argv, (key, banned)


def test_install_package_is_admin_only_and_verified() -> None:
    spec = REGISTRY["install_package"]
    assert spec.risk == "admin" and spec.approve is True
    assert spec.roles == ("admin",)
    assert spec.verify_with == "package_status"


def test_no_package_removal_tool_exists() -> None:
    for name in REGISTRY:
        for banned in ("remove", "purge", "uninstall", "downgrade"):
            assert banned not in name, name
    for spec in REGISTRY.values():
        if spec.plan_fn is None:
            continue
        for key in PACKAGES:
            args = {"package": key} if "package" in spec.input_schema()["properties"] else None
            if args is None:
                break
            plan = spec.plan(args)
            assert "apt-get remove" not in plan and "apt-get purge" not in plan, spec.name


def test_install_package_plan_shows_both_exact_commands() -> None:
    plan = REGISTRY["install_package"].plan({"package": "postgresql"})
    lines = plan.splitlines()
    assert len(lines) == 2
    assert lines[0] == (
        "sudo systemd-run --wait --pipe --collect --quiet "
        "--setenv=DEBIAN_FRONTEND=noninteractive --unit=bastion-apt-update "
        "/usr/bin/apt-get update -q"
    )
    assert lines[1] == (
        "sudo systemd-run --wait --pipe --collect --quiet "
        "--setenv=DEBIAN_FRONTEND=noninteractive --unit=bastion-apt-install-postgresql "
        "/usr/bin/apt-get install -y postgresql postgresql-contrib"
    )


def test_install_package_rejects_free_text() -> None:
    spec = REGISTRY["install_package"]
    for bad in ("vim", "nginx redis", "nginx;id", "nginx=1.24", "--reinstall", ""):
        with pytest.raises(ValidationFailed):
            spec.plan({"package": bad})
    with pytest.raises(ValidationFailed):
        spec.plan({"package": "nginx", "flags": "--force-yes"})


class FakeApt:
    """Records every call and answers apt/dpkg the way a real host would."""

    def __init__(self, *, install_rc: int = 0) -> None:
        self.calls: list[tuple[list[str], bool, float]] = []
        self.install_rc = install_rc
        self._installed = False

    def __call__(self, argv: list[str], *, timeout: float = 30.0, sudo: bool = False) -> Any:
        self.calls.append((list(argv), sudo, timeout))
        if argv[0] == "dpkg-query":
            if self._installed:
                return CmdResult(tuple(argv), 0, "redis-server\t5:7.0.15-1\tinstalled\n", "")
            return CmdResult(
                tuple(argv), 1, "", "dpkg-query: no packages found matching redis-server\n"
            )
        if argv[0] == "systemd-run" and "update" in argv:
            return CmdResult(
                tuple(argv),
                0,
                "Hit:1 http://archive.ubuntu.com/ubuntu noble InRelease\nReading package lists...\n",
                "",
            )
        if argv[0] == "systemd-run" and "install" in argv:
            self._installed = self.install_rc == 0
            progress = "\n".join(f"Get:{i} pkg{i}" for i in range(60))
            body = progress + "\nSetting up redis-server (5:7.0.15-1) ...\n"
            err = "" if self.install_rc == 0 else "E: Unable to locate package\n"
            return CmdResult(tuple(argv), self.install_rc, body, err)
        raise AssertionError(f"unexpected argv {argv}")


def test_install_package_runs_update_then_install_then_status(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake = FakeApt()
    monkeypatch.setattr(packages, "run_cmd", fake)
    out = REGISTRY["install_package"].run({"package": "redis"})
    argvs = [c[0][0] for c in fake.calls]
    assert argvs == ["systemd-run", "systemd-run", "dpkg-query"]
    assert fake.calls[0][1] is True and fake.calls[1][1] is True  # apt via sudo
    assert fake.calls[2][1] is False  # dpkg-query never via sudo
    assert fake.calls[0][2] == packages.UPDATE_TIMEOUT
    assert fake.calls[1][2] == packages.INSTALL_TIMEOUT
    assert "Setting up redis-server" in out
    assert "lines omitted" in out  # long apt output is tailed
    assert "redis-server: installed 5:7.0.15-1" in out
    assert "summary: all installed" in out
    assert "unit is 'redis-server'" in out


def test_install_package_reports_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = FakeApt(install_rc=100)
    monkeypatch.setattr(packages, "run_cmd", fake)
    out = REGISTRY["install_package"].run({"package": "redis"})
    assert "apt-get install failed with exit 100" in out
    assert "Unable to locate package" in out
    assert "summary: missing redis-server" in out
    assert "hint:" not in out
