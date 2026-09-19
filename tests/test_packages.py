"""Package catalog: closed enum, exact apt names, read-only status tool."""

from __future__ import annotations

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


def test_catalog_entries_are_plain_apt_names() -> None:
    import re

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
