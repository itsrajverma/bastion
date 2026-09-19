"""install_package through the real executor: role, approval hash, catalog, audit."""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient

from bastion.tools import packages
from bastion.tools._exec import CmdResult
from tests.conftest import ADMIN_TOKEN as ADMIN
from tests.conftest import OPERATOR_TOKEN as OPERATOR
from tests.conftest import VIEWER_TOKEN as VIEWER
from tests.conftest import make_settings


def auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture
def client(tmp_path: Path) -> Iterator[TestClient]:
    from bastion.executor.main import create_app

    app = create_app(make_settings(tmp_path, enabled_risks=["read", "write", "admin"]))
    with TestClient(app, raise_server_exceptions=False) as c:
        yield c


@pytest.fixture
def fake_apt(monkeypatch: pytest.MonkeyPatch) -> list[list[str]]:
    calls: list[list[str]] = []

    def fake_run(argv: list[str], *, timeout: float = 30.0, sudo: bool = False) -> Any:
        calls.append(list(argv))
        if argv[0] == "dpkg-query":
            return CmdResult(tuple(argv), 0, "nginx\t1.24.0-2ubuntu7\tinstalled\n", "")
        assert sudo, argv
        return CmdResult(tuple(argv), 0, "done", "")

    monkeypatch.setattr(packages, "run_cmd", fake_run)
    return calls


def test_install_hidden_below_admin(client: TestClient, fake_apt: list[list[str]]) -> None:
    for token in (VIEWER, OPERATOR):
        names = {t["name"] for t in client.get("/tools", headers=auth(token)).json()["tools"]}
        assert "install_package" not in names
        assert "package_status" in names
        r = client.post(
            "/plan",
            json={"tool": "install_package", "args": {"package": "nginx"}},
            headers=auth(token),
        )
        assert r.status_code == 403 and r.json()["error"] == "policy_denied"
    names = {t["name"] for t in client.get("/tools", headers=auth(ADMIN)).json()["tools"]}
    assert "install_package" in names
    assert fake_apt == []


def test_install_hidden_when_admin_risk_disabled(tmp_path: Path) -> None:
    from bastion.executor.main import create_app

    app = create_app(make_settings(tmp_path, enabled_risks=["read", "write"]))
    with TestClient(app, raise_server_exceptions=False) as c:
        names = {t["name"] for t in c.get("/tools", headers=auth(ADMIN)).json()["tools"]}
        assert "install_package" not in names
        r = c.post(
            "/plan",
            json={"tool": "install_package", "args": {"package": "nginx"}},
            headers=auth(ADMIN),
        )
        assert r.status_code == 403
        assert "not enabled" in r.json()["message"]


def test_install_requires_plan_hash_and_is_audited(
    client: TestClient, fake_apt: list[list[str]]
) -> None:
    body = {"tool": "install_package", "args": {"package": "nginx"}}
    r = client.post("/run", json=body, headers=auth(ADMIN))
    assert r.status_code == 403 and "approval" in r.json()["message"]
    assert fake_apt == []
    plan = client.post("/plan", json=body, headers=auth(ADMIN)).json()
    assert plan["risk"] == "admin" and plan["approve"] is True
    assert plan["plan"].splitlines()[-1].endswith("/usr/bin/apt-get install -y nginx")
    assert fake_apt == []  # /plan never executes
    r = client.post(
        "/run", json={**body, "approved_plan_hash": plan["plan_hash"]}, headers=auth(ADMIN)
    )
    assert r.status_code == 200, r.text
    assert [c[0] for c in fake_apt] == ["systemd-run", "systemd-run", "dpkg-query"]
    assert fake_apt[1][-3:] == ["install", "-y", "nginx"]
    assert "nginx: installed 1.24.0-2ubuntu7" in r.json()["result"]
    recs = client.get("/audit", headers=auth(ADMIN)).json()
    assert recs["verified"] is True
    assert recs["records"][-1]["tool"] == "install_package"
    assert recs["records"][-1]["args"] == {"package": "nginx"}
    assert recs["records"][-1]["plan"] == plan["plan"]


def test_install_plan_hash_bound_to_package(client: TestClient, fake_apt: list[list[str]]) -> None:
    plan = client.post(
        "/plan",
        json={"tool": "install_package", "args": {"package": "redis"}},
        headers=auth(ADMIN),
    ).json()
    r = client.post(
        "/run",
        json={
            "tool": "install_package",
            "args": {"package": "mysql"},
            "approved_plan_hash": plan["plan_hash"],
        },
        headers=auth(ADMIN),
    )
    assert r.status_code == 403
    assert fake_apt == []


def test_install_outside_catalog_is_422(client: TestClient, fake_apt: list[list[str]]) -> None:
    for bad in ("vim", "nginx redis", "nginx; apt-get remove nginx", "", "NGINX"):
        r = client.post(
            "/plan",
            json={"tool": "install_package", "args": {"package": bad}},
            headers=auth(ADMIN),
        )
        assert r.status_code == 422, bad
    assert fake_apt == []
