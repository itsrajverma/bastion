"""Write/admin tools through the real executor: approval hash, guards, validation."""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient

from bastion.tools import postgres, process
from bastion.tools._context import ToolContext, set_context
from bastion.tools._exec import CmdResult
from tests.conftest import ADMIN_TOKEN as ADMIN
from tests.conftest import OPERATOR_TOKEN as OPERATOR
from tests.conftest import make_settings


def auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture
def full_client(tmp_path: Path) -> Iterator[TestClient]:
    from bastion.executor.main import create_app

    app = create_app(make_settings(tmp_path, enabled_risks=["read", "write", "admin"]))
    with TestClient(app, raise_server_exceptions=False) as c:
        yield c


class FakeCmd:
    def __init__(self) -> None:
        self.calls: list[tuple[list[str], bool]] = []

    def __call__(self, argv: list[str], *, timeout: float = 30.0, sudo: bool = False) -> Any:
        self.calls.append((list(argv), sudo))
        return CmdResult(tuple(argv), 0, "active", "")


@pytest.fixture
def fake_cmd(monkeypatch: pytest.MonkeyPatch) -> FakeCmd:
    fake = FakeCmd()
    monkeypatch.setattr("bastion.tools.services.run_cmd", fake)
    monkeypatch.setattr("bastion.tools.web.run_cmd", fake)
    return fake


def test_write_tool_requires_plan_hash(full_client: TestClient, fake_cmd: FakeCmd) -> None:
    body = {"tool": "restart_service", "args": {"service": "nginx"}}
    r = full_client.post("/run", json=body, headers=auth(OPERATOR))
    assert r.status_code == 403
    assert "approval" in r.json()["message"]
    assert fake_cmd.calls == []
    r = full_client.post(
        "/run", json={**body, "approved_plan_hash": "0" * 64}, headers=auth(OPERATOR)
    )
    assert r.status_code == 403
    assert fake_cmd.calls == []
    plan = full_client.post("/plan", json=body, headers=auth(OPERATOR)).json()
    assert plan["plan"] == "sudo systemctl restart nginx"
    assert plan["approve"] is True and plan["risk"] == "write"
    assert fake_cmd.calls == []  # /plan never executes
    r = full_client.post(
        "/run", json={**body, "approved_plan_hash": plan["plan_hash"]}, headers=auth(OPERATOR)
    )
    assert r.status_code == 200, r.text
    assert fake_cmd.calls[0] == (["systemctl", "restart", "nginx"], True)
    recs = full_client.get("/audit", headers=auth(OPERATOR)).json()["records"]
    assert recs[-1]["tool"] == "restart_service" and recs[-1]["plan"] == plan["plan"]


def test_plan_hash_is_bound_to_args(full_client: TestClient, fake_cmd: FakeCmd) -> None:
    plan = full_client.post(
        "/plan",
        json={"tool": "restart_service", "args": {"service": "celery"}},
        headers=auth(ADMIN),
    ).json()
    r = full_client.post(
        "/run",
        json={
            "tool": "restart_service",
            "args": {"service": "postgresql"},
            "approved_plan_hash": plan["plan_hash"],
        },
        headers=auth(ADMIN),
    )
    assert r.status_code == 403
    assert fake_cmd.calls == []


BAD_DOMAINS = (
    "Example.com",
    "app_1.example.com",
    "app.example.com; id",
    "-bad.example.com",
    "nodots",
    "a..b.com",
    "$(id).example.com",
    "app.example.com/../x",
    "",
    "a" * 300 + ".com",
)


def test_invalid_domain_422(full_client: TestClient, fake_cmd: FakeCmd) -> None:
    set_context(ToolContext(certbot_email="ops@example.com"))
    for bad in BAD_DOMAINS:
        r = full_client.post(
            "/plan", json={"tool": "install_ssl", "args": {"domain": bad}}, headers=auth(ADMIN)
        )
        assert r.status_code == 422, bad
    r = full_client.post(
        "/plan",
        json={"tool": "install_ssl", "args": {"domain": "app.example.com"}},
        headers=auth(ADMIN),
    )
    assert r.status_code == 200
    assert r.json()["plan"] == (
        "sudo certbot --nginx -d app.example.com --non-interactive --agree-tos -m ops@example.com"
    )
    assert fake_cmd.calls == []
    r = full_client.post(
        "/run",
        json={
            "tool": "install_ssl",
            "args": {"domain": "app.example.com"},
            "approved_plan_hash": r.json()["plan_hash"],
        },
        headers=auth(ADMIN),
    )
    assert r.status_code == 200, r.text
    assert fake_cmd.calls[-1][0][:4] == ["certbot", "--nginx", "-d", "app.example.com"]
    assert fake_cmd.calls[-1][1] is True


def test_install_ssl_without_email_is_config_error(full_client: TestClient) -> None:
    set_context(ToolContext(certbot_email=None))
    r = full_client.post(
        "/plan",
        json={"tool": "install_ssl", "args": {"domain": "app.example.com"}},
        headers=auth(ADMIN),
    )
    assert r.status_code == 500
    assert r.json()["error"] == "config_error"
    assert "Traceback" not in r.text


PROCESS_TABLE = {
    1: process.ProcessInfo(1, "systemd", "root", "/sbin/init", 99999),
    700: process.ProcessInfo(700, "sshd", "root", "sshd: /usr/sbin/sshd -D", 99999),
    800: process.ProcessInfo(800, "postgres", "postgres", "postgres: checkpointer", 99999),
    900: process.ProcessInfo(
        900, "nginx", "www-data", "nginx: master process /usr/sbin/nginx", 99999
    ),
    901: process.ProcessInfo(901, "gunicorn", "www-data", "gunicorn: master [app]", 99999),
    902: process.ProcessInfo(902, "dockerd", "root", "/usr/bin/dockerd -H fd://", 99999),
    950: process.ProcessInfo(950, "python", "www-data", "gunicorn: worker [app]", 5),
    960: process.ProcessInfo(960, "python", "www-data", "gunicorn: worker [app]", 3600),
    970: process.ProcessInfo(970, "celery", "app", "celery worker -A proj", 7200),
}


@pytest.fixture
def fake_processes(monkeypatch: pytest.MonkeyPatch) -> list[int]:
    def fake_inspect(pid: int) -> process.ProcessInfo:
        if pid not in PROCESS_TABLE:
            raise process.ValidationFailed(f"no process with pid {pid}")
        return PROCESS_TABLE[pid]

    monkeypatch.setattr(process, "inspect_process", fake_inspect)
    terminated: list[int] = []

    class FakeProc:
        def __init__(self, pid: int) -> None:
            self.pid = pid

        def terminate(self) -> None:
            terminated.append(self.pid)

        def wait(self, timeout: float = 0) -> None:
            return None

    monkeypatch.setattr(process.psutil, "Process", FakeProc)
    return terminated


@pytest.mark.parametrize(
    ("pid", "why"),
    [
        (1, "init"),
        (700, "protected user"),
        (800, "protected user"),
        (900, "protected command"),
        (901, "protected command"),
        (902, "protected user"),
        (950, "younger than"),
    ],
)
def test_protected_process_refused(
    full_client: TestClient, fake_processes: list[int], pid: int, why: str
) -> None:
    r = full_client.post(
        "/plan", json={"tool": "kill_process", "args": {"pid": pid}}, headers=auth(OPERATOR)
    )
    assert r.status_code == 403, (pid, r.text)
    assert r.json()["error"] == "protected_target"
    assert why in r.json()["message"], (pid, r.json()["message"])
    r = full_client.post(
        "/run",
        json={"tool": "kill_process", "args": {"pid": pid}, "approved_plan_hash": "f" * 64},
        headers=auth(OPERATOR),
    )
    assert r.status_code == 403
    assert fake_processes == []


def test_unprotected_process_gets_sigterm_only(
    full_client: TestClient, fake_processes: list[int]
) -> None:
    r = full_client.post(
        "/run", json={"tool": "kill_process", "args": {"pid": 123456}}, headers=auth(OPERATOR)
    )
    assert r.status_code == 422
    plan = full_client.post(
        "/plan", json={"tool": "kill_process", "args": {"pid": 960}}, headers=auth(OPERATOR)
    ).json()
    assert plan["plan"] == "kill -TERM 960"
    r = full_client.post(
        "/run",
        json={
            "tool": "kill_process",
            "args": {"pid": 960},
            "approved_plan_hash": plan["plan_hash"],
        },
        headers=auth(OPERATOR),
    )
    assert r.status_code == 200, r.text
    assert fake_processes == [960]
    assert "SIGTERM" in r.json()["result"]
    assert "-9" not in r.json()["plan"]


def test_db_cancel_guard_in_sql(full_client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    seen: list[tuple[str, tuple[Any, ...]]] = []

    def fake_query(sql: str, params: tuple[Any, ...] = ()) -> list[tuple[Any, ...]]:
        seen.append((sql, tuple(params)))
        if params and params[0] == 4242:
            return [(True, 4242, "app", "active", "SELECT count(*) FROM huge")]
        return []  # walsender / autovacuum / replication user: filtered by the WHERE clause

    monkeypatch.setattr(postgres, "query", fake_query)
    plan = full_client.post(
        "/plan", json={"tool": "db_cancel_query", "args": {"pid": 4242}}, headers=auth(OPERATOR)
    ).json()
    assert "pg_cancel_backend" in plan["plan"]
    assert "backend_type = 'client backend'" in plan["plan"]
    assert "rolreplication" in plan["plan"]
    assert "pid = 4242" in plan["plan"]
    r = full_client.post(
        "/run",
        json={
            "tool": "db_cancel_query",
            "args": {"pid": 4242},
            "approved_plan_hash": plan["plan_hash"],
        },
        headers=auth(OPERATOR),
    )
    assert r.status_code == 200, r.text
    assert seen[-1][1] == (4242,)
    assert "%s" in seen[-1][0]  # parameterised, never interpolated
    assert "cancelled: True" in r.json()["result"]

    plan = full_client.post(
        "/plan", json={"tool": "db_terminate_query", "args": {"pid": 77}}, headers=auth(ADMIN)
    ).json()
    assert "pg_terminate_backend" in plan["plan"]
    r = full_client.post(
        "/run",
        json={
            "tool": "db_terminate_query",
            "args": {"pid": 77},
            "approved_plan_hash": plan["plan_hash"],
        },
        headers=auth(ADMIN),
    )
    assert r.status_code == 403
    assert r.json()["error"] == "protected_target"
    r = full_client.post(
        "/plan", json={"tool": "db_terminate_query", "args": {"pid": 77}}, headers=auth(OPERATOR)
    )
    assert r.status_code == 403 and r.json()["error"] == "policy_denied"


def test_sql_never_touches_table_rows() -> None:
    for sql in (
        postgres.ACTIVE_QUERIES_SQL,
        postgres.LOCKS_SQL,
        postgres.CANCEL_SQL,
        postgres.TERMINATE_SQL,
    ):
        lowered = sql.lower()
        assert "from pg_stat_activity" in lowered
        for banned in (
            "delete ",
            "drop ",
            "truncate ",
            "update ",
            "insert ",
            "copy ",
            "pg_read_file",
        ):
            assert banned not in lowered
