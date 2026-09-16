"""Executor API: auth, default deny, validation, structured errors, audit."""

from __future__ import annotations

import json
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient

from bastion.core.audit import AuditLog
from bastion.executor.config import ExecutorSettings, settings_from_dict
from bastion.executor.main import create_app
from bastion.tools import REGISTRY

VIEWER = "viewer-token-" + "v" * 32
OPERATOR = "operator-token-" + "o" * 32
ADMIN = "admin-token-" + "a" * 32


def make_settings(tmp_path: Path, **overrides: Any) -> ExecutorSettings:
    raw: dict[str, Any] = {
        "bind": "127.0.0.1:8710",
        "enabled_risks": ["read"],
        "tokens": {
            "vera": {"token": VIEWER, "role": "viewer"},
            "oscar": {"token": OPERATOR, "role": "operator"},
            "ada": {"token": ADMIN, "role": "admin"},
        },
        "audit_path": str(tmp_path / "audit.jsonl"),
    }
    raw.update(overrides)
    return settings_from_dict(raw)


@pytest.fixture
def client(tmp_path: Path) -> Iterator[TestClient]:
    app = create_app(make_settings(tmp_path))
    with TestClient(app, raise_server_exceptions=False) as c:
        yield c


@pytest.fixture
def full_client(tmp_path: Path) -> Iterator[TestClient]:
    app = create_app(make_settings(tmp_path, enabled_risks=["read", "write", "admin"]))
    with TestClient(app, raise_server_exceptions=False) as c:
        yield c


def auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def first_tool(risk: str) -> str:
    for spec in REGISTRY.values():
        if spec.risk == risk:
            return spec.name
    pytest.skip(f"no {risk} tools registered yet")


# -- auth ---------------------------------------------------------------------


def test_health_needs_no_auth(client: TestClient) -> None:
    r = client.get("/health")
    assert r.status_code == 200
    assert r.json()["status"] == "ok"
    assert r.json()["enabled_risks"] == ["read"]


@pytest.mark.parametrize("path", ["/tools", "/audit"])
def test_missing_auth_rejected(client: TestClient, path: str) -> None:
    r = client.get(path)
    assert r.status_code == 401
    assert r.json()["error"] == "unauthorized"


def test_bad_token_rejected(client: TestClient) -> None:
    r = client.get("/tools", headers=auth("x" * 40))
    assert r.status_code == 401
    r = client.get("/tools", headers={"Authorization": "Basic abc"})
    assert r.status_code == 401
    r = client.get("/tools", headers={"Authorization": f"Bearer {ADMIN[:-1]}"})
    assert r.status_code == 401


def test_post_without_auth(client: TestClient) -> None:
    r = client.post("/run", json={"tool": "load_avg"})
    assert r.status_code == 401


# -- default deny / role filtering -----------------------------------------------


def test_tools_default_read_only_for_every_role(client: TestClient) -> None:
    for token in (VIEWER, OPERATOR, ADMIN):
        r = client.get("/tools", headers=auth(token))
        assert r.status_code == 200
        risks = {t["risk"] for t in r.json()["tools"]}
        assert risks == {"read"}
        names = {t["name"] for t in r.json()["tools"]}
        assert "load_avg" in names
        assert "ask_user" in names


def test_tools_filtered_by_role_when_enabled(full_client: TestClient) -> None:
    first_tool("write")
    first_tool("admin")

    def risks(token: str) -> set[str]:
        r = full_client.get("/tools", headers=auth(token))
        return {t["risk"] for t in r.json()["tools"]}

    assert risks(VIEWER) == {"read"}
    assert risks(OPERATOR) <= {"read", "write"}
    assert "write" in risks(OPERATOR)
    assert "admin" in risks(ADMIN)
    r = full_client.get("/tools", headers=auth(ADMIN))
    assert r.json()["role"] == "admin"
    assert r.json()["user"] == "ada"


def test_disabled_tool_returns_403(client: TestClient) -> None:
    write_tool = first_tool("write")
    r = client.post("/plan", json={"tool": write_tool, "args": {}}, headers=auth(ADMIN))
    assert r.status_code == 403
    assert r.json()["error"] == "policy_denied"
    assert "not enabled" in r.json()["message"]
    r = client.post("/run", json={"tool": write_tool, "args": {}}, headers=auth(ADMIN))
    assert r.status_code == 403


def test_role_too_low_returns_403(full_client: TestClient) -> None:
    write_tool = first_tool("write")
    r = full_client.post("/plan", json={"tool": write_tool, "args": {}}, headers=auth(VIEWER))
    assert r.status_code == 403
    assert "viewer" in r.json()["message"]
    admin_tool = first_tool("admin")
    r = full_client.post("/plan", json={"tool": admin_tool, "args": {}}, headers=auth(OPERATOR))
    assert r.status_code == 403


# -- validation --------------------------------------------------------------------


def test_unknown_tool_404(client: TestClient) -> None:
    r = client.post("/plan", json={"tool": "run_command", "args": {}}, headers=auth(ADMIN))
    assert r.status_code == 404
    assert r.json()["error"] == "tool_not_found"


def test_invalid_tool_name_422(client: TestClient) -> None:
    r = client.post("/plan", json={"tool": "rm -rf /", "args": {}}, headers=auth(ADMIN))
    assert r.status_code == 422
    assert r.json()["error"] == "validation_failed"
    assert "Traceback" not in r.text


def test_invalid_pid_422(client: TestClient) -> None:
    for pid in (-1, 0, "abc", 4_194_303):
        r = client.post(
            "/run", json={"tool": "process_detail", "args": {"pid": pid}}, headers=auth(ADMIN)
        )
        assert r.status_code == 422, pid
        assert r.json()["error"] == "validation_failed"


def test_invalid_limit_422(client: TestClient) -> None:
    r = client.post(
        "/run", json={"tool": "top_processes", "args": {"limit": 999}}, headers=auth(VIEWER)
    )
    assert r.status_code == 422


def test_extra_args_422(client: TestClient) -> None:
    r = client.post(
        "/run", json={"tool": "load_avg", "args": {"shell": "id"}}, headers=auth(VIEWER)
    )
    assert r.status_code == 422
    r = client.post(
        "/run", json={"tool": "load_avg", "args": {}, "cmd": "id"}, headers=auth(VIEWER)
    )
    assert r.status_code == 422


def test_invalid_service_422(client: TestClient) -> None:
    r = client.post(
        "/plan", json={"tool": "service_status", "args": {"service": "sshd"}}, headers=auth(VIEWER)
    )
    assert r.status_code == 422


def test_malformed_body_422(client: TestClient) -> None:
    r = client.post(
        "/run", content=b"not json", headers={**auth(ADMIN), "content-type": "application/json"}
    )
    assert r.status_code == 422
    assert r.json()["error"] == "validation_failed"


def test_virtual_tool_cannot_run(client: TestClient) -> None:
    r = client.post(
        "/run", json={"tool": "ask_user", "args": {"question": "which?"}}, headers=auth(ADMIN)
    )
    assert r.status_code == 422


# -- plan / run --------------------------------------------------------------------


def test_plan_does_not_execute(client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[str] = []
    monkeypatch.setattr(REGISTRY["load_avg"], "fn", lambda: calls.append("ran") or "x")
    r = client.post("/plan", json={"tool": "load_avg"}, headers=auth(VIEWER))
    assert r.status_code == 200
    assert r.json()["plan"] == "cat /proc/loadavg; nproc; free -m"
    assert r.json()["risk"] == "read"
    assert len(r.json()["plan_hash"]) == 64
    assert calls == []


def test_run_read_tool_and_audit(client: TestClient, tmp_path: Path) -> None:
    r = client.post("/run", json={"tool": "load_avg"}, headers=auth(VIEWER))
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["tool"] == "load_avg"
    assert "load:" in body["result"]
    assert len(body["result_hash"]) == 64
    a = client.get("/audit", headers=auth(VIEWER))
    assert a.status_code == 200
    assert a.json()["verified"] is True
    recs = a.json()["records"]
    assert recs[-1]["tool"] == "load_avg"
    assert recs[-1]["user"] == "vera"
    assert recs[-1]["result_hash"] == body["result_hash"]
    assert AuditLog(tmp_path / "audit.jsonl").verify().ok


def test_run_output_is_redacted(client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        REGISTRY["load_avg"], "fn", lambda: "owner ops@example.com token=abcdef123456"
    )
    r = client.post("/run", json={"tool": "load_avg"}, headers=auth(VIEWER))
    assert r.status_code == 200
    assert "ops@example.com" not in r.json()["result"]
    assert "abcdef123456" not in r.json()["result"]
    assert "[REDACTED:email]" in r.json()["result"]


def test_tool_errors_are_structured_and_audited(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    def boom() -> str:
        raise RuntimeError("secret internal detail /etc/passwd")

    monkeypatch.setattr(REGISTRY["load_avg"], "fn", boom)
    r = client.post("/run", json={"tool": "load_avg"}, headers=auth(VIEWER))
    assert r.status_code == 500
    assert r.json() == {"error": "internal_error", "message": "internal error"}
    assert "secret internal detail" not in r.text
    assert "Traceback" not in r.text
    a = client.get("/audit", headers=auth(VIEWER)).json()
    assert a["records"][-1]["status"] == "error"
    assert a["verified"] is True


def test_audit_n_bounds(client: TestClient) -> None:
    assert client.get("/audit?n=0", headers=auth(VIEWER)).status_code == 422
    assert client.get("/audit?n=5000", headers=auth(VIEWER)).status_code == 422


def test_audit_records_contain_no_result_body(client: TestClient, tmp_path: Path) -> None:
    client.post("/run", json={"tool": "load_avg"}, headers=auth(VIEWER))
    text = (tmp_path / "audit.jsonl").read_text(encoding="utf-8")
    for line in text.splitlines():
        rec = json.loads(line)
        assert "result" not in rec
        assert "result_hash" in rec


# -- config ---------------------------------------------------------------------------


def test_settings_default_deny(tmp_path: Path) -> None:
    s = settings_from_dict({"tokens": {"a": {"token": ADMIN, "role": "admin"}}})
    assert s.enabled_risks == ("read",)
    assert s.bind == "127.0.0.1:8710"
    assert s.is_loopback


def test_settings_reject_non_loopback_by_default() -> None:
    from bastion.core.errors import ConfigError

    with pytest.raises(ConfigError, match="not loopback"):
        settings_from_dict({"bind": "0.0.0.0:8710"})
    s = settings_from_dict({"bind": "0.0.0.0:8710", "allow_non_loopback_bind": True})
    assert s.host == "0.0.0.0"


def test_settings_reject_unknown_keys_and_short_tokens() -> None:
    from bastion.core.errors import ConfigError

    with pytest.raises(ConfigError):
        settings_from_dict({"enable_shell": True})
    with pytest.raises(ConfigError, match="token"):
        settings_from_dict({"tokens": {"a": {"token": "short", "role": "admin"}}})
    with pytest.raises(ConfigError):
        settings_from_dict({"tokens": {"a": {"token": ADMIN, "role": "root"}}})
    with pytest.raises(ConfigError, match="unknown risk"):
        settings_from_dict({"enabled_risks": ["read", "destroy"]})
