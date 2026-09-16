"""CLI commands via Typer's CliRunner, with scripted provider + fake executor."""

from __future__ import annotations

import json
import os
import stat
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

from bastion.cli.main import app
from tests.conftest import FakeExecutor, ScriptedProvider
from tests.test_agent_loop import fake_tools

runner = CliRunner()


@pytest.fixture
def cfg(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    path = tmp_path / "config.yaml"
    monkeypatch.setenv("BASTION_CLI_CONFIG", str(path))
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test-key")
    result = runner.invoke(
        app,
        [
            "init",
            "--non-interactive",
            "--provider",
            "anthropic",
            "--server",
            "prod",
            "--url",
            "http://127.0.0.1:8710",
            "--token",
            "t" * 40,
        ],
    )
    assert result.exit_code == 0, result.output
    return path


@pytest.fixture
def fake_backend(monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    state: dict[str, Any] = {
        "provider": ScriptedProvider.from_fixture("simple_cpu_question"),
        "executor": FakeExecutor(fake_tools()),
    }
    import bastion.agent.client as client_mod
    import bastion.agent.providers as providers_mod

    monkeypatch.setattr(providers_mod, "make_provider", lambda *a, **k: state["provider"])
    monkeypatch.setattr(client_mod, "ExecutorClient", lambda *a, **k: state["executor"])
    return state


# -- init / servers -------------------------------------------------------------------------


def test_init_writes_private_config(cfg: Path) -> None:
    assert cfg.exists()
    text = cfg.read_text(encoding="utf-8")
    assert "prod" in text and "http://127.0.0.1:8710" in text
    if os.name == "posix":
        assert stat.S_IMODE(cfg.stat().st_mode) == 0o600
    out = runner.invoke(app, ["servers", "list"])
    assert out.exit_code == 0
    assert "* prod" in out.output


def test_init_rejects_bad_provider(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("BASTION_CLI_CONFIG", str(tmp_path / "c.yaml"))
    r = runner.invoke(
        app, ["init", "--non-interactive", "--provider", "gemini", "--token", "x" * 20]
    )
    assert r.exit_code != 0


def test_servers_add_remove(cfg: Path) -> None:
    r = runner.invoke(
        app, ["servers", "add", "staging", "--url", "http://127.0.0.1:8711", "--token", "s" * 40]
    )
    assert r.exit_code == 0, r.output
    out = runner.invoke(app, ["servers", "list"]).output
    assert "staging" in out and "* prod" in out
    r = runner.invoke(app, ["servers", "remove", "staging"])
    assert r.exit_code == 0
    assert "staging" not in runner.invoke(app, ["servers", "list"]).output
    assert runner.invoke(app, ["servers", "remove", "nope"]).exit_code == 1


# -- tools ------------------------------------------------------------------------------------


def test_tools_denied_lists_never_actions() -> None:
    r = runner.invoke(app, ["tools", "--denied"])
    assert r.exit_code == 0
    assert "never" in r.output.lower()
    assert "shell" in r.output and "kill -9" in r.output
    j = runner.invoke(app, ["tools", "--denied", "--json"])
    assert len(json.loads(j.output)["never"]) >= 10


def test_tools_table(cfg: Path, fake_backend: dict[str, Any]) -> None:
    r = runner.invoke(app, ["tools"])
    assert r.exit_code == 0, r.output
    assert "load_avg" in r.output and "db_cancel_query" in r.output
    j = runner.invoke(app, ["tools", "--json"])
    data = json.loads(j.output)
    assert data["role"] == "operator"
    assert {t["name"] for t in data["tools"]} >= {"load_avg", "db_cancel_query"}


# -- ask ----------------------------------------------------------------------------------------


def test_ask_rich_read_only(cfg: Path, fake_backend: dict[str, Any]) -> None:
    r = runner.invoke(app, ["ask", "what's using the most CPU?"])
    assert r.exit_code == 0, r.output
    assert "bastion" in r.output and "prod" in r.output and "claude-sonnet-4-6" in r.output
    assert "top_processes" in r.output
    assert "Diagnosis" in r.output
    assert "nothing is saturating" in r.output


def test_ask_json_stream(cfg: Path, fake_backend: dict[str, Any]) -> None:
    r = runner.invoke(app, ["ask", "cpu?", "--json"])
    assert r.exit_code == 0, r.output
    events = [json.loads(line) for line in r.output.splitlines() if line.strip()]
    kinds = [e["event"] for e in events]
    assert kinds == ["start", "tool_start", "tool_end", "final", "done"]
    assert events[1]["tool"] == "top_processes"
    assert events[2]["status"] == "ok"
    assert events[-1]["calls"] == ["top_processes"]
    assert "◆" not in r.output  # no Rich header in json mode


def test_ask_approval_yes_via_stdin(cfg: Path, fake_backend: dict[str, Any]) -> None:
    fake_backend["provider"] = ScriptedProvider.from_fixture("high_load_postgres")
    r = runner.invoke(app, ["ask", "server is slow, find out why"], input="y\n")
    assert r.exit_code == 0, r.output
    assert "Proposed action" in r.output
    assert "needs approval" in r.output
    assert "pg_cancel_backend(4242)" in r.output
    assert "Approve?" in r.output
    assert "load 14.20" in r.output and "3.10" in r.output
    executor: FakeExecutor = fake_backend["executor"]
    assert any(t == "db_cancel_query" for t, _, _ in executor.ran)


def test_ask_approval_default_is_no(cfg: Path, fake_backend: dict[str, Any]) -> None:
    fake_backend["provider"] = ScriptedProvider.from_fixture("high_load_postgres")
    r = runner.invoke(app, ["ask", "server is slow"], input="\n")
    assert r.exit_code == 0, r.output
    executor: FakeExecutor = fake_backend["executor"]
    assert not any(t == "db_cancel_query" for t, _, _ in executor.ran)


def test_ask_dry_run_shows_plan_and_never_runs(cfg: Path, fake_backend: dict[str, Any]) -> None:
    fake_backend["provider"] = ScriptedProvider.from_fixture("high_load_postgres")
    r = runner.invoke(app, ["ask", "server is slow", "--dry-run"], input="y\n")
    assert r.exit_code == 0, r.output
    assert "pg_cancel_backend(4242)" in r.output
    assert "not executed" in r.output.lower() or "dry run" in r.output.lower()
    assert "Approve?" not in r.output
    executor: FakeExecutor = fake_backend["executor"]
    assert not any(t == "db_cancel_query" for t, _, _ in executor.ran)


def test_ask_json_approval_via_stdin(cfg: Path, fake_backend: dict[str, Any]) -> None:
    fake_backend["provider"] = ScriptedProvider.from_fixture("high_load_postgres")
    r = runner.invoke(app, ["ask", "slow", "--json"], input="y\n")
    assert r.exit_code == 0, r.output
    events = [json.loads(line) for line in r.output.splitlines() if line.strip()]
    kinds = [e["event"] for e in events]
    assert "approval_required" in kinds and "verify" in kinds
    approval = next(e for e in events if e["event"] == "approval_required")
    assert approval["plan"].startswith("SELECT pg_cancel_backend(4242)")
    assert len(approval["plan_hash"]) == 64


def test_ask_max_calls_exit_code(cfg: Path, fake_backend: dict[str, Any]) -> None:
    fake_backend["provider"] = ScriptedProvider(
        [{"text": "", "tool_calls": [{"name": "load_avg", "args": {}}]}] * 10
    )
    r = runner.invoke(app, ["ask", "loop", "--max-calls", "2"])
    assert r.exit_code == 2
    assert "limit of 2 tool calls" in r.output


def test_ask_without_config_fails_cleanly(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("BASTION_CLI_CONFIG", str(tmp_path / "missing.yaml"))
    r = runner.invoke(app, ["ask", "hi"])
    assert r.exit_code == 1
    assert "bastion init" in r.output


# -- doctor / audit ------------------------------------------------------------------------------


def test_doctor_ok(cfg: Path, fake_backend: dict[str, Any]) -> None:
    fake_backend["executor"].health = lambda: {"status": "ok", "version": "0.1.0"}  # type: ignore[method-assign]
    r = runner.invoke(app, ["doctor"])
    assert r.exit_code == 0, r.output
    assert "token accepted" in r.output and "role=operator" in r.output
    assert "✘" not in r.output


def test_doctor_missing_key(
    cfg: Path, fake_backend: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("ANTHROPIC_API_KEY")
    fake_backend["executor"].health = lambda: {"status": "ok", "version": "0.1.0"}  # type: ignore[method-assign]
    r = runner.invoke(app, ["doctor"])
    assert r.exit_code == 1
    assert "ANTHROPIC_API_KEY" in r.output


def test_audit_tail(cfg: Path, fake_backend: dict[str, Any]) -> None:
    fake_backend["executor"].audit = lambda n=20: {  # type: ignore[method-assign]
        "records": [
            {
                "ts": "2026-09-16T00:00:00",
                "user": "ada",
                "tool": "load_avg",
                "status": "ok",
                "plan": "cat /proc/loadavg",
                "hash": "abc123def456",
            }
        ],
        "verified": True,
        "total": 1,
    }
    r = runner.invoke(app, ["audit", "tail", "-n", "5"])
    assert r.exit_code == 0, r.output
    assert "load_avg" in r.output and "verified" in r.output
    j = runner.invoke(app, ["audit", "tail", "--json"])
    assert json.loads(j.output)["verified"] is True


def test_version() -> None:
    r = runner.invoke(app, ["--version"])
    assert r.exit_code == 0 and "0.1.0" in r.output


def test_cli_module_import_is_lazy() -> None:
    """`bastion --help` must not import rich/httpx/the agent (startup budget)."""
    code = (
        "import sys, bastion.cli.main; "
        "print(sorted(m for m in sys.modules if m.startswith(('rich', 'httpx', 'bastion.agent', 'bastion.tools', 'psutil'))))"
    )
    out = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, check=True)
    assert out.stdout.strip() == "[]", out.stdout
